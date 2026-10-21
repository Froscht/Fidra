#include "LibrarySignatures.h"
#include "AnalysisDatabase.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <QStandardPaths>
#include <QTextStream>
#include <capstone/capstone.h>
#include <vector>

namespace Fidra {

namespace {

constexpr uint64_t FnvOffset = 0xcbf29ce484222325ULL;
constexpr uint64_t FnvPrime = 0x100000001b3ULL;

void MaskRange(std::vector<uint8_t>& Mask, size_t InsnOff, uint8_t Off, uint8_t Len) {
    if (Off == 0 || Len == 0) return;
    for (size_t I = InsnOff + Off; I < InsnOff + Off + Len && I < Mask.size(); ++I) Mask[I] = 1;
}

bool IsGeneratedName(const QString& Name) {
    return Name.isEmpty() || Name.startsWith("sub_") || Name.startsWith("loc_") || Name.startsWith("j_") ||
           Name == "entry_point";
}

}

uint64_t LibrarySignatures::HashFunction(const uint8_t* Bytes, size_t Size, Address Start, bool Is64Bit,
                                         Address ImageLow, Address ImageHigh) {
    if (Size == 0) return 0;
    const size_t Hashed = std::min<size_t>(Size, MaxHashedBytes);

    csh Handle;
    if (cs_open(CS_ARCH_X86, Is64Bit ? CS_MODE_64 : CS_MODE_32, &Handle) != CS_ERR_OK) return 0;
    cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn* Insn = cs_malloc(Handle);

    // In position-independent images every small constant would look like an
    // address; their addresses are RIP-relative anyway.
    const bool MaskAbsolute = ImageLow >= 0x10000;
    auto InImage = [&](int64_t V) {
        return MaskAbsolute && static_cast<Address>(V) >= ImageLow && static_cast<Address>(V) < ImageHigh;
    };

    std::vector<uint8_t> Mask(Hashed, 0);
    size_t Off = 0;
    while (Off < Hashed) {
        const uint8_t* Code = Bytes + Off;
        size_t Left = Size - Off;
        uint64_t Addr = Start + Off;
        if (!cs_disasm_iter(Handle, &Code, &Left, &Addr, Insn)) {
            ++Off;  // undecodable byte (inline data): hash it as is
            continue;
        }
        const cs_x86& X = Insn->detail->x86;
        const bool RelBranch = cs_insn_group(Handle, Insn, CS_GRP_BRANCH_RELATIVE);
        for (uint8_t I = 0; I < X.op_count; ++I) {
            const cs_x86_op& Op = X.operands[I];
            if (Op.type == X86_OP_IMM) {
                if (RelBranch || (X.encoding.imm_size >= 4 && InImage(Op.imm))) {
                    MaskRange(Mask, Off, X.encoding.imm_offset, X.encoding.imm_size);
                }
            } else if (Op.type == X86_OP_MEM) {
                if (Op.mem.base == X86_REG_RIP || Op.mem.base == X86_REG_EIP ||
                    (X.encoding.disp_size >= 4 && InImage(Op.mem.disp))) {
                    MaskRange(Mask, Off, X.encoding.disp_offset, X.encoding.disp_size);
                }
            }
        }
        Off += Insn->size;
    }
    cs_free(Insn, 1);
    cs_close(&Handle);

    uint64_t H = FnvOffset;
    for (size_t I = 0; I < Hashed; ++I) {
        H ^= Mask[I] ? 0x100u : Bytes[I];
        H *= FnvPrime;
    }
    return H ? H : 1;
}

QList<LibrarySignatures::Entry> LibrarySignatures::Generate(AnalysisDatabase* Db, const QString& Module) {
    QList<Entry> Out;
    const BinaryInfo Info = Db->GetBinaryInfo();
    Address Low = ~Address(0), High = 0;
    for (const Segment& Seg : Info.Segments) {
        Low = std::min(Low, Seg.VirtualAddress);
        High = std::max(High, Seg.VirtualAddress + Seg.VirtualSize);
    }
    for (const AnalyzedFunction& F : Db->GetAllFunctions()) {
        if (F.IsImported || F.IsThunk || F.Size < MinFunctionSize || IsGeneratedName(F.Name)) continue;
        const QByteArray Bytes = Db->ReadBytes(F.Start, std::min<size_t>(F.Size, MaxHashedBytes));
        if (static_cast<size_t>(Bytes.size()) != std::min<size_t>(F.Size, MaxHashedBytes)) continue;
        const uint64_t H = HashFunction(reinterpret_cast<const uint8_t*>(Bytes.constData()),
                                        static_cast<size_t>(Bytes.size()), F.Start, Info.Is64Bit, Low, High);
        if (H == 0) continue;
        Out.append({static_cast<uint32_t>(F.Size), H, F.Name, Module});
    }
    return Out;
}

bool LibrarySignatures::Save(const QString& Path, const QList<Entry>& Entries, bool Is64Bit, const QString& Module,
                             QString* Error) {
    // Drop pairs claimed by different names: they cannot identify anything.
    QHash<QPair<uint32_t, quint64>, QString> Names;
    QSet<QPair<uint32_t, quint64>> Clash;
    for (const Entry& E : Entries) {
        const QPair<uint32_t, quint64> K{E.Size, E.Hash};
        auto It = Names.constFind(K);
        if (It == Names.constEnd()) Names.insert(K, E.Name);
        else if (It.value() != E.Name) Clash.insert(K);
    }

    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        if (Error) *Error = File.errorString();
        return false;
    }
    QTextStream Stream(&File);
    QString Mod = Module.simplified();
    Mod.replace(' ', '_');
    if (Mod.isEmpty()) Mod = "unnamed";
    Stream << "# Fidra library signatures\n";
    Stream << "fsig 1 " << (Is64Bit ? "x86_64" : "x86") << ' ' << Mod << '\n';
    int Written = 0;
    for (auto It = Names.constBegin(); It != Names.constEnd(); ++It) {
        if (Clash.contains(It.key())) continue;
        Stream << It.key().first << ' ' << QString::number(It.key().second, 16) << ' ' << It.value() << '\n';
        ++Written;
    }
    Stream.flush();
    if (Error) *Error = QString("%1 signatures written, %2 ambiguous dropped").arg(Written).arg(Clash.size());
    return Stream.status() == QTextStream::Ok;
}

void LibrarySignatures::Insert(const Entry& E) {
    const Key K{E.Size, E.Hash};
    if (Ambiguous.contains(K)) return;
    auto It = Table.constFind(K);
    if (It == Table.constEnd()) {
        Table.insert(K, E);
    } else if (It->Name != E.Name) {
        Table.remove(K);
        Ambiguous.insert(K, true);
    }
}

bool LibrarySignatures::LoadFile(const QString& Path, bool Is64Bit, QString* Error) {
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly | QIODevice::Text)) {
        if (Error) *Error = File.errorString();
        return false;
    }
    QTextStream Stream(&File);
    QString Module;
    bool HeaderSeen = false;
    while (!Stream.atEnd()) {
        const QString Line = Stream.readLine().trimmed();
        if (Line.isEmpty() || Line.startsWith('#')) continue;
        if (!HeaderSeen) {
            const QStringList Parts = Line.split(' ', Qt::SkipEmptyParts);
            if (Parts.size() < 3 || Parts[0] != "fsig" || Parts[1] != "1") {
                if (Error) *Error = "not a Fidra signature file (missing 'fsig 1' header)";
                return false;
            }
            if (Parts[2] != (Is64Bit ? "x86_64" : "x86")) {
                if (Error) *Error = QString("architecture %1 does not match").arg(Parts[2]);
                return false;
            }
            Module = Parts.size() > 3 ? Parts[3] : QFileInfo(Path).baseName();
            HeaderSeen = true;
            continue;
        }
        const int S1 = Line.indexOf(' ');
        const int S2 = S1 < 0 ? -1 : Line.indexOf(' ', S1 + 1);
        if (S2 < 0) continue;
        bool OkSize = false, OkHash = false;
        Entry E;
        E.Size = Line.left(S1).toUInt(&OkSize);
        E.Hash = Line.mid(S1 + 1, S2 - S1 - 1).toULongLong(&OkHash, 16);
        E.Name = Line.mid(S2 + 1);
        E.Module = Module;
        if (OkSize && OkHash && E.Size >= MinFunctionSize && !E.Name.isEmpty()) Insert(E);
    }
    if (!HeaderSeen && Error) *Error = "empty file";
    return HeaderSeen;
}

QStringList LibrarySignatures::DefaultDirectories() {
    QStringList Dirs;
    for (const QString& Base : QStandardPaths::standardLocations(QStandardPaths::GenericDataLocation))
        Dirs << Base + "/Fidra/sigs";
    Dirs << QCoreApplication::applicationDirPath() + "/sigs";
    const QString Env = qEnvironmentVariable("FIDRA_SIG_PATH");
    if (!Env.isEmpty()) Dirs << Env.split(QDir::listSeparator(), Qt::SkipEmptyParts);
    return Dirs;
}

int LibrarySignatures::LoadDefaultDirectories(bool Is64Bit, QStringList* LoadedFiles) {
    int Loaded = 0;
    QSet<QString> Seen;
    for (const QString& DirPath : DefaultDirectories()) {
        const QFileInfo Single(DirPath);
        if (Single.isFile()) {  // $FIDRA_SIG_PATH may also name files
            const QString Canon = Single.canonicalFilePath();
            if (!Seen.contains(Canon) && LoadFile(Canon, Is64Bit)) {
                ++Loaded;
                if (LoadedFiles) *LoadedFiles << Canon;
            }
            Seen.insert(Canon);
            continue;
        }
        QDir Dir(DirPath);
        if (!Dir.exists()) continue;
        for (const QFileInfo& Fi : Dir.entryInfoList({"*.fsig"}, QDir::Files, QDir::Name)) {
            const QString Canon = Fi.canonicalFilePath();
            if (Seen.contains(Canon)) continue;
            Seen.insert(Canon);
            if (LoadFile(Canon, Is64Bit)) {
                ++Loaded;
                if (LoadedFiles) *LoadedFiles << Canon;
            }
        }
    }
    return Loaded;
}

int LibrarySignatures::Apply(AnalysisDatabase* Db, QStringList* Log) const {
    if (Table.isEmpty()) return 0;
    const BinaryInfo Info = Db->GetBinaryInfo();
    Address Low = ~Address(0), High = 0;
    for (const Segment& Seg : Info.Segments) {
        Low = std::min(Low, Seg.VirtualAddress);
        High = std::max(High, Seg.VirtualAddress + Seg.VirtualSize);
    }

    int Renamed = 0;
    for (AnalyzedFunction F : Db->GetAllFunctions()) {
        if (!F.Name.startsWith("sub_") || F.Size < MinFunctionSize || F.Size > 0xffffffffULL) continue;
        const size_t Want = std::min<size_t>(F.Size, MaxHashedBytes);
        const QByteArray Bytes = Db->ReadBytes(F.Start, Want);
        if (static_cast<size_t>(Bytes.size()) != Want) continue;
        const uint64_t H = HashFunction(reinterpret_cast<const uint8_t*>(Bytes.constData()), Want, F.Start,
                                        Info.Is64Bit, Low, High);
        auto It = Table.constFind(Key{static_cast<uint32_t>(F.Size), H});
        if (It == Table.constEnd()) continue;
        F.Name = It->Name;
        Db->UpdateFunction(F.Start, F);
        Db->SetName(F.Start, It->Name);
        if (Log) *Log << QString("0x%1 -> %2 [%3]").arg(F.Start, 0, 16).arg(It->Name, It->Module);
        ++Renamed;
    }
    return Renamed;
}

}
