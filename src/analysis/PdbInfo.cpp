// PDB (MSF 7.00) reader: functions, prototypes, stack locals and public
// symbols for PE binaries. Format per the LLVM PDB documentation and
// Microsoft's microsoft-pdb repository (cvinfo.h).

#include "DwarfInfo.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QVector>
#include <algorithm>
#include <cstring>

namespace Fidra {

namespace {

template <typename T> T Rd(const QByteArray& B, qsizetype Off) {
    T V{};
    if (Off >= 0 && Off + static_cast<qsizetype>(sizeof(T)) <= B.size()) std::memcpy(&V, B.constData() + Off, sizeof(T));
    return V;
}

QString CStrAt(const QByteArray& B, qsizetype Off, qsizetype Limit) {
    if (Off < 0 || Off >= Limit || Limit > B.size()) return {};
    const char* S = B.constData() + Off;
    const qsizetype N = static_cast<qsizetype>(qstrnlen(S, static_cast<size_t>(Limit - Off)));
    return QString::fromUtf8(S, N);
}

// ---------------------------------------------------------------- PE CodeView entry

struct CodeViewRef {
    bool Found = false;
    QByteArray Guid;   // 16 bytes as stored
    uint32_t Age = 0;
    QString PdbPath;
    Address ImageBase = 0;
};

CodeViewRef ReadCodeView(const QString& Path) {
    CodeViewRef R;
    QFile F(Path);
    if (!F.open(QIODevice::ReadOnly)) return R;
    const QByteArray D = F.readAll();
    const uint32_t PeOff = Rd<uint32_t>(D, 0x3c);
    if (Rd<uint32_t>(D, PeOff) != 0x4550) return R;
    const uint16_t NumSec = Rd<uint16_t>(D, PeOff + 6);
    const uint16_t OptSize = Rd<uint16_t>(D, PeOff + 20);
    const qsizetype Opt = PeOff + 24;
    const uint16_t Magic = Rd<uint16_t>(D, Opt);
    const bool Plus = Magic == 0x20b;
    R.ImageBase = Plus ? Rd<uint64_t>(D, Opt + 24) : Rd<uint32_t>(D, Opt + 28);
    const qsizetype Dirs = Opt + (Plus ? 112 : 96);
    const uint32_t DbgRva = Rd<uint32_t>(D, Dirs + 6 * 8);
    const uint32_t DbgSize = Rd<uint32_t>(D, Dirs + 6 * 8 + 4);
    if (!DbgRva || !DbgSize) return R;

    const qsizetype SecTab = Opt + OptSize;
    auto RvaToOff = [&](uint32_t Rva) -> qsizetype {
        for (int I = 0; I < NumSec; ++I) {
            const qsizetype S = SecTab + I * 40;
            const uint32_t Va = Rd<uint32_t>(D, S + 12), VSize = Rd<uint32_t>(D, S + 8);
            const uint32_t RawSize = Rd<uint32_t>(D, S + 16), RawPtr = Rd<uint32_t>(D, S + 20);
            if (Rva >= Va && Rva < Va + std::max(VSize, RawSize)) return RawPtr + (Rva - Va);
        }
        return -1;
    };
    const qsizetype DbgOff = RvaToOff(DbgRva);
    if (DbgOff < 0) return R;
    for (uint32_t E = 0; E + 28 <= DbgSize; E += 28) {
        if (Rd<uint32_t>(D, DbgOff + E + 12) != 2) continue;  // IMAGE_DEBUG_TYPE_CODEVIEW
        const uint32_t Size = Rd<uint32_t>(D, DbgOff + E + 16);
        const uint32_t Ptr = Rd<uint32_t>(D, DbgOff + E + 24);
        if (Size < 24 || Ptr + Size > static_cast<uint32_t>(D.size())) continue;
        if (std::memcmp(D.constData() + Ptr, "RSDS", 4) != 0) continue;
        R.Guid = D.mid(Ptr + 4, 16);
        R.Age = Rd<uint32_t>(D, Ptr + 20);
        R.PdbPath = CStrAt(D, Ptr + 24, Ptr + Size);
        R.Found = true;
        break;
    }
    return R;
}

// Symbol store directory name: GUID (Data1-3 as numbers, Data4 as bytes) + age.
QString StoreKey(const QByteArray& G, uint32_t Age) {
    if (G.size() != 16) return {};
    auto U = [&](int Off, int N) {
        uint64_t V = 0;
        std::memcpy(&V, G.constData() + Off, static_cast<size_t>(N));
        return QString("%1").arg(V, N * 2, 16, QChar('0'));
    };
    QString Key = U(0, 4) + U(4, 2) + U(6, 2) + QString::fromLatin1(G.mid(8, 8).toHex());
    return Key.toUpper() + QString::number(Age, 16).toUpper();
}

// ---------------------------------------------------------------- MSF container

class Msf {
public:
    bool Open(const QString& Path, QString& Error) {
        QFile F(Path);
        if (!F.open(QIODevice::ReadOnly)) { Error = F.errorString(); return false; }
        Data = F.readAll();
        static const char Magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";
        if (Data.size() < 56 || std::memcmp(Data.constData(), Magic, 32) != 0) {
            Error = "not an MSF 7.00 PDB (old 2.00 format is not supported)";
            return false;
        }
        BlockSize = Rd<uint32_t>(Data, 32);
        const uint32_t NumBlocks = Rd<uint32_t>(Data, 40);
        const uint32_t DirBytes = Rd<uint32_t>(Data, 44);
        const uint32_t BlockMapAddr = Rd<uint32_t>(Data, 52);
        if (BlockSize < 512 || BlockSize > 65536 || static_cast<uint64_t>(NumBlocks) * BlockSize > static_cast<uint64_t>(Data.size()) + BlockSize) {
            Error = "bad MSF header";
            return false;
        }
        const uint32_t DirBlocks = (DirBytes + BlockSize - 1) / BlockSize;
        QVector<uint32_t> DirList;
        for (uint32_t I = 0; I < DirBlocks; ++I) DirList << Rd<uint32_t>(Data, static_cast<qsizetype>(BlockMapAddr) * BlockSize + I * 4);
        const QByteArray Dir = Gather(DirList, DirBytes);
        if (Dir.size() != static_cast<qsizetype>(DirBytes)) { Error = "bad MSF directory"; return false; }

        const uint32_t NumStreams = Rd<uint32_t>(Dir, 0);
        if (NumStreams > 100000) { Error = "bad stream count"; return false; }
        qsizetype Pos = 4 + static_cast<qsizetype>(NumStreams) * 4;
        for (uint32_t S = 0; S < NumStreams; ++S) {
            uint32_t Size = Rd<uint32_t>(Dir, 4 + S * 4);
            if (Size == 0xffffffffu) Size = 0;
            const uint32_t N = (Size + BlockSize - 1) / BlockSize;
            QVector<uint32_t> Blocks;
            for (uint32_t B = 0; B < N; ++B) Blocks << Rd<uint32_t>(Dir, Pos + B * 4);
            Pos += static_cast<qsizetype>(N) * 4;
            Streams.append({Blocks, Size});
        }
        return true;
    }

    QByteArray Stream(int Index) const {
        if (Index < 0 || Index >= Streams.size()) return {};
        return Gather(Streams[Index].Blocks, Streams[Index].Size);
    }

private:
    QByteArray Gather(const QVector<uint32_t>& Blocks, uint32_t Size) const {
        QByteArray Out;
        Out.reserve(static_cast<qsizetype>(Size));
        for (uint32_t B : Blocks) {
            const qsizetype Off = static_cast<qsizetype>(B) * BlockSize;
            const qsizetype Want = std::min<qsizetype>(BlockSize, static_cast<qsizetype>(Size) - Out.size());
            if (Off < 0 || Off + Want > Data.size()) return {};
            Out.append(Data.constData() + Off, Want);
        }
        return Out;
    }
    struct StreamInfo { QVector<uint32_t> Blocks; uint32_t Size; };
    QByteArray Data;
    uint32_t BlockSize = 4096;
    QVector<StreamInfo> Streams;
};

// ---------------------------------------------------------------- type records (TPI / IPI)

class TypeTable {
public:
    void Load(const QByteArray& S) {
        Stream = S;
        if (S.size() < 56) return;
        const uint32_t HeaderSize = Rd<uint32_t>(S, 4);
        Begin = Rd<uint32_t>(S, 8);
        const uint32_t End = Rd<uint32_t>(S, 12);
        qsizetype Pos = HeaderSize;
        for (uint32_t Ti = Begin; Ti < End && Pos + 4 <= S.size(); ++Ti) {
            const uint16_t Len = Rd<uint16_t>(S, Pos);
            Offsets << Pos;
            Pos += 2 + Len;
        }
    }
    // Record body (after the length) for a type index, or -1.
    qsizetype Record(uint32_t Ti, uint16_t& Kind, qsizetype& End) const {
        if (Ti < Begin || Ti - Begin >= static_cast<uint32_t>(Offsets.size())) return -1;
        const qsizetype Off = Offsets[Ti - Begin];
        End = Off + 2 + Rd<uint16_t>(Stream, Off);
        Kind = Rd<uint16_t>(Stream, Off + 2);
        return Off + 4;
    }
    QByteArray Stream;
    uint32_t Begin = 0x1000;
    QVector<qsizetype> Offsets;
};

// Numeric leaf (sizes in LF_STRUCTURE etc.); returns its encoded length.
qsizetype SkipNumeric(const QByteArray& S, qsizetype Off) {
    const uint16_t V = Rd<uint16_t>(S, Off);
    if (V < 0x8000) return 2;
    switch (V) {
    case 0x8000: return 3;
    case 0x8001: case 0x8002: return 4;
    case 0x8003: case 0x8004: case 0x8005: return 6;
    case 0x8009: case 0x800a: case 0x8006: return 10;
    default: return 2;
    }
}

QString SimpleTypeName(uint32_t Ti) {
    const uint32_t Kind = Ti & 0xff;
    const uint32_t Mode = (Ti >> 8) & 0xf;
    QString B;
    switch (Kind) {
    case 0x00: B = Mode ? "void" : "..."; break;   // T_NOTYPE
    case 0x03: B = "void"; break;
    case 0x08: B = "HRESULT"; break;
    case 0x10: B = "signed char"; break;
    case 0x20: B = "unsigned char"; break;
    case 0x68: B = "int8_t"; break;
    case 0x69: B = "uint8_t"; break;
    case 0x70: B = "char"; break;
    case 0x71: B = "wchar_t"; break;
    case 0x7a: B = "char16_t"; break;
    case 0x7b: B = "char32_t"; break;
    case 0x7c: B = "char8_t"; break;
    case 0x11: B = "short"; break;
    case 0x21: B = "unsigned short"; break;
    case 0x72: B = "int16_t"; break;
    case 0x73: B = "uint16_t"; break;
    case 0x12: B = "LONG"; break;
    case 0x22: B = "ULONG"; break;
    case 0x74: B = "int"; break;
    case 0x75: B = "unsigned int"; break;
    case 0x13: B = "long long"; break;
    case 0x23: B = "unsigned long long"; break;
    case 0x76: B = "int64_t"; break;
    case 0x77: B = "uint64_t"; break;
    case 0x40: B = "float"; break;
    case 0x41: B = "double"; break;
    case 0x42: B = "long double"; break;
    case 0x30: B = "bool"; break;
    case 0x31: B = "int16_t"; break;
    case 0x32: B = "int32_t"; break;
    case 0x33: B = "int64_t"; break;
    default: B = "int"; break;
    }
    return Mode ? B + "*" : B;
}

class PdbTypes {
public:
    TypeTable Tpi, Ipi;

    QString Name(uint32_t Ti, int Depth = 0) {
        if (Ti < 0x1000) return SimpleTypeName(Ti);
        if (Depth > 12) return "void";
        auto C = Cache.constFind(Ti);
        if (C != Cache.constEnd()) return C.value();
        uint16_t Kind = 0;
        qsizetype End = 0;
        const qsizetype P = Tpi.Record(Ti, Kind, End);
        const QByteArray& S = Tpi.Stream;
        QString T = "void";
        if (P >= 0) {
            switch (Kind) {
            case 0x1001: {  // LF_MODIFIER
                const QString Inner = Name(Rd<uint32_t>(S, P), Depth + 1);
                const uint16_t Mods = Rd<uint16_t>(S, P + 4);
                T = Inner;
                if (Mods & 1) T = Inner.endsWith('*') ? Inner + " const" : "const " + Inner;
                if (Mods & 2) T = "volatile " + T;
                break;
            }
            case 0x1002: {  // LF_POINTER
                const uint32_t Ref = Rd<uint32_t>(S, P);
                const uint32_t Attr = Rd<uint32_t>(S, P + 4);
                const uint32_t Mode = (Attr >> 5) & 7;
                uint16_t RefKind = 0;
                qsizetype RefEnd = 0;
                if (Ref >= 0x1000 && Tpi.Record(Ref, RefKind, RefEnd) >= 0 && (RefKind == 0x1008 || RefKind == 0x1009)) {
                    T = FunctionPointer(Ref, Depth + 1);
                } else {
                    T = Name(Ref, Depth + 1) + (Mode == 1 ? "&" : Mode == 4 ? "&&" : "*");
                }
                break;
            }
            case 0x1008: case 0x1009: T = FunctionPointer(Ti, Depth + 1); break;
            case 0x1503: {  // LF_ARRAY
                const QString Elem = Name(Rd<uint32_t>(S, P), Depth + 1);
                const qsizetype SizeOff = P + 8;
                uint64_t Bytes = Rd<uint16_t>(S, SizeOff);
                if (Bytes >= 0x8000) Bytes = Rd<uint32_t>(S, SizeOff + 2);
                const uint64_t ElemSize = ElementSize(Rd<uint32_t>(S, P));
                T = ElemSize && Bytes ? Elem + QString("[%1]").arg(Bytes / ElemSize) : Elem + "[]";
                break;
            }
            case 0x1504: case 0x1505: case 0x1506: {  // LF_CLASS / LF_STRUCTURE / LF_UNION
                const qsizetype NumOff = Kind == 0x1506 ? P + 8 : P + 16;
                T = (Kind == 0x1506 ? "union " : "struct ") + CStrAt(S, NumOff + SkipNumeric(S, NumOff), End);
                break;
            }
            case 0x1507: T = "enum " + CStrAt(S, P + 12, End); break;  // LF_ENUM
            default: break;
            }
        }
        Cache.insert(Ti, T);
        return T;
    }

    // LF_PROCEDURE / LF_MFUNCTION: return type and parameter types.
    bool Signature(uint32_t Ti, QString& Ret, QStringList& Params, bool& Variadic, QString* ThisType = nullptr) {
        uint16_t Kind = 0;
        qsizetype End = 0;
        const qsizetype P = Tpi.Record(Ti, Kind, End);
        if (P < 0 || (Kind != 0x1008 && Kind != 0x1009)) return false;
        const QByteArray& S = Tpi.Stream;
        Ret = Name(Rd<uint32_t>(S, P));
        uint32_t ArgList = 0;
        if (Kind == 0x1008) {
            ArgList = Rd<uint32_t>(S, P + 8);
        } else {
            const uint32_t This = Rd<uint32_t>(S, P + 8);
            if (ThisType && This != 0 && This != 3) *ThisType = Name(This);
            ArgList = Rd<uint32_t>(S, P + 16);
        }
        uint16_t AKind = 0;
        qsizetype AEnd = 0;
        const qsizetype A = Tpi.Record(ArgList, AKind, AEnd);
        Variadic = false;
        if (A >= 0 && AKind == 0x1201) {
            const uint32_t N = Rd<uint32_t>(S, A);
            for (uint32_t I = 0; I < N && A + 4 + (I + 1) * 4 <= AEnd; ++I) {
                const uint32_t T = Rd<uint32_t>(S, A + 4 + I * 4);
                if (T == 0) { Variadic = true; continue; }
                if (N == 1 && T == 3) continue;  // (void)
                Params << Name(T);
            }
        }
        return true;
    }

    // S_GPROC32_ID's type is an IPI item (LF_FUNC_ID / LF_MFUNC_ID) naming the TPI type.
    uint32_t FunctionTypeFromId(uint32_t Id) const {
        uint16_t Kind = 0;
        qsizetype End = 0;
        const qsizetype P = Ipi.Record(Id, Kind, End);
        if (P < 0 || (Kind != 0x1601 && Kind != 0x1602)) return 0;
        return Rd<uint32_t>(Ipi.Stream, P + 4);
    }

private:
    QString FunctionPointer(uint32_t Ti, int Depth) {
        QString Ret;
        QStringList Params;
        bool Variadic = false;
        if (Depth > 12 || !Signature(Ti, Ret, Params, Variadic)) return "void*";
        if (Variadic) Params << "...";
        return Ret + " (*)(" + Params.join(", ") + ")";
    }
    uint64_t ElementSize(uint32_t Ti) {
        if (Ti < 0x1000) {
            if ((Ti >> 8) & 0xf) return 8;
            switch (Ti & 0xff) {
            case 0x10: case 0x20: case 0x68: case 0x69: case 0x70: case 0x30: case 0x7c: return 1;
            case 0x11: case 0x21: case 0x72: case 0x73: case 0x71: case 0x7a: return 2;
            case 0x12: case 0x22: case 0x74: case 0x75: case 0x40: case 0x7b: return 4;
            case 0x13: case 0x23: case 0x76: case 0x77: case 0x41: return 8;
            default: return 0;
            }
        }
        uint16_t Kind = 0;
        qsizetype End = 0;
        const qsizetype P = Tpi.Record(Ti, Kind, End);
        if (P < 0) return 0;
        if (Kind == 0x1002) return 8;
        if (Kind == 0x1001) return ElementSize(Rd<uint32_t>(Tpi.Stream, P));
        if (Kind == 0x1504 || Kind == 0x1505) return Rd<uint16_t>(Tpi.Stream, P + 16) < 0x8000 ? Rd<uint16_t>(Tpi.Stream, P + 16) : Rd<uint32_t>(Tpi.Stream, P + 18);
        return 0;
    }
    QHash<uint32_t, QString> Cache;
};

constexpr uint16_t CvAmd64Rsp = 335;
constexpr uint16_t CvAmd64Rbp = 334;

}

DebugInfo ParsePdbFile(const QString& PdbPath, Address ImageBase, const QByteArray& ExpectedGuid) {
    DebugInfo Out;
    Out.Path = PdbPath;
    Msf M;
    if (!M.Open(PdbPath, Out.Error)) return Out;

    const QByteArray Info = M.Stream(1);
    if (!ExpectedGuid.isEmpty() && Info.mid(12, 16) != ExpectedGuid) {
        Out.Error = "PDB GUID does not match the binary";
        return Out;
    }

    PdbTypes Types;
    Types.Tpi.Load(M.Stream(2));
    Types.Ipi.Load(M.Stream(4));

    const QByteArray Dbi = M.Stream(3);
    if (Dbi.size() < 64 || Rd<int32_t>(Dbi, 0) != -1) { Out.Error = "no DBI stream"; return Out; }
    const uint16_t SymRecordStream = Rd<uint16_t>(Dbi, 20);
    const int32_t ModInfoSize = Rd<int32_t>(Dbi, 24);
    const int32_t SecContribSize = Rd<int32_t>(Dbi, 28);
    const int32_t SecMapSize = Rd<int32_t>(Dbi, 32);
    const int32_t SourceInfoSize = Rd<int32_t>(Dbi, 36);
    const int32_t TypeServerSize = Rd<int32_t>(Dbi, 40);
    const int32_t OptDbgSize = Rd<int32_t>(Dbi, 48);
    const int32_t EcSize = Rd<int32_t>(Dbi, 52);

    // Section headers (optional debug header slot 5) map segment:offset to RVA.
    QVector<uint32_t> SectionRva;
    {
        const qsizetype OptOff = 64 + static_cast<qsizetype>(ModInfoSize) + SecContribSize + SecMapSize + SourceInfoSize + TypeServerSize + EcSize;
        if (OptDbgSize >= 12) {
            const uint16_t SecStream = Rd<uint16_t>(Dbi, OptOff + 5 * 2);
            const QByteArray Secs = M.Stream(SecStream == 0xffff ? -1 : SecStream);
            for (qsizetype S = 0; S + 40 <= Secs.size(); S += 40) SectionRva << Rd<uint32_t>(Secs, S + 12);
        }
    }
    auto ToVa = [&](uint16_t Seg, uint32_t Off) -> Address {
        if (Seg == 0 || Seg > SectionRva.size()) return 0;
        return ImageBase + SectionRva[Seg - 1] + Off;
    };
    if (SectionRva.isEmpty()) { Out.Error = "PDB has no section headers"; return Out; }

    // Module symbol streams: procedures with their locals.
    QHash<Address, int> ByLow;
    qsizetype Pos = 64;
    const qsizetype ModEnd = 64 + ModInfoSize;
    while (Pos + 64 <= ModEnd) {
        const uint16_t SymStream = Rd<uint16_t>(Dbi, Pos + 34);
        const uint32_t SymBytes = Rd<uint32_t>(Dbi, Pos + 36);
        qsizetype NameEnd = Pos + 64;
        for (int Str = 0; Str < 2; ++Str) {  // module name, object file name
            while (NameEnd < ModEnd && Dbi[NameEnd] != '\0') ++NameEnd;
            ++NameEnd;
        }
        Pos = (NameEnd + 3) & ~qsizetype(3);
        ++Out.Units;
        if (SymStream == 0xffff || SymBytes < 4) continue;

        const QByteArray Syms = M.Stream(SymStream);
        const qsizetype Limit = std::min<qsizetype>(Syms.size(), SymBytes);
        DebugFunction* Cur = nullptr;
        DebugFunction Building;
        int Depth = 0;        // nesting inside the current procedure
        int InlineDepth = 0;  // inside S_INLINESITE: locals belong to the inlinee
        int LocalBase = 0, ParamBase = 0;  // S_FRAMEPROC frame pointer encodings (1 = rsp)
        QStringList ParamNames;
        QStringList RegRelNames;
        DebugVariable PendingLocal;
        bool PendingIsParam = false;
        bool HavePending = false;

        auto Finish = [&]() {
            if (!Cur) return;
            const int N = Building.Proto.Params.size();
            const QStringList& Names = !ParamNames.isEmpty() ? ParamNames : RegRelNames;
            for (int I = 0; I < N && I < Names.size(); ++I) Building.Proto.Params[I].Name = Names[I];
            auto It = ByLow.constFind(Building.Low);
            if (It == ByLow.constEnd()) {
                ByLow.insert(Building.Low, Out.Functions.size());
                Out.Functions.append(Building);
            }
            Cur = nullptr;
        };

        for (qsizetype S = 4; S + 4 <= Limit;) {
            const uint16_t Len = Rd<uint16_t>(Syms, S);
            const uint16_t Kind = Rd<uint16_t>(Syms, S + 2);
            const qsizetype Body = S + 4;
            const qsizetype RecEnd = S + 2 + Len;
            if (Len < 2 || RecEnd > Limit) break;
            S = RecEnd;

            switch (Kind) {
            case 0x1110: case 0x110f: case 0x1147: case 0x1146: {  // S_[GL]PROC32[_ID]
                if (Cur) { ++Depth; break; }  // nested procedure record: ignore
                const uint32_t CodeSize = Rd<uint32_t>(Syms, Body + 12);
                uint32_t TypeIdx = Rd<uint32_t>(Syms, Body + 24);
                const uint32_t Off = Rd<uint32_t>(Syms, Body + 28);
                const uint16_t Seg = Rd<uint16_t>(Syms, Body + 32);
                const QString Name = CStrAt(Syms, Body + 35, RecEnd);
                if (Kind == 0x1147 || Kind == 0x1146) TypeIdx = Types.FunctionTypeFromId(TypeIdx);
                const Address Low = ToVa(Seg, Off);
                Building = DebugFunction{};
                Building.Low = Low;
                Building.High = Low + CodeSize;
                Building.Name = Building.SourceName = Building.Proto.Name = Name;
                QString Ret, This;
                QStringList Params;
                bool Variadic = false;
                if (Types.Signature(TypeIdx, Ret, Params, Variadic, &This)) {
                    Building.Proto.ReturnType = Ret;
                    Building.Proto.Variadic = Variadic;
                    if (!This.isEmpty()) Building.Proto.Params.append({This, "this"});
                    for (int I = 0; I < Params.size(); ++I) Building.Proto.Params.append({Params[I], QString("a%1").arg(I + 1)});
                } else {
                    Building.Proto.ReturnType = "int";
                }
                ParamNames.clear();
                RegRelNames.clear();
                HavePending = false;
                Depth = 0;
                InlineDepth = 0;
                LocalBase = ParamBase = 0;
                Cur = (Low != 0 && CodeSize > 0) ? &Building : nullptr;
                break;
            }
            case 0x1103: if (Cur) ++Depth; break;  // S_BLOCK32
            case 0x114d: if (Cur) { ++Depth; ++InlineDepth; } break;  // S_INLINESITE
            case 0x114e: if (Cur) { --Depth; --InlineDepth; } break;  // S_INLINESITE_END
            case 0x0006: case 0x114f:  // S_END / S_PROC_ID_END
                if (!Cur) break;
                if (Depth > 0) { --Depth; break; }
                Finish();
                break;
            case 0x1012:  // S_FRAMEPROC
                if (Cur && Depth == 0) {
                    const uint32_t Flags = Rd<uint32_t>(Syms, Body + 22);
                    LocalBase = static_cast<int>((Flags >> 14) & 3);
                    ParamBase = static_cast<int>((Flags >> 16) & 3);
                }
                break;
            case 0x1111: {  // S_REGREL32 (MSVC debug builds)
                if (!Cur || InlineDepth) break;
                const int32_t Off = Rd<int32_t>(Syms, Body);
                const uint32_t Ti = Rd<uint32_t>(Syms, Body + 4);
                const uint16_t Reg = Rd<uint16_t>(Syms, Body + 8);
                const QString Name = CStrAt(Syms, Body + 10, RecEnd);
                if (Depth == 0) RegRelNames << Name;
                if (Reg == CvAmd64Rsp)
                    Building.Locals.append({Name, Types.Name(Ti), Off, DebugVariable::FrameBase::SpAfterPrologue});
                else if (Reg == CvAmd64Rbp)
                    Building.Locals.append({Name, Types.Name(Ti), Off, DebugVariable::FrameBase::FramePointer});
                break;
            }
            case 0x113e: {  // S_LOCAL (clang, MSVC optimized): location follows in S_DEFRANGE_*
                if (!Cur || InlineDepth) { HavePending = false; break; }
                const uint32_t Ti = Rd<uint32_t>(Syms, Body);
                const uint16_t Flags = Rd<uint16_t>(Syms, Body + 4);
                PendingLocal = DebugVariable{CStrAt(Syms, Body + 6, RecEnd), Types.Name(Ti), 0, DebugVariable::FrameBase::SpAfterPrologue};
                PendingIsParam = (Flags & 1) != 0;
                if (PendingIsParam && Depth == 0) ParamNames << PendingLocal.Name;
                HavePending = true;
                break;
            }
            case 0x1142: case 0x1144: {  // S_DEFRANGE_FRAMEPOINTER_REL[_FULL_SCOPE]
                if (!Cur || !HavePending) break;
                const int Base = PendingIsParam ? ParamBase : LocalBase;
                if (Base == 1 || Base == 2) {  // 1 = rsp after the prologue, 2 = rbp
                    PendingLocal.CfaOffset = Rd<int32_t>(Syms, Body);
                    PendingLocal.Base = Base == 1 ? DebugVariable::FrameBase::SpAfterPrologue : DebugVariable::FrameBase::FramePointer;
                    Building.Locals.append(PendingLocal);
                }
                HavePending = false;
                break;
            }
            case 0x1145: {  // S_DEFRANGE_REGISTER_REL
                if (!Cur || !HavePending) break;
                const uint16_t Reg = Rd<uint16_t>(Syms, Body);
                if (Reg == CvAmd64Rsp || Reg == CvAmd64Rbp) {
                    PendingLocal.CfaOffset = Rd<int32_t>(Syms, Body + 4);
                    PendingLocal.Base = Reg == CvAmd64Rsp ? DebugVariable::FrameBase::SpAfterPrologue : DebugVariable::FrameBase::FramePointer;
                    Building.Locals.append(PendingLocal);
                }
                HavePending = false;
                break;
            }
            default: break;
            }
        }
        Finish();
    }

    // Public symbols: names for code without module debug info.
    if (SymRecordStream != 0xffff) {
        const QByteArray Rec = M.Stream(SymRecordStream);
        for (qsizetype S = 0; S + 4 <= Rec.size();) {
            const uint16_t Len = Rd<uint16_t>(Rec, S);
            const uint16_t Kind = Rd<uint16_t>(Rec, S + 2);
            const qsizetype Body = S + 4;
            const qsizetype RecEnd = S + 2 + Len;
            if (Len < 2 || RecEnd > Rec.size()) break;
            S = RecEnd;
            if (Kind != 0x110e) continue;  // S_PUB32
            const uint32_t Flags = Rd<uint32_t>(Rec, Body);
            const uint32_t Off = Rd<uint32_t>(Rec, Body + 4);
            const uint16_t Seg = Rd<uint16_t>(Rec, Body + 8);
            if (!(Flags & 2)) continue;  // not code
            const Address Va = ToVa(Seg, Off);
            if (Va) Out.Publics.append({Va, CStrAt(Rec, Body + 10, RecEnd)});
        }
    }

    std::sort(Out.Functions.begin(), Out.Functions.end(),
              [](const DebugFunction& A, const DebugFunction& B) { return A.Low < B.Low; });
    Out.Found = !Out.Functions.isEmpty() || !Out.Publics.isEmpty();
    if (!Out.Found) Out.Error = "PDB has no functions";
    return Out;
}

DebugInfo LoadPdbInfo(const BinaryInfo& Info) {
    DebugInfo Out;
    const CodeViewRef Cv = ReadCodeView(Info.FilePath);
    if (!Cv.Found) { Out.Error = "no CodeView debug entry"; return Out; }
    const Address ImageBase = Info.ImageBase ? Info.ImageBase : Cv.ImageBase;

    QString Recorded = Cv.PdbPath;
    Recorded.replace('\\', '/');
    const QString PdbName = Recorded.mid(Recorded.lastIndexOf('/') + 1);
    const QString ExeDir = QFileInfo(Info.FilePath).absolutePath();

    QStringList Candidates{ExeDir + "/" + PdbName, Recorded, QFileInfo(Info.FilePath).path() + "/" + QFileInfo(Info.FilePath).completeBaseName() + ".pdb"};

    // Symbol stores: srv*<cache>*<url>, cache*<dir>, or plain directories.
    QStringList Stores;
    for (const char* Var : {"FIDRA_SYMBOL_PATH", "_NT_SYMBOL_PATH"}) {
        for (const QString& Part : qEnvironmentVariable(Var).split(QRegularExpression("[;]"), Qt::SkipEmptyParts)) {
            const QStringList Fields = Part.split('*');
            if (Fields.first().compare("srv", Qt::CaseInsensitive) == 0 || Fields.first().compare("cache", Qt::CaseInsensitive) == 0) {
                for (int I = 1; I < Fields.size(); ++I)
                    if (!Fields[I].startsWith("http", Qt::CaseInsensitive)) Stores << Fields[I];
            } else {
                Stores << Part;
            }
        }
    }
    for (const QString& Cache : QStandardPaths::standardLocations(QStandardPaths::GenericCacheLocation))
        Stores << Cache + "/fidra/symbols";
    const QString Key = StoreKey(Cv.Guid, Cv.Age);
    for (const QString& Store : Stores) {
        Candidates << Store + "/" + PdbName + "/" + Key + "/" + PdbName << Store + "/" + PdbName;
    }

    for (const QString& C : Candidates) {
        if (C.isEmpty() || !QFileInfo(C).isFile()) continue;
        DebugInfo D = ParsePdbFile(C, ImageBase, Cv.Guid);
        if (D.Found) return D;
        Out.Error = C + ": " + D.Error;
    }
    if (Out.Error.isEmpty()) Out.Error = "no PDB found for " + PdbName + " (" + Key + ")";
    return Out;
}

}
