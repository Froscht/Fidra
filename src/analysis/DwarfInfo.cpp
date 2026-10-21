#include "DwarfInfo.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QStandardPaths>
#include <QVector>
#include <algorithm>
#include <cstring>

namespace Fidra {

namespace {

// ---------------------------------------------------------------- ELF file access

struct ElfFile {
    bool Ok = false;
    QString Error;
    QHash<QString, QByteArray> Sections;  // decompressed contents of the wanted sections
    QByteArray BuildId;
    QString DebugLink;
};

uint64_t ReadUN(const uint8_t* P, int N) {
    uint64_t V = 0;
    std::memcpy(&V, P, static_cast<size_t>(N));
    return V;
}

bool Inflate(const uint8_t* Src, size_t SrcLen, uint64_t OutSize, QByteArray& Out) {
    if (OutSize == 0 || OutSize > 0x7fffffffULL) return false;
    // qUncompress wants the expected size as a 4-byte big-endian prefix.
    QByteArray Buf;
    Buf.resize(static_cast<qsizetype>(4 + SrcLen));
    Buf[0] = static_cast<char>((OutSize >> 24) & 0xff);
    Buf[1] = static_cast<char>((OutSize >> 16) & 0xff);
    Buf[2] = static_cast<char>((OutSize >> 8) & 0xff);
    Buf[3] = static_cast<char>(OutSize & 0xff);
    std::memcpy(Buf.data() + 4, Src, SrcLen);
    Out = qUncompress(Buf);
    return static_cast<uint64_t>(Out.size()) == OutSize;
}

ElfFile ReadElf(const QString& Path) {
    ElfFile F;
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly)) { F.Error = File.errorString(); return F; }
    const qint64 Size = File.size();
    const uint8_t* D = Size > 0 ? File.map(0, Size) : nullptr;
    if (!D || Size < 64 || std::memcmp(D, "\x7f" "ELF", 4) != 0) { F.Error = "not an ELF file"; return F; }
    if (D[5] != 1) { F.Error = "big-endian ELF not supported"; return F; }
    const bool Is64 = D[4] == 2;
    const uint64_t ShOff = Is64 ? ReadUN(D + 0x28, 8) : ReadUN(D + 0x20, 4);
    const uint16_t ShEntSize = static_cast<uint16_t>(ReadUN(D + (Is64 ? 0x3a : 0x2e), 2));
    const uint16_t ShNum = static_cast<uint16_t>(ReadUN(D + (Is64 ? 0x3c : 0x30), 2));
    const uint16_t ShStrNdx = static_cast<uint16_t>(ReadUN(D + (Is64 ? 0x3e : 0x32), 2));
    if (ShOff == 0 || ShOff + static_cast<uint64_t>(ShNum) * ShEntSize > static_cast<uint64_t>(Size) || ShStrNdx >= ShNum) {
        F.Error = "no section headers";
        return F;
    }

    struct Sh { uint32_t Name, Type; uint64_t Flags, Offset, Size; };
    auto Header = [&](int I) {
        const uint8_t* H = D + ShOff + static_cast<uint64_t>(I) * ShEntSize;
        Sh S;
        S.Name = static_cast<uint32_t>(ReadUN(H, 4));
        S.Type = static_cast<uint32_t>(ReadUN(H + 4, 4));
        S.Flags = Is64 ? ReadUN(H + 8, 8) : ReadUN(H + 8, 4);
        S.Offset = Is64 ? ReadUN(H + 24, 8) : ReadUN(H + 16, 4);
        S.Size = Is64 ? ReadUN(H + 32, 8) : ReadUN(H + 20, 4);
        return S;
    };
    const Sh StrSh = Header(ShStrNdx);
    if (StrSh.Offset + StrSh.Size > static_cast<uint64_t>(Size)) { F.Error = "bad section name table"; return F; }

    for (int I = 0; I < ShNum; ++I) {
        const Sh S = Header(I);
        if (S.Name >= StrSh.Size || S.Type == 8 /* NOBITS */) continue;
        QString Name = QString::fromLatin1(reinterpret_cast<const char*>(D + StrSh.Offset + S.Name));
        if (S.Offset + S.Size > static_cast<uint64_t>(Size)) continue;
        const uint8_t* Body = D + S.Offset;

        if (Name == ".note.gnu.build-id" && S.Size >= 16) {
            const uint32_t NameSz = static_cast<uint32_t>(ReadUN(Body, 4));
            const uint32_t DescSz = static_cast<uint32_t>(ReadUN(Body + 4, 4));
            const uint64_t DescOff = 12 + ((NameSz + 3) & ~3u);
            if (DescOff + DescSz <= S.Size) F.BuildId = QByteArray(reinterpret_cast<const char*>(Body + DescOff), DescSz);
            continue;
        }
        if (Name == ".gnu_debuglink") {
            F.DebugLink = QString::fromLocal8Bit(reinterpret_cast<const char*>(Body), static_cast<qsizetype>(qstrnlen(reinterpret_cast<const char*>(Body), static_cast<size_t>(S.Size))));
            continue;
        }

        bool OldZlib = false;
        if (Name.startsWith(".zdebug_")) { Name = ".debug_" + Name.mid(8); OldZlib = true; }
        if (!Name.startsWith(".debug_")) continue;

        QByteArray Data;
        if (S.Flags & 0x800) {  // SHF_COMPRESSED
            const size_t ChSize = Is64 ? 24 : 12;
            if (S.Size < ChSize) continue;
            const uint32_t ChType = static_cast<uint32_t>(ReadUN(Body, 4));
            const uint64_t OutSize = Is64 ? ReadUN(Body + 8, 8) : ReadUN(Body + 4, 4);
            if (ChType != 1) { F.Error = "section " + Name + " is zstd-compressed (only zlib is supported)"; continue; }
            if (!Inflate(Body + ChSize, static_cast<size_t>(S.Size - ChSize), OutSize, Data)) continue;
        } else if (OldZlib) {
            if (S.Size < 12 || std::memcmp(Body, "ZLIB", 4) != 0) continue;
            uint64_t OutSize = 0;
            for (int B = 0; B < 8; ++B) OutSize = (OutSize << 8) | Body[4 + B];
            if (!Inflate(Body + 12, static_cast<size_t>(S.Size - 12), OutSize, Data)) continue;
        } else {
            Data = QByteArray(reinterpret_cast<const char*>(Body), static_cast<qsizetype>(S.Size));
        }
        F.Sections.insert(Name, Data);
    }
    F.Ok = true;
    return F;
}

// ---------------------------------------------------------------- DWARF constants

enum : uint16_t {
    TagArrayType = 0x01, TagClassType = 0x02, TagEnumType = 0x04, TagFormalParameter = 0x05,
    TagLexicalBlock = 0x0b, TagPointerType = 0x0f, TagReferenceType = 0x10, TagCompileUnit = 0x11,
    TagStructType = 0x13, TagSubroutineType = 0x15, TagTypedef = 0x16, TagUnionType = 0x17,
    TagUnspecifiedParams = 0x18, TagInlinedSubroutine = 0x1d, TagPtrToMember = 0x1f, TagBaseType = 0x24,
    TagConstType = 0x26, TagSubprogram = 0x2e, TagVariable = 0x34, TagVolatileType = 0x35,
    TagRestrictType = 0x37, TagUnspecifiedType = 0x3b, TagRvalueRefType = 0x42, TagAtomicType = 0x47,
};

enum : uint16_t {
    AtLocation = 0x02, AtName = 0x03, AtByteSize = 0x0b, AtLowPc = 0x11, AtHighPc = 0x12,
    AtUpperBound = 0x2f, AtAbstractOrigin = 0x31, AtCount = 0x37, AtDeclaration = 0x3c, AtExternal = 0x3f,
    AtFrameBase = 0x40, AtSpecification = 0x47, AtType = 0x49, AtEntryPc = 0x52, AtRanges = 0x55,
    AtLinkageName = 0x6e, AtStrOffsetsBase = 0x72, AtAddrBase = 0x73, AtRngListsBase = 0x74,
    AtNoReturn = 0x87, AtMipsLinkageName = 0x2007, AtGnuAddrBase = 0x2133,
};

class Reader {
public:
    Reader(const uint8_t* B, size_t N) : Base(B), End(B + N), P(B) {}
    const uint8_t* Base;
    const uint8_t* End;
    const uint8_t* P;
    bool Bad = false;

    size_t Pos() const { return static_cast<size_t>(P - Base); }
    bool Need(uint64_t N) {
        if (static_cast<uint64_t>(End - P) < N) { Bad = true; P = End; return false; }
        return true;
    }
    uint64_t U(int N) {
        if (!Need(static_cast<uint64_t>(N))) return 0;
        const uint64_t V = ReadUN(P, N);
        P += N;
        return V;
    }
    uint64_t Uleb() {
        uint64_t V = 0;
        int Shift = 0;
        while (P < End) {
            const uint8_t B = *P++;
            if (Shift < 64) V |= static_cast<uint64_t>(B & 0x7f) << Shift;
            Shift += 7;
            if (!(B & 0x80)) return V;
        }
        Bad = true;
        return V;
    }
    int64_t Sleb() {
        int64_t V = 0;
        int Shift = 0;
        uint8_t B = 0;
        while (P < End) {
            B = *P++;
            if (Shift < 64) V |= static_cast<int64_t>(B & 0x7f) << Shift;
            Shift += 7;
            if (!(B & 0x80)) {
                if (Shift < 64 && (B & 0x40)) V |= -(static_cast<int64_t>(1) << Shift);
                return V;
            }
        }
        Bad = true;
        return V;
    }
    const char* CStr() {
        const uint8_t* S = P;
        while (P < End && *P) ++P;
        if (P >= End) { Bad = true; return ""; }
        ++P;
        return reinterpret_cast<const char*>(S);
    }
    void Skip(uint64_t N) { if (Need(N)) P += N; }
};

struct AttrSpec {
    uint16_t Name;
    uint16_t Form;
    int64_t Implicit;
};

struct Abbrev {
    uint16_t Tag = 0;
    bool Children = false;
    QVector<AttrSpec> Attrs;
};

using AbbrevTable = QHash<uint64_t, Abbrev>;

struct Die {
    uint64_t Offset = 0;
    uint16_t Tag = 0;
    int32_t Unit = -1;
    int32_t FirstChild = -1;
    int32_t NextSibling = -1;
    const char* Name = nullptr;
    const char* Linkage = nullptr;
    uint64_t TypeRef = 0;     // section offset, 0 = none
    uint64_t Origin = 0;
    uint64_t Spec = 0;
    uint64_t Low = 0;
    uint64_t High = 0;
    uint64_t EntryPc = 0;
    uint64_t RangesVal = 0;
    uint64_t ByteSize = 0;
    uint64_t Count = 0;
    const uint8_t* Loc = nullptr;
    const uint8_t* FrameBase = nullptr;
    uint16_t LocLen = 0;
    uint16_t FrameBaseLen = 0;
    uint8_t RangesKind = 0;   // 0 none, 1 section offset, 2 rnglistx index
    bool HasLow = false, HasHigh = false, HighIsOffset = false, HasEntryPc = false;
    bool NoReturn = false, Declaration = false, HasCount = false;
};

struct UnitInfo {
    int Version = 4;
    int AddrSize = 8;
    int OffsetSize = 4;
    uint64_t StrOffsetsBase = 0;
    uint64_t AddrBase = 0;
    uint64_t RngListsBase = 0;
    uint64_t BaseAddr = 0;
};

class DwarfParser {
public:
    explicit DwarfParser(const QHash<QString, QByteArray>& S) : Secs(S) {
        Info = Sec(".debug_info");
        Abbr = Sec(".debug_abbrev");
        Str = Sec(".debug_str");
        LineStr = Sec(".debug_line_str");
        StrOffsets = Sec(".debug_str_offsets");
        AddrSec = Sec(".debug_addr");
        RngLists = Sec(".debug_rnglists");
        Ranges = Sec(".debug_ranges");
    }

    bool Run(DebugInfo& Out);

private:
    struct Span { const uint8_t* P = nullptr; size_t N = 0; };
    Span Sec(const char* Name) const {
        auto It = Secs.constFind(QString::fromLatin1(Name));
        if (It == Secs.constEnd()) return {};
        return {reinterpret_cast<const uint8_t*>(It->constData()), static_cast<size_t>(It->size())};
    }

    const AbbrevTable& Abbrevs(uint64_t Off);
    bool ParseUnit(Reader& R);
    const char* StrAt(Span S, uint64_t Off) const {
        if (!S.P || Off >= S.N) return nullptr;
        if (!std::memchr(S.P + Off, 0, S.N - Off)) return nullptr;
        return reinterpret_cast<const char*>(S.P + Off);
    }
    const char* StrIndex(const UnitInfo& U, uint64_t Idx) const {
        const uint64_t At = U.StrOffsetsBase + Idx * static_cast<uint64_t>(U.OffsetSize);
        if (!StrOffsets.P || At + U.OffsetSize > StrOffsets.N) return nullptr;
        return StrAt(Str, ReadUN(StrOffsets.P + At, U.OffsetSize));
    }
    uint64_t AddrIndex(const UnitInfo& U, uint64_t Idx) const {
        const uint64_t At = U.AddrBase + Idx * static_cast<uint64_t>(U.AddrSize);
        if (!AddrSec.P || At + U.AddrSize > AddrSec.N) return 0;
        return ReadUN(AddrSec.P + At, U.AddrSize);
    }
    bool FirstRange(const Die& D, uint64_t& Lo, uint64_t& Hi) const;
    const Die* Find(uint64_t Off) const {
        auto It = Index.constFind(Off);
        return It == Index.constEnd() ? nullptr : &Dies[It.value()];
    }
    QString TypeName(uint64_t Off, int Depth = 0);
    // Follows abstract_origin / specification to the DIE that has the attribute.
    template <typename Pred> const Die* Resolve(const Die* D, Pred Has) const {
        for (int Hop = 0; D && Hop < 6; ++Hop) {
            if (Has(*D)) return D;
            D = Find(D->Origin ? D->Origin : D->Spec);
        }
        return nullptr;
    }
    void CollectLocals(int Parent, int64_t FbAdjust, bool FbIsCfa, QList<DebugVariable>& Out, int Depth);

    const QHash<QString, QByteArray>& Secs;
    Span Info, Abbr, Str, LineStr, StrOffsets, AddrSec, RngLists, Ranges;
    QHash<uint64_t, AbbrevTable> AbbrevCache;
    QVector<Die> Dies;
    QVector<UnitInfo> Units;
    QHash<uint64_t, int> Index;
    QHash<uint64_t, QString> TypeCache;
};

const AbbrevTable& DwarfParser::Abbrevs(uint64_t Off) {
    auto It = AbbrevCache.find(Off);
    if (It != AbbrevCache.end()) return It.value();
    AbbrevTable T;
    if (Off < Abbr.N) {
        Reader R(Abbr.P, Abbr.N);
        R.P += Off;
        while (!R.Bad) {
            const uint64_t Code = R.Uleb();
            if (Code == 0) break;
            Abbrev A;
            A.Tag = static_cast<uint16_t>(R.Uleb());
            A.Children = R.U(1) != 0;
            while (!R.Bad) {
                const uint16_t Name = static_cast<uint16_t>(R.Uleb());
                const uint16_t Form = static_cast<uint16_t>(R.Uleb());
                int64_t Implicit = 0;
                if (Form == 0x21) Implicit = R.Sleb();
                if (Name == 0 && Form == 0) break;
                A.Attrs.append({Name, Form, Implicit});
            }
            T.insert(Code, A);
        }
    }
    return AbbrevCache.insert(Off, T).value();
}

bool DwarfParser::ParseUnit(Reader& R) {
    const size_t UnitStart = R.Pos();
    uint64_t Length = R.U(4);
    int OffsetSize = 4;
    if (Length == 0xffffffffULL) { Length = R.U(8); OffsetSize = 8; }
    const size_t BodyStart = R.Pos();
    if (R.Bad || Length > Info.N - BodyStart) return false;
    const size_t UnitEnd = BodyStart + static_cast<size_t>(Length);

    UnitInfo U;
    U.OffsetSize = OffsetSize;
    U.Version = static_cast<int>(R.U(2));
    uint64_t AbbrevOff = 0;
    uint8_t UnitType = 1;
    if (U.Version >= 5) {
        UnitType = static_cast<uint8_t>(R.U(1));
        U.AddrSize = static_cast<int>(R.U(1));
        AbbrevOff = R.U(OffsetSize);
        if (UnitType == 2 || UnitType == 6) R.Skip(8 + static_cast<uint64_t>(OffsetSize));  // type units
        else if (UnitType == 4 || UnitType == 5) R.Skip(8);                                // skeleton/split
    } else if (U.Version >= 2) {
        AbbrevOff = R.U(OffsetSize);
        U.AddrSize = static_cast<int>(R.U(1));
    } else {
        R.P = R.Base + UnitEnd;
        return true;
    }
    if (U.AddrSize != 4 && U.AddrSize != 8) { R.P = R.Base + UnitEnd; return true; }

    const AbbrevTable& Table = Abbrevs(AbbrevOff);
    const int UnitIdx = Units.size();
    Units.append(U);
    UnitInfo& Unit = Units.last();

    Reader DR(Info.P, UnitEnd);
    DR.P = R.P;
    QVector<int> ParentStack;   // index of the open parent at each depth
    QVector<int> LastChild;     // last child seen at each depth
    ParentStack.append(-1);
    LastChild.append(-1);

    struct Pending { int DieIdx; uint16_t Attr; uint64_t Index; bool IsAddr; };
    QVector<Pending> Deferred;  // strx/addrx values resolved once the unit's bases are known

    while (DR.P < DR.End && !DR.Bad) {
        const uint64_t DieOff = DR.Pos();
        const uint64_t Code = DR.Uleb();
        if (Code == 0) {  // end of siblings
            if (ParentStack.size() > 1) { ParentStack.removeLast(); LastChild.removeLast(); }
            continue;
        }
        auto AIt = Table.constFind(Code);
        if (AIt == Table.constEnd()) break;
        const Abbrev& A = AIt.value();

        Die D;
        D.Offset = DieOff;
        D.Tag = A.Tag;
        D.Unit = UnitIdx;
        const int MyIdx = Dies.size();

        for (const AttrSpec& S : A.Attrs) {
            uint16_t Form = S.Form;
            if (Form == 0x16) Form = static_cast<uint16_t>(DR.Uleb());  // indirect
            uint64_t V = 0;
            int64_t SV = 0;
            const char* Str = nullptr;
            const uint8_t* Blk = nullptr;
            uint64_t BlkLen = 0;
            bool IsRef = false, IsStrIdx = false, IsAddrIdx = false, IsRngIdx = false, IsSigned = false;
            switch (Form) {
            case 0x01: V = DR.U(Unit.AddrSize); break;                                    // addr
            case 0x03: BlkLen = DR.U(2); Blk = DR.P; DR.Skip(BlkLen); break;               // block2
            case 0x04: BlkLen = DR.U(4); Blk = DR.P; DR.Skip(BlkLen); break;               // block4
            case 0x05: V = DR.U(2); break;
            case 0x06: V = DR.U(4); break;
            case 0x07: V = DR.U(8); break;
            case 0x08: Str = DR.CStr(); break;                                             // string
            case 0x09: case 0x18: BlkLen = DR.Uleb(); Blk = DR.P; DR.Skip(BlkLen); break;  // block, exprloc
            case 0x0a: BlkLen = DR.U(1); Blk = DR.P; DR.Skip(BlkLen); break;               // block1
            case 0x0b: V = DR.U(1); break;
            case 0x0c: V = DR.U(1); break;                                                 // flag
            case 0x0d: SV = DR.Sleb(); V = static_cast<uint64_t>(SV); IsSigned = true; break;
            case 0x0e: Str = StrAt(this->Str, DR.U(OffsetSize)); break;                    // strp
            case 0x0f: V = DR.Uleb(); break;
            case 0x10: V = DR.U(U.Version == 2 ? Unit.AddrSize : OffsetSize); IsRef = true; break;  // ref_addr
            case 0x11: V = UnitStart + DR.U(1); IsRef = true; break;
            case 0x12: V = UnitStart + DR.U(2); IsRef = true; break;
            case 0x13: V = UnitStart + DR.U(4); IsRef = true; break;
            case 0x14: V = UnitStart + DR.U(8); IsRef = true; break;
            case 0x15: V = UnitStart + DR.Uleb(); IsRef = true; break;
            case 0x17: V = DR.U(OffsetSize); break;                                        // sec_offset
            case 0x19: V = 1; break;                                                       // flag_present
            case 0x1a: V = DR.Uleb(); IsStrIdx = true; break;                              // strx
            case 0x1b: V = DR.Uleb(); IsAddrIdx = true; break;                             // addrx
            case 0x1c: DR.Skip(4); break;                                                  // ref_sup4
            case 0x1d: DR.Skip(static_cast<uint64_t>(OffsetSize)); break;                  // strp_sup
            case 0x1e: DR.Skip(16); break;                                                 // data16
            case 0x1f: Str = StrAt(LineStr, DR.U(OffsetSize)); break;                      // line_strp
            case 0x20: DR.Skip(8); break;                                                  // ref_sig8
            case 0x21: SV = S.Implicit; V = static_cast<uint64_t>(SV); IsSigned = true; break;
            case 0x22: DR.Uleb(); break;                                                   // loclistx
            case 0x23: V = DR.Uleb(); IsRngIdx = true; break;                              // rnglistx
            case 0x24: DR.Skip(8); break;                                                  // ref_sup8
            case 0x25: V = DR.U(1); IsStrIdx = true; break;
            case 0x26: V = DR.U(2); IsStrIdx = true; break;
            case 0x27: V = DR.U(3); IsStrIdx = true; break;
            case 0x28: V = DR.U(4); IsStrIdx = true; break;
            case 0x29: V = DR.U(1); IsAddrIdx = true; break;
            case 0x2a: V = DR.U(2); IsAddrIdx = true; break;
            case 0x2b: V = DR.U(3); IsAddrIdx = true; break;
            case 0x2c: V = DR.U(4); IsAddrIdx = true; break;
            case 0x1f01: V = DR.Uleb(); IsAddrIdx = true; break;                           // GNU_addr_index
            case 0x1f02: V = DR.Uleb(); IsStrIdx = true; break;                            // GNU_str_index
            case 0x1f20: case 0x1f21: DR.Skip(static_cast<uint64_t>(OffsetSize)); break;   // dwz alt file
            default: DR.Bad = true; break;
            }
            if (DR.Bad) break;
            Q_UNUSED(IsSigned);

            if (IsStrIdx || IsAddrIdx) {
                if (S.Name == AtName || S.Name == AtLinkageName || S.Name == AtMipsLinkageName || S.Name == AtLowPc ||
                    S.Name == AtHighPc || S.Name == AtEntryPc)
                    Deferred.append({MyIdx, S.Name, V, IsAddrIdx});
                continue;
            }
            switch (S.Name) {
            case AtName: D.Name = Str; break;
            case AtLinkageName: case AtMipsLinkageName: D.Linkage = Str; break;
            case AtType: if (IsRef) D.TypeRef = V; break;
            case AtAbstractOrigin: if (IsRef) D.Origin = V; break;
            case AtSpecification: if (IsRef) D.Spec = V; break;
            case AtLowPc: D.Low = V; D.HasLow = true; break;
            case AtHighPc: D.High = V; D.HasHigh = true; D.HighIsOffset = Form != 0x01; break;
            case AtEntryPc: D.EntryPc = V; D.HasEntryPc = Form == 0x01; break;
            case AtRanges: D.RangesVal = V; D.RangesKind = IsRngIdx ? 2 : 1; break;
            case AtByteSize: D.ByteSize = V; break;
            case AtCount: D.Count = V; D.HasCount = true; break;
            case AtUpperBound: if (!D.HasCount) { D.Count = V + 1; D.HasCount = true; } break;
            case AtNoReturn: D.NoReturn = V != 0; break;
            case AtDeclaration: D.Declaration = V != 0; break;
            case AtLocation: if (Blk && BlkLen < 0xffff) { D.Loc = Blk; D.LocLen = static_cast<uint16_t>(BlkLen); } break;
            case AtFrameBase: if (Blk && BlkLen < 0xffff) { D.FrameBase = Blk; D.FrameBaseLen = static_cast<uint16_t>(BlkLen); } break;
            case AtStrOffsetsBase: Unit.StrOffsetsBase = V; break;
            case AtAddrBase: case AtGnuAddrBase: Unit.AddrBase = V; break;
            case AtRngListsBase: Unit.RngListsBase = V; break;
            default: break;
            }
        }
        if (DR.Bad) break;

        if (D.Tag == TagCompileUnit || D.Tag == 0x4a /* skeleton */ || D.Tag == 0x3c /* partial */) {
            if (D.HasLow) Unit.BaseAddr = D.Low;
        }

        // Tree links.
        const int Parent = ParentStack.last();
        if (LastChild.last() >= 0) Dies[LastChild.last()].NextSibling = MyIdx;
        else if (Parent >= 0) Dies[Parent].FirstChild = MyIdx;
        LastChild.last() = MyIdx;

        Index.insert(DieOff, MyIdx);
        Dies.append(D);
        if (A.Children) { ParentStack.append(MyIdx); LastChild.append(-1); }
        if (Dies.size() > 40'000'000) return false;
    }

    // DWARF 5 bases default past the section headers when absent.
    if (Unit.Version >= 5) {
        if (Unit.StrOffsetsBase == 0 && StrOffsets.N >= 8) Unit.StrOffsetsBase = OffsetSize == 8 ? 16 : 8;
    }
    for (const Pending& P : Deferred) {
        Die& D = Dies[P.DieIdx];
        if (P.IsAddr) {
            const uint64_t A = AddrIndex(Unit, P.Index);
            if (P.Attr == AtLowPc) { D.Low = A; D.HasLow = true; }
            else if (P.Attr == AtHighPc) { D.High = A; D.HasHigh = true; D.HighIsOffset = false; }
            else if (P.Attr == AtEntryPc) { D.EntryPc = A; D.HasEntryPc = true; }
        } else {
            const char* S = StrIndex(Unit, P.Index);
            if (P.Attr == AtName) D.Name = S;
            else D.Linkage = S;
        }
        if ((D.Tag == TagCompileUnit || D.Tag == 0x4a) && D.HasLow) Unit.BaseAddr = D.Low;
    }

    R.P = R.Base + UnitEnd;
    return true;
}

bool DwarfParser::FirstRange(const Die& D, uint64_t& Lo, uint64_t& Hi) const {
    const UnitInfo& U = Units[D.Unit];
    uint64_t Base = U.BaseAddr;
    if (U.Version >= 5) {
        uint64_t Off = D.RangesVal;
        if (D.RangesKind == 2) {
            const uint64_t At = U.RngListsBase + D.RangesVal * static_cast<uint64_t>(U.OffsetSize);
            if (!RngLists.P || At + U.OffsetSize > RngLists.N) return false;
            Off = U.RngListsBase + ReadUN(RngLists.P + At, U.OffsetSize);
        }
        if (!RngLists.P || Off >= RngLists.N) return false;
        Reader R(RngLists.P, RngLists.N);
        R.P += Off;
        for (int Guard = 0; Guard < 4096 && !R.Bad; ++Guard) {
            const uint8_t Kind = static_cast<uint8_t>(R.U(1));
            switch (Kind) {
            case 0: return false;                                                          // end_of_list
            case 1: Base = AddrIndex(U, R.Uleb()); break;                                  // base_addressx
            case 2: Lo = AddrIndex(U, R.Uleb()); Hi = AddrIndex(U, R.Uleb()); return Hi > Lo;
            case 3: Lo = AddrIndex(U, R.Uleb()); Hi = Lo + R.Uleb(); return Hi > Lo;
            case 4: Lo = Base + R.Uleb(); Hi = Base + R.Uleb(); if (Hi > Lo) return true; break;
            case 5: Base = R.U(U.AddrSize); break;
            case 6: Lo = R.U(U.AddrSize); Hi = R.U(U.AddrSize); return Hi > Lo;
            case 7: Lo = R.U(U.AddrSize); Hi = Lo + R.Uleb(); return Hi > Lo;
            default: return false;
            }
        }
        return false;
    }
    if (!Ranges.P || D.RangesVal >= Ranges.N) return false;
    Reader R(Ranges.P, Ranges.N);
    R.P += D.RangesVal;
    const uint64_t MaxAddr = U.AddrSize == 4 ? 0xffffffffULL : ~0ULL;
    while (!R.Bad) {
        const uint64_t A = R.U(U.AddrSize);
        const uint64_t B = R.U(U.AddrSize);
        if (A == 0 && B == 0) return false;
        if (A == MaxAddr) { Base = B; continue; }
        if (B > A) { Lo = Base + A; Hi = Base + B; return true; }
    }
    return false;
}

QString DwarfParser::TypeName(uint64_t Off, int Depth) {
    if (Off == 0) return "void";
    if (Depth > 12) return "void";
    auto Cached = TypeCache.constFind(Off);
    if (Cached != TypeCache.constEnd()) return Cached.value();
    const Die* D = Find(Off);
    if (!D) return "void";

    auto Named = [&](const char* Prefix) {
        const QString N = D->Name ? QString::fromUtf8(D->Name) : QString("<anonymous>");
        return Prefix ? QString::fromLatin1(Prefix) + N : N;
    };
    QString T;
    switch (D->Tag) {
    case TagBaseType: case TagTypedef: case TagUnspecifiedType: T = Named(nullptr); break;
    case TagStructType: T = Named(D->Name ? "struct " : "struct "); break;
    case TagUnionType: T = Named("union "); break;
    case TagClassType: T = Named(nullptr); break;
    case TagEnumType: T = Named("enum "); break;
    case TagPointerType: {
        const Die* Target = Find(D->TypeRef);
        if (Target && Target->Tag == TagSubroutineType) {
            QStringList Args;
            for (int C = Target->FirstChild; C >= 0; C = Dies[C].NextSibling) {
                if (Dies[C].Tag == TagFormalParameter) Args << TypeName(Dies[C].TypeRef, Depth + 1);
                else if (Dies[C].Tag == TagUnspecifiedParams) Args << "...";
            }
            T = TypeName(Target->TypeRef, Depth + 1) + " (*)(" + Args.join(", ") + ")";
        } else {
            T = TypeName(D->TypeRef, Depth + 1) + "*";
        }
        break;
    }
    case TagReferenceType: T = TypeName(D->TypeRef, Depth + 1) + "&"; break;
    case TagRvalueRefType: T = TypeName(D->TypeRef, Depth + 1) + "&&"; break;
    case TagConstType: {
        const QString Inner = TypeName(D->TypeRef, Depth + 1);
        T = Inner.endsWith('*') ? Inner + " const" : "const " + Inner;
        break;
    }
    case TagVolatileType: T = "volatile " + TypeName(D->TypeRef, Depth + 1); break;
    case TagRestrictType: case TagAtomicType: T = TypeName(D->TypeRef, Depth + 1); break;
    case TagArrayType: {
        uint64_t N = 0;
        for (int C = D->FirstChild; C >= 0; C = Dies[C].NextSibling)
            if (Dies[C].HasCount) { N = Dies[C].Count; break; }
        T = TypeName(D->TypeRef, Depth + 1) + (N ? QString("[%1]").arg(N) : QString("[]"));
        break;
    }
    case TagSubroutineType: T = "void"; break;
    case TagPtrToMember: T = "void*"; break;
    default: T = D->Name ? QString::fromUtf8(D->Name) : QString("void"); break;
    }
    TypeCache.insert(Off, T);
    return T;
}

// Stack variables of a function body (descending into lexical blocks but not
// into inlined calls, whose variables belong to the inlined function).
void DwarfParser::CollectLocals(int Parent, int64_t FbAdjust, bool FbIsCfa, QList<DebugVariable>& Out, int Depth) {
    if (Depth > 32) return;
    for (int C = Dies[Parent].FirstChild; C >= 0; C = Dies[C].NextSibling) {
        const Die& V = Dies[C];
        if (V.Tag == TagLexicalBlock) { CollectLocals(C, FbAdjust, FbIsCfa, Out, Depth + 1); continue; }
        // Parameters spilled to the frame (typical at -O0) count as locals too.
        const bool IsParam = V.Tag == TagFormalParameter && Depth == 0;
        if ((V.Tag != TagVariable && !IsParam) || !V.Loc || V.LocLen < 2 || V.Loc[0] != 0x91 /* DW_OP_fbreg */) continue;
        if (!FbIsCfa) continue;
        Reader R(V.Loc + 1, V.LocLen - 1u);
        const int64_t Off = R.Sleb();
        if (R.Bad || R.P != R.End) continue;  // fbreg plus more ops: not a plain slot
        const Die* NameDie = Resolve(&V, [](const Die& X) { return X.Name != nullptr; });
        const Die* TypeDie = Resolve(&V, [](const Die& X) { return X.TypeRef != 0; });
        if (!NameDie) continue;
        Out.append({QString::fromUtf8(NameDie->Name), TypeDie ? TypeName(TypeDie->TypeRef) : QString("int"), Off + FbAdjust});
    }
}

bool DwarfParser::Run(DebugInfo& Out) {
    if (!Info.P || !Abbr.P) { Out.Error = "no .debug_info"; return false; }
    Reader R(Info.P, Info.N);
    while (R.P < R.End && !R.Bad) {
        if (!ParseUnit(R)) break;
    }
    Out.Units = Units.size();

    QHash<uint64_t, int> ByLow;  // Low -> index in Out.Functions
    for (int I = 0; I < Dies.size(); ++I) {
        const Die& D = Dies[I];
        if (D.Tag != TagSubprogram || D.Declaration) continue;
        uint64_t Lo = 0, Hi = 0;
        if (D.HasLow && D.HasHigh) {
            Lo = D.Low;
            Hi = D.HighIsOffset ? D.Low + D.High : D.High;
        } else if (D.RangesKind && FirstRange(D, Lo, Hi)) {
            if (D.HasEntryPc && D.EntryPc >= Lo && D.EntryPc < Hi) Lo = D.EntryPc;
        } else {
            continue;
        }
        if (Lo == 0 || Hi <= Lo || Hi - Lo > 0x10000000) continue;

        const Die* NameDie = Resolve(&D, [](const Die& X) { return X.Name != nullptr; });
        const Die* LinkDie = Resolve(&D, [](const Die& X) { return X.Linkage != nullptr; });
        const Die* TypeDie = Resolve(&D, [](const Die& X) { return X.TypeRef != 0; });
        const Die* NoRetDie = Resolve(&D, [](const Die& X) { return X.NoReturn; });
        if (!NameDie && !LinkDie) continue;

        DebugFunction F;
        F.Low = Lo;
        F.High = Hi;
        F.SourceName = NameDie ? QString::fromUtf8(NameDie->Name) : QString();
        F.Name = LinkDie ? QString::fromUtf8(LinkDie->Linkage) : F.SourceName;
        F.Proto.Name = F.Name;
        F.Proto.ReturnType = TypeDie ? TypeName(TypeDie->TypeRef) : QString("void");
        F.Proto.NoReturn = NoRetDie != nullptr;

        // Parameters: the concrete DIE's own, else the abstract instance's.
        const Die* ParamOwner = &D;
        for (int Hop = 0; ParamOwner && Hop < 6; ++Hop) {
            bool HasParams = false;
            for (int C = ParamOwner->FirstChild; C >= 0; C = Dies[C].NextSibling)
                if (Dies[C].Tag == TagFormalParameter || Dies[C].Tag == TagUnspecifiedParams) { HasParams = true; break; }
            if (HasParams) break;
            ParamOwner = Find(ParamOwner->Origin ? ParamOwner->Origin : ParamOwner->Spec);
        }
        if (ParamOwner) {
            for (int C = ParamOwner->FirstChild; C >= 0; C = Dies[C].NextSibling) {
                const Die& P = Dies[C];
                if (P.Tag == TagUnspecifiedParams) { F.Proto.Variadic = true; continue; }
                if (P.Tag != TagFormalParameter) continue;
                const Die* PName = Resolve(&P, [](const Die& X) { return X.Name != nullptr; });
                const Die* PType = Resolve(&P, [](const Die& X) { return X.TypeRef != 0; });
                FuncParam FP;
                FP.Name = PName ? QString::fromUtf8(PName->Name) : QString("a%1").arg(F.Proto.Params.size() + 1);
                FP.Type = PType ? TypeName(PType->TypeRef) : QString("int");
                F.Proto.Params.append(FP);
            }
        }

        // Stack locals need the frame base as an offset from the CFA.
        bool FbIsCfa = false;
        int64_t FbAdjust = 0;
        if (D.FrameBase && D.FrameBaseLen >= 1) {
            if (D.FrameBase[0] == 0x9c && D.FrameBaseLen == 1) {      // DW_OP_call_frame_cfa
                FbIsCfa = true;
            } else if (D.FrameBase[0] == 0x76 && D.FrameBaseLen >= 2) {  // DW_OP_breg6 (rbp): rbp = CFA - 16
                Reader FR(D.FrameBase + 1, D.FrameBaseLen - 1u);
                FbAdjust = FR.Sleb() - 16;
                FbIsCfa = !FR.Bad;
            }
        }
        CollectLocals(I, FbAdjust, FbIsCfa, F.Locals, 0);

        auto Existing = ByLow.constFind(Lo);
        if (Existing != ByLow.constEnd()) {
            DebugFunction& Prev = Out.Functions[Existing.value()];
            if (Prev.Proto.Params.isEmpty() && !F.Proto.Params.isEmpty()) Prev = F;
            continue;
        }
        ByLow.insert(Lo, Out.Functions.size());
        Out.Functions.append(F);
    }
    std::sort(Out.Functions.begin(), Out.Functions.end(),
              [](const DebugFunction& A, const DebugFunction& B) { return A.Low < B.Low; });
    Out.Found = !Out.Functions.isEmpty();
    if (!Out.Found && Out.Error.isEmpty()) Out.Error = "no functions in DWARF";
    return Out.Found;
}

QString HexId(const QByteArray& Id) { return QString::fromLatin1(Id.toHex()); }

}

DebugInfo ParseDwarfFile(const QString& Path) {
    DebugInfo Out;
    Out.Path = Path;
    const ElfFile F = ReadElf(Path);
    if (!F.Ok) { Out.Error = F.Error; return Out; }
    if (!F.Sections.contains(".debug_info")) { Out.Error = F.Error.isEmpty() ? "no .debug_info" : F.Error; return Out; }
    DwarfParser P(F.Sections);
    P.Run(Out);
    return Out;
}

DebugInfo LoadDebugInfo(const BinaryInfo& Info) {
    DebugInfo Out;
    if (Info.FilePath.isEmpty()) { Out.Error = "no file path"; return Out; }
    {
        QFile Probe(Info.FilePath);
        if (Probe.open(QIODevice::ReadOnly) && Probe.read(2) == "MZ") return LoadPdbInfo(Info);
    }
    const ElfFile Self = ReadElf(Info.FilePath);
    if (!Self.Ok) { Out.Error = Self.Error; return Out; }
    if (Self.Sections.contains(".debug_info")) {
        DwarfParser P(Self.Sections);
        Out.Path = Info.FilePath;
        P.Run(Out);
        if (Out.Found) return Out;
    }

    QStringList Candidates;
    if (Self.BuildId.size() >= 2) {
        const QString Hex = HexId(Self.BuildId);
        Candidates << "/usr/lib/debug/.build-id/" + Hex.left(2) + "/" + Hex.mid(2) + ".debug";
        for (const QString& Cache : QStandardPaths::standardLocations(QStandardPaths::GenericCacheLocation))
            Candidates << Cache + "/debuginfod_client/" + Hex + "/debuginfo";
    }
    if (!Self.DebugLink.isEmpty()) {
        const QFileInfo Bin(Info.FilePath);
        const QString Dir = Bin.absolutePath();
        Candidates << Dir + "/" + Self.DebugLink << Dir + "/.debug/" + Self.DebugLink
                   << "/usr/lib/debug" + Dir + "/" + Self.DebugLink;
        const QString Canon = QFileInfo(Bin.canonicalFilePath()).absolutePath();
        if (Canon != Dir) Candidates << "/usr/lib/debug" + Canon + "/" + Self.DebugLink;
    }
    for (const QString& C : Candidates) {
        if (!QFileInfo::exists(C) || QFileInfo(C).canonicalFilePath() == QFileInfo(Info.FilePath).canonicalFilePath()) continue;
        DebugInfo D = ParseDwarfFile(C);
        if (D.Found) return D;
        if (Out.Error.isEmpty() || !D.Error.isEmpty()) Out.Error = C + ": " + D.Error;
    }
    if (Out.Error.isEmpty()) Out.Error = "no debug info found";
    return Out;
}

}
