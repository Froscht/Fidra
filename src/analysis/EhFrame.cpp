#include "EhFrame.h"

#include <QHash>
#include <algorithm>
#include <cstring>

namespace Fidra {

namespace {

// DWARF pointer encodings (DW_EH_PE_*).
constexpr uint8_t PeOmit = 0xff;
constexpr uint8_t PeFormatMask = 0x0f;
constexpr uint8_t PeApplyMask = 0x70;
constexpr uint8_t PePcRel = 0x10;
constexpr uint8_t PeIndirect = 0x80;

class Reader {
public:
    Reader(const uint8_t* Bytes, size_t Size, Address BaseAddr) : Bytes(Bytes), Size(Size), BaseAddr(BaseAddr) {}

    bool Ok() const { return !Failed; }
    size_t Pos = 0;

    bool Has(size_t Len) {
        if (Pos + Len > Size || Pos + Len < Pos) { Failed = true; return false; }
        return true;
    }

    uint8_t U8() { return Has(1) ? Bytes[Pos++] : 0; }

    template <typename T> T Fixed() {
        T V{};
        if (!Has(sizeof(T))) return V;
        std::memcpy(&V, Bytes + Pos, sizeof(T));
        Pos += sizeof(T);
        return V;
    }

    uint64_t Uleb() {
        uint64_t V = 0;
        for (int Shift = 0; Shift < 64; Shift += 7) {
            const uint8_t B = U8();
            if (Failed) return 0;
            V |= static_cast<uint64_t>(B & 0x7f) << Shift;
            if (!(B & 0x80)) return V;
        }
        Failed = true;
        return 0;
    }

    int64_t Sleb() {
        int64_t V = 0;
        int Shift = 0;
        uint8_t B = 0;
        do {
            B = U8();
            if (Failed || Shift >= 64) { Failed = true; return 0; }
            V |= static_cast<int64_t>(B & 0x7f) << Shift;
            Shift += 7;
        } while (B & 0x80);
        if (Shift < 64 && (B & 0x40)) V |= -(static_cast<int64_t>(1) << Shift);
        return V;
    }

    const char* CString() {
        const char* S = reinterpret_cast<const char*>(Bytes + Pos);
        while (Pos < Size && Bytes[Pos] != 0) ++Pos;
        if (Pos >= Size) { Failed = true; return ""; }
        ++Pos;
        return S;
    }

    // Reads a pointer in the given encoding. ApplyBase = false reads the raw
    // value only (used for an FDE's address range).
    uint64_t Encoded(uint8_t Enc, int PtrSize, bool ApplyBase = true) {
        if (Enc == PeOmit) return 0;
        const Address FieldAddr = BaseAddr + Pos;
        uint64_t V = 0;
        switch (Enc & PeFormatMask) {
        case 0x00: V = PtrSize == 4 ? Fixed<uint32_t>() : Fixed<uint64_t>(); break;
        case 0x01: V = Uleb(); break;
        case 0x02: V = Fixed<uint16_t>(); break;
        case 0x03: V = Fixed<uint32_t>(); break;
        case 0x04: V = Fixed<uint64_t>(); break;
        case 0x09: V = static_cast<uint64_t>(Sleb()); break;
        case 0x0a: V = static_cast<uint64_t>(static_cast<int64_t>(Fixed<int16_t>())); break;
        case 0x0b: V = static_cast<uint64_t>(static_cast<int64_t>(Fixed<int32_t>())); break;
        case 0x0c: V = static_cast<uint64_t>(Fixed<int64_t>()); break;
        default: Failed = true; return 0;
        }
        if (!ApplyBase) return V;
        switch (Enc & PeApplyMask) {
        case 0x00: break;
        case PePcRel: V += FieldAddr; break;
        default: break;  // textrel/datarel/funcrel do not occur in .eh_frame
        }
        if (PtrSize == 4) V &= 0xffffffffULL;
        return V;
    }

private:
    const uint8_t* Bytes;
    size_t Size;
    Address BaseAddr;
    bool Failed = false;
};

struct CieData {
    uint8_t FdeEnc = 0;  // absptr unless 'R' says otherwise
    bool HasAugData = false;
};

// True for addresses in executable code outside the PLT. The PLT has one FDE
// covering every stub; treating it as one function would swallow the stubs.
bool InFunctionCode(const BinaryInfo& Info, Address Addr) {
    for (const Segment& Seg : Info.Segments) {
        if ((Seg.Type == SegmentType::Code || Seg.IsExecutable) &&
            Addr >= Seg.VirtualAddress && Addr < Seg.VirtualAddress + Seg.VirtualSize) {
            return !Seg.Name.startsWith(".plt") && !Seg.Name.endsWith("/__stubs");
        }
    }
    return false;
}

bool ParseCie(Reader R, const BinaryInfo& Info, CieData& Out) {
    const int PtrSize = Info.Is64Bit ? 8 : 4;
    const uint8_t Version = R.U8();
    if (Version != 1 && Version != 3 && Version != 4) return false;
    const char* Aug = R.CString();
    if (!R.Ok()) return false;
    if (Aug[0] == 'e' && Aug[1] == 'h') R.Encoded(0x00, PtrSize);  // old GCC "eh" data
    if (Version == 4) { R.U8(); R.U8(); }                          // address_size, segment_size
    R.Uleb();                                                       // code alignment
    R.Sleb();                                                       // data alignment
    if (Version == 1) R.U8(); else R.Uleb();                        // return register
    if (Aug[0] != 'z') return R.Ok();

    Out.HasAugData = true;
    const uint64_t AugLen = R.Uleb();
    const size_t AugEnd = R.Pos + AugLen;
    for (const char* C = Aug + 1; *C && R.Ok() && R.Pos < AugEnd; ++C) {
        switch (*C) {
        case 'R': Out.FdeEnc = R.U8(); break;
        case 'L': R.U8(); break;
        case 'P': { const uint8_t Enc = R.U8(); R.Encoded(static_cast<uint8_t>(Enc & ~PeIndirect), PtrSize); break; }
        case 'S': case 'B': case 'G': break;
        default: return R.Ok();  // unknown letter: the length still lets FDEs parse
        }
    }
    return R.Ok();
}

void ParseSection(const BinaryInfo& Info, const Segment& Seg, EhFrameInfo& Out) {
    const uint8_t* Bytes = reinterpret_cast<const uint8_t*>(Seg.Data.constData());
    const size_t Size = static_cast<size_t>(Seg.Data.size());
    const int PtrSize = Info.Is64Bit ? 8 : 4;
    QHash<size_t, CieData> Cies;

    size_t Off = 0;
    while (Off + 4 <= Size) {
        Reader R(Bytes, Size, Seg.VirtualAddress);
        R.Pos = Off;
        uint64_t Length = R.Fixed<uint32_t>();
        if (Length == 0) break;  // terminator
        if (Length == 0xffffffffULL) Length = R.Fixed<uint64_t>();
        const size_t Body = R.Pos;
        const size_t Next = Body + Length;
        if (!R.Ok() || Next > Size || Next <= Off) break;

        const size_t IdPos = R.Pos;
        const uint32_t CieId = R.Fixed<uint32_t>();
        if (CieId == 0) {
            CieData Cie;
            Reader CieR(Bytes, Next, Seg.VirtualAddress);
            CieR.Pos = R.Pos;
            if (ParseCie(CieR, Info, Cie)) {
                Cies.insert(Off, Cie);
                ++Out.CieCount;
            }
        } else if (CieId <= IdPos) {
            auto It = Cies.constFind(IdPos - CieId);
            if (It != Cies.constEnd()) {
                Reader FdeR(Bytes, Next, Seg.VirtualAddress);
                FdeR.Pos = R.Pos;
                const uint8_t Enc = It->FdeEnc;
                const uint64_t Begin = FdeR.Encoded(Enc, PtrSize);
                const uint64_t Range = FdeR.Encoded(static_cast<uint8_t>(Enc & PeFormatMask), PtrSize, false);
                // Range 0 marks a discarded FDE (linker --gc-sections leftovers).
                if (FdeR.Ok() && !(Enc & PeIndirect) && Range > 0 && Range < 0x4000000 && InFunctionCode(Info, Begin)) {
                    Out.Ranges.append({Begin, Begin + Range});
                }
            }
        }
        Off = Next;
    }
}

}

EhFrameInfo ParseEhFrame(const BinaryInfo& Info) {
    EhFrameInfo Out;
    for (const Segment& Seg : Info.Segments) {
        // Mach-O sections are named "<segment>/<section>".
        if (Seg.Name != ".eh_frame" && !Seg.Name.endsWith("/__eh_frame")) continue;
        if (Seg.Data.isEmpty()) continue;
        ParseSection(Info, Seg, Out);
    }
    std::sort(Out.Ranges.begin(), Out.Ranges.end(),
              [](const EhFrameRange& A, const EhFrameRange& B) { return A.Start < B.Start; });
    Out.Ranges.erase(std::unique(Out.Ranges.begin(), Out.Ranges.end(),
                                 [](const EhFrameRange& A, const EhFrameRange& B) { return A.Start == B.Start; }),
                     Out.Ranges.end());
    Out.Found = !Out.Ranges.isEmpty();
    return Out;
}

}
