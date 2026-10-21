#include "GoPclntab.h"

#include <cstring>

namespace Fidra {

namespace {

constexpr uint32_t MagicGo12 = 0xfffffffb;
constexpr uint32_t MagicGo116 = 0xfffffffa;
constexpr uint32_t MagicGo118 = 0xfffffff0;
constexpr uint32_t MagicGo120 = 0xfffffff1;

class TableReader {
public:
    TableReader(const QByteArray& Data, size_t Base, int PtrSize)
        : Bytes(reinterpret_cast<const uint8_t*>(Data.constData())), Size(Data.size()), Base(Base), PtrSize(PtrSize) {}

    bool Has(size_t Off, size_t Len) const { return Base + Off + Len <= Size && Base + Off + Len >= Base + Off; }

    uint32_t U32(size_t Off) const {
        uint32_t V = 0;
        if (Has(Off, 4)) std::memcpy(&V, Bytes + Base + Off, 4);
        return V;
    }

    uint64_t Ptr(size_t Off) const {
        if (PtrSize == 4) return U32(Off);
        uint64_t V = 0;
        if (Has(Off, 8)) std::memcpy(&V, Bytes + Base + Off, 8);
        return V;
    }

    QString CString(size_t Off) const {
        if (!Has(Off, 1)) return {};
        const char* Start = reinterpret_cast<const char*>(Bytes + Base + Off);
        size_t Max = Size - (Base + Off);
        size_t Len = 0;
        while (Len < Max && Len < 4096 && Start[Len] != '\0') ++Len;
        return QString::fromUtf8(Start, static_cast<qsizetype>(Len));
    }

    int PtrSize;

private:
    const uint8_t* Bytes;
    size_t Size;
    size_t Base;
};

bool InCode(const BinaryInfo& Info, Address Addr) {
    for (const Segment& Seg : Info.Segments) {
        if ((Seg.Type == SegmentType::Code || Seg.IsExecutable) &&
            Addr >= Seg.VirtualAddress && Addr < Seg.VirtualAddress + Seg.VirtualSize) {
            return true;
        }
    }
    return false;
}

Address TextStartFallback(const BinaryInfo& Info) {
    for (const Segment& Seg : Info.Segments) {
        if (Seg.Name == ".text" || Seg.Name == "__text") return Seg.VirtualAddress;
    }
    for (const Segment& Seg : Info.Segments) {
        if (Seg.Type == SegmentType::Code || Seg.IsExecutable) return Seg.VirtualAddress;
    }
    return 0;
}

// Parses a candidate table at Base inside Data. Returns false unless the
// table is self-consistent (sorted entries inside code, sane counts).
bool ParseAt(const BinaryInfo& Info, const QByteArray& Data, size_t Base, GoPclntabInfo& Out) {
    if (Base + 16 > static_cast<size_t>(Data.size())) return false;
    const uint8_t* H = reinterpret_cast<const uint8_t*>(Data.constData()) + Base;
    uint32_t Magic;
    std::memcpy(&Magic, H, 4);
    if (Magic != MagicGo12 && Magic != MagicGo116 && Magic != MagicGo118 && Magic != MagicGo120) return false;
    if (H[4] != 0 || H[5] != 0) return false;
    if (H[6] != 1 && H[6] != 2 && H[6] != 4) return false;
    if (H[7] != 4 && H[7] != 8) return false;

    TableReader R(Data, Base, H[7]);
    const int P = R.PtrSize;
    const uint64_t NFunc = R.Ptr(8);
    if (NFunc == 0 || NFunc > 2'000'000) return false;

    QList<GoFunctionEntry> Funcs;
    Funcs.reserve(static_cast<qsizetype>(NFunc));

    if (Magic == MagicGo118 || Magic == MagicGo120) {
        uint64_t TextStart = R.Ptr(8 + 2 * P);
        const uint64_t FuncNameOff = R.Ptr(8 + 3 * P);
        const uint64_t PclnOff = R.Ptr(8 + 7 * P);
        if (TextStart == 0) TextStart = TextStartFallback(Info);
        for (uint64_t I = 0; I < NFunc; ++I) {
            const size_t Ent = PclnOff + I * 8;
            if (!R.Has(Ent, 8)) return false;
            const uint32_t EntryOff = R.U32(Ent);
            const uint32_t FuncOff = R.U32(Ent + 4);
            const int32_t NameOff = static_cast<int32_t>(R.U32(PclnOff + FuncOff + 4));
            Funcs.append({TextStart + EntryOff, R.CString(FuncNameOff + static_cast<uint32_t>(NameOff))});
        }
        Out.TextEnd = TextStart + R.U32(PclnOff + NFunc * 8);
        Out.Version = Magic == MagicGo120 ? "1.20+" : "1.18";
    } else if (Magic == MagicGo116) {
        const uint64_t FuncNameOff = R.Ptr(8 + 2 * P);
        const uint64_t PclnOff = R.Ptr(8 + 6 * P);
        for (uint64_t I = 0; I < NFunc; ++I) {
            const size_t Ent = PclnOff + I * 2 * P;
            if (!R.Has(Ent, 2 * P)) return false;
            const uint64_t Entry = R.Ptr(Ent);
            const uint64_t FuncOff = R.Ptr(Ent + P);
            const int32_t NameOff = static_cast<int32_t>(R.U32(PclnOff + FuncOff + P));
            Funcs.append({Entry, R.CString(FuncNameOff + static_cast<uint32_t>(NameOff))});
        }
        Out.TextEnd = R.Ptr(PclnOff + NFunc * 2 * P);
        Out.Version = "1.16";
    } else {
        const size_t FuncTab = 8 + P;
        for (uint64_t I = 0; I < NFunc; ++I) {
            const size_t Ent = FuncTab + I * 2 * P;
            if (!R.Has(Ent, 2 * P)) return false;
            const uint64_t Entry = R.Ptr(Ent);
            const uint64_t FuncOff = R.Ptr(Ent + P);
            const int32_t NameOff = static_cast<int32_t>(R.U32(FuncOff + P));
            Funcs.append({Entry, R.CString(static_cast<uint32_t>(NameOff))});
        }
        Out.TextEnd = R.Ptr(FuncTab + NFunc * 2 * P);
        Out.Version = "1.2";
    }

    // Consistency: entries ascending and in code, names mostly present.
    int Named = 0;
    for (int I = 0; I < Funcs.size(); ++I) {
        if (!InCode(Info, Funcs[I].Entry)) return false;
        if (I > 0 && Funcs[I].Entry < Funcs[I - 1].Entry) return false;
        if (!Funcs[I].Name.isEmpty()) ++Named;
    }
    if (Named < Funcs.size() / 2) return false;

    if (Out.TextEnd <= Funcs.last().Entry) Out.TextEnd = Funcs.last().Entry + 1;
    Out.Found = true;
    Out.Functions = Funcs;
    return true;
}

}

GoPclntabInfo ParseGoPclntab(const BinaryInfo& Info) {
    GoPclntabInfo Out;

    // Named section first (ELF .gopclntab, Mach-O __gopclntab).
    for (const Segment& Seg : Info.Segments) {
        if (Seg.Name == ".gopclntab" || Seg.Name == "__gopclntab") {
            if (ParseAt(Info, Seg.Data, 0, Out)) return Out;
        }
    }

    // PE and section-less binaries: scan non-code data for the header.
    for (const Segment& Seg : Info.Segments) {
        if (Seg.Type == SegmentType::Code || Seg.IsExecutable || Seg.Data.size() < 64) continue;
        const uint8_t* D = reinterpret_cast<const uint8_t*>(Seg.Data.constData());
        const size_t N = static_cast<size_t>(Seg.Data.size());
        for (size_t Off = 0; Off + 16 <= N; Off += 4) {
            if (D[Off + 1] != 0xff || D[Off + 2] != 0xff || D[Off + 3] != 0xff) continue;
            if (D[Off] != 0xfb && D[Off] != 0xfa && D[Off] != 0xf0 && D[Off] != 0xf1) continue;
            if (ParseAt(Info, Seg.Data, Off, Out)) return Out;
        }
    }
    return Out;
}

}
