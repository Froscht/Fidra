#include <fidra/ida_shim.h>
#include <fidra/hexrays_shim.h>
#include <fidra/ICore.h>

#include "AnalysisDatabase.h"

#include <mutex>
#include <unordered_map>
#include <vector>

namespace {

struct ShimState {
    Fidra::AnalysisDatabase* Db = nullptr;
    Fidra::ICore* Core = nullptr;
    std::mutex CacheLock;
    std::unordered_map<ea_t, std::unique_ptr<func_t>> FuncCache;
    std::vector<ea_t> FuncOrder;
    bool FuncOrderBuilt = false;
    std::unordered_map<ea_t, std::unique_ptr<segment_t>> SegCache;
    std::vector<ea_t> SegOrder;
    bool SegOrderBuilt = false;
};

ShimState& State() {
    static ShimState S;
    return S;
}

std::unique_ptr<func_t> BuildFunc(const Fidra::AnalyzedFunction& F) {
    auto Out = std::make_unique<func_t>();
    Out->start_ea = F.Start;
    Out->end_ea = F.End;
    Out->size = F.Size;
    Out->argsize = static_cast<uint32_t>(F.ArgCount * 8);
    Out->frsize = static_cast<uint32_t>(F.StackFrameSize);
    if (F.IsThunk) Out->flags |= FUNC_THUNK;
    if (F.IsNoReturn) Out->flags |= FUNC_NORET;
    return Out;
}

std::unique_ptr<segment_t> BuildSeg(const Fidra::Segment& S) {
    auto Out = std::make_unique<segment_t>();
    Out->start_ea = S.VirtualAddress;
    Out->end_ea = S.VirtualAddress + S.VirtualSize;
    Out->bitness = S.IsExecutable ? 2 : 1;
    switch (S.Type) {
        case Fidra::SegmentType::Code:   Out->type = SEG_CODE; break;
        case Fidra::SegmentType::Data:   Out->type = SEG_DATA; break;
        case Fidra::SegmentType::Bss:    Out->type = SEG_BSS;  break;
        case Fidra::SegmentType::Import:
        case Fidra::SegmentType::Export: Out->type = SEG_XTRN; break;
        default: Out->type = SEG_NORM;
    }
    if (S.IsReadable)   Out->perm |= 4;
    if (S.IsWritable)   Out->perm |= 2;
    if (S.IsExecutable) Out->perm |= 1;
    return Out;
}

template<typename T>
T ReadPrimitive(ea_t ea) {
    auto* Db = State().Db;
    if (!Db) return T{};
    QByteArray B = Db->ReadBytes(ea, sizeof(T));
    if (B.size() < static_cast<int>(sizeof(T))) return T{};
    T V;
    std::memcpy(&V, B.constData(), sizeof(T));
    return V;
}

}

namespace Fidra::IdaShim {

void Bind(AnalysisDatabase* Db, ICore* Core) {
    auto& S = State();
    std::lock_guard<std::mutex> Lock(S.CacheLock);
    S.Db = Db;
    S.Core = Core;
    S.FuncCache.clear();
    S.FuncOrder.clear();
    S.FuncOrderBuilt = false;
    S.SegCache.clear();
    S.SegOrder.clear();
    S.SegOrderBuilt = false;
}

AnalysisDatabase* CurrentDb() { return State().Db; }
ICore* CurrentCore() { return State().Core; }

void Clear() { Bind(nullptr, nullptr); }

}

// -------- func APIs --------

func_t* get_func(ea_t ea) {
    auto& S = State();
    auto* Db = S.Db;
    if (!Db) return nullptr;
    Fidra::AnalyzedFunction F = Db->GetFunctionContaining(ea);
    if (F.Start == 0 && F.End == 0) return nullptr;
    std::lock_guard<std::mutex> Lock(S.CacheLock);
    auto It = S.FuncCache.find(F.Start);
    if (It == S.FuncCache.end()) {
        auto Wrapper = BuildFunc(F);
        func_t* Raw = Wrapper.get();
        S.FuncCache.emplace(F.Start, std::move(Wrapper));
        return Raw;
    }
    return It->second.get();
}

size_t get_func_qty() {
    auto* Db = State().Db;
    return Db ? static_cast<size_t>(Db->FunctionCount()) : 0;
}

func_t* getn_func(size_t n) {
    auto& S = State();
    auto* Db = S.Db;
    if (!Db) return nullptr;
    {
        std::lock_guard<std::mutex> Lock(S.CacheLock);
        if (!S.FuncOrderBuilt) {
            S.FuncOrder.clear();
            for (const auto& F : Db->GetAllFunctions()) S.FuncOrder.push_back(F.Start);
            S.FuncOrderBuilt = true;
        }
        if (n >= S.FuncOrder.size()) return nullptr;
    }
    return get_func(S.FuncOrder[n]);
}

ea_t get_func_start(ea_t ea) {
    func_t* F = get_func(ea);
    return F ? F->start_ea : BADADDR;
}

ea_t get_func_end(ea_t ea) {
    func_t* F = get_func(ea);
    return F ? F->end_ea : BADADDR;
}

bool func_contains(func_t* pfn, ea_t ea) {
    return pfn && pfn->contains(ea);
}

// -------- Byte reads --------

ssize_t get_bytes(void* buf, size_t size, ea_t ea) {
    auto* Db = State().Db;
    if (!Db || !buf || size == 0) return 0;
    QByteArray B = Db->ReadBytes(ea, size);
    if (B.isEmpty()) return 0;
    size_t Copy = std::min(size, static_cast<size_t>(B.size()));
    std::memcpy(buf, B.constData(), Copy);
    return static_cast<ssize_t>(Copy);
}

uint8_t  get_byte(ea_t ea)  { return ReadPrimitive<uint8_t>(ea); }
uint16_t get_word(ea_t ea)  { return ReadPrimitive<uint16_t>(ea); }
uint32_t get_dword(ea_t ea) { return ReadPrimitive<uint32_t>(ea); }
uint64_t get_qword(ea_t ea) { return ReadPrimitive<uint64_t>(ea); }

ea_t get_ea(ea_t ea) {
    return inf_is_64bit() ? get_qword(ea) : static_cast<ea_t>(get_dword(ea));
}

flags_t get_flags(ea_t ea) {
    auto* Db = State().Db;
    if (!Db) return 0;
    switch (Db->GetItemType(ea)) {
        case Fidra::ItemType::Code:     return 0x00000600;
        case Fidra::ItemType::Function: return 0x00000600 | 0x10000000;
        case Fidra::ItemType::Data:     return 0x00000400;
        case Fidra::ItemType::String:
        case Fidra::ItemType::WideString: return 0x00000400 | 0x00050000;
        default: return 0;
    }
}

// -------- Name / comment --------

static std::string QToStd(const QString& S) { return S.toStdString(); }

std::string get_name(ea_t ea) {
    auto* Db = State().Db;
    return Db ? QToStd(Db->GetName(ea)) : std::string{};
}

std::string get_func_name(ea_t ea) {
    auto* Db = State().Db;
    if (!Db) return {};
    Fidra::AnalyzedFunction F = Db->GetFunctionContaining(ea);
    return QToStd(F.Name);
}

std::string get_true_name(ea_t ea)  { return get_name(ea); }
std::string get_short_name(ea_t ea) { return get_name(ea); }
std::string get_long_name(ea_t ea)  {
    auto* Db = State().Db;
    if (!Db) return {};
    Fidra::AnalyzedFunction F = Db->GetFunctionContaining(ea);
    return F.DemangledName.isEmpty() ? QToStd(F.Name) : QToStd(F.DemangledName);
}

bool set_name(ea_t ea, const char* name, int /*flags*/) {
    auto* Db = State().Db;
    if (!Db || !name) return false;
    Db->SetName(ea, QString::fromUtf8(name));
    return true;
}

std::string get_cmt(ea_t ea, bool /*repeatable*/) {
    auto* Db = State().Db;
    return Db ? QToStd(Db->GetComment(ea)) : std::string{};
}

bool set_cmt(ea_t ea, const char* comment, bool /*repeatable*/) {
    auto* Db = State().Db;
    if (!Db || !comment) return false;
    Db->SetComment(ea, QString::fromUtf8(comment));
    return true;
}

bool append_cmt(ea_t ea, const char* comment, bool repeatable) {
    auto* Db = State().Db;
    if (!Db || !comment) return false;
    QString Cur = Db->GetComment(ea);
    QString Add = QString::fromUtf8(comment);
    if (Cur.isEmpty()) return set_cmt(ea, comment, repeatable);
    Db->SetComment(ea, Cur + "\n" + Add);
    return true;
}

// -------- Segments --------

segment_t* getseg(ea_t ea) {
    auto& S = State();
    auto* Db = S.Db;
    if (!Db) return nullptr;
    auto Opt = Db->GetSegmentAt(ea);
    if (!Opt) return nullptr;
    std::lock_guard<std::mutex> Lock(S.CacheLock);
    auto Key = Opt->VirtualAddress;
    auto It = S.SegCache.find(Key);
    if (It == S.SegCache.end()) {
        auto Wrap = BuildSeg(*Opt);
        segment_t* Raw = Wrap.get();
        S.SegCache.emplace(Key, std::move(Wrap));
        return Raw;
    }
    return It->second.get();
}

size_t get_segm_qty() {
    auto* Db = State().Db;
    if (!Db) return 0;
    return static_cast<size_t>(Db->GetBinaryInfo().Segments.size());
}

segment_t* getnseg(int n) {
    auto& S = State();
    auto* Db = S.Db;
    if (!Db) return nullptr;
    auto Info = Db->GetBinaryInfo();
    if (n < 0 || n >= Info.Segments.size()) return nullptr;
    return getseg(Info.Segments[n].VirtualAddress);
}

segment_t* get_first_seg() { return getnseg(0); }

segment_t* get_next_seg(ea_t ea) {
    auto* Db = State().Db;
    if (!Db) return nullptr;
    auto Info = Db->GetBinaryInfo();
    for (int i = 0; i < Info.Segments.size(); ++i) {
        if (Info.Segments[i].VirtualAddress > ea) return getseg(Info.Segments[i].VirtualAddress);
    }
    return nullptr;
}

std::string get_segm_name(const segment_t* seg) {
    if (!seg) return {};
    auto* Db = State().Db;
    if (!Db) return {};
    for (const auto& S : Db->GetBinaryInfo().Segments) {
        if (S.VirtualAddress == seg->start_ea) return S.Name.toStdString();
    }
    return {};
}

uint32_t segtype(ea_t ea) {
    segment_t* Seg = getseg(ea);
    return Seg ? Seg->type : SEG_NORM;
}

// -------- Binary meta --------

int inf_get_app_bitness() {
    auto* Db = State().Db;
    if (!Db) return 64;
    return Db->GetBinaryInfo().Is64Bit ? 64 : 32;
}

bool inf_is_64bit() {
    auto* Db = State().Db;
    return Db ? Db->GetBinaryInfo().Is64Bit : true;
}

bool inf_is_dll() {
    auto* Db = State().Db;
    return Db ? Db->GetBinaryInfo().IsDll : false;
}

int inf_get_cc_id() { return CM_CC_UNKNOWN; }

uint32_t inf_get_database_change_count() { return 0; }

uint16_t inf_get_filetype() {
    auto* Db = State().Db;
    if (!Db) return f_BIN;
    const auto& Info = Db->GetBinaryInfo();
    QString P = Info.FilePath.toLower();
    if (P.endsWith(".exe") || P.endsWith(".dll") || P.endsWith(".sys")) return f_PE;
    if (P.endsWith(".dylib") || P.endsWith(".macho")) return f_MACHO;
    return f_ELF;
}

ea_t inf_get_max_ea() {
    auto* Db = State().Db;
    if (!Db) return BADADDR;
    const auto& Info = Db->GetBinaryInfo();
    return Info.ImageBase + Info.ImageSize;
}

ea_t inf_get_min_ea() {
    auto* Db = State().Db;
    return Db ? Db->GetBinaryInfo().ImageBase : BADADDR;
}

std::string inf_get_procname() {
    auto* Db = State().Db;
    if (!Db) return "metapc";
    switch (Db->GetBinaryInfo().Arch) {
        case Fidra::Architecture::X64:
        case Fidra::Architecture::X86:   return "metapc";
        case Fidra::Architecture::ARM:
        case Fidra::Architecture::ARM64: return "ARM";
        default: return "metapc";
    }
}

ea_t inf_get_start_ea() {
    auto* Db = State().Db;
    return Db ? Db->GetBinaryInfo().EntryPoint : BADADDR;
}

// -------- xrefblk_t --------

bool xrefblk_t::first_from(ea_t ea, int /*flags*/) {
    auto* Db = ::Fidra::IdaShim::CurrentDb();
    pending.clear();
    cursor = 0;
    anchor = ea;
    to_direction = false;
    if (!Db) return false;
    for (const auto& X : Db->GetXrefsFrom(ea)) {
        uint8_t T = 0;
        switch (X.Type) {
            case Fidra::XrefType::CodeCall:     T = fl_CN; break;
            case Fidra::XrefType::CodeJump:     T = fl_JN; break;
            case Fidra::XrefType::CodeCondJump: T = fl_JF; break;
            case Fidra::XrefType::DataRead:     T = dr_R; break;
            case Fidra::XrefType::DataWrite:    T = dr_W; break;
            case Fidra::XrefType::DataOffset:   T = dr_O; break;
        }
        pending.emplace_back(X.To, T);
    }
    if (pending.empty()) return false;
    from = ea;
    to = pending[0].first;
    type = pending[0].second;
    iscode = (type >= fl_CF) ? 1 : 0;
    return true;
}

bool xrefblk_t::next_from() {
    ++cursor;
    if (cursor >= pending.size()) return false;
    from = anchor;
    to = pending[cursor].first;
    type = pending[cursor].second;
    iscode = (type >= fl_CF) ? 1 : 0;
    return true;
}

bool xrefblk_t::first_to(ea_t ea, int /*flags*/) {
    auto* Db = ::Fidra::IdaShim::CurrentDb();
    pending.clear();
    cursor = 0;
    anchor = ea;
    to_direction = true;
    if (!Db) return false;
    for (const auto& X : Db->GetXrefsTo(ea)) {
        uint8_t T = 0;
        switch (X.Type) {
            case Fidra::XrefType::CodeCall:     T = fl_CN; break;
            case Fidra::XrefType::CodeJump:     T = fl_JN; break;
            case Fidra::XrefType::CodeCondJump: T = fl_JF; break;
            case Fidra::XrefType::DataRead:     T = dr_R; break;
            case Fidra::XrefType::DataWrite:    T = dr_W; break;
            case Fidra::XrefType::DataOffset:   T = dr_O; break;
        }
        pending.emplace_back(X.From, T);
    }
    if (pending.empty()) return false;
    to = ea;
    from = pending[0].first;
    type = pending[0].second;
    iscode = (type >= fl_CF) ? 1 : 0;
    return true;
}

bool xrefblk_t::next_to() {
    ++cursor;
    if (cursor >= pending.size()) return false;
    to = anchor;
    from = pending[cursor].first;
    type = pending[cursor].second;
    iscode = (type >= fl_CF) ? 1 : 0;
    return true;
}

// -------- Hexrays tier-2 stubs (compile only) --------

cfuncptr_t decompile(func_t* pfn, hexrays_failure_t* hf, int /*flags*/) {
    if (hf) {
        hf->code = -1;
        hf->errea = pfn ? pfn->start_ea : BADADDR;
        hf->desc = "Fidra: hexrays shim — no decompiler bound";
    }
    return nullptr;
}

cfuncptr_t decompile(ea_t ea, hexrays_failure_t* hf, int flags) {
    return decompile(get_func(ea), hf, flags);
}
