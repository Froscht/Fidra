#include <fidra/ida_shim.h>
#include <fidra/hexrays_shim.h>
#include <fidra/ICore.h>

#include "AnalysisDatabase.h"

#include <mutex>
#include <unordered_map>
#include <vector>
#include <set>
#include <map>
#include <algorithm>

#include <QString>

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

// -------- qstring-form name/segment/comment accessors --------

static ssize_t WriteQ(qstring* out, const std::string& s) {
    if (!out) return 0;
    *out = s;
    return static_cast<ssize_t>(s.size());
}

ssize_t get_func_name(qstring* out, ea_t ea) {
    return WriteQ(out, get_func_name(ea));
}
ssize_t get_name(qstring* out, ea_t ea) {
    return WriteQ(out, get_name(ea));
}
ssize_t get_short_name(qstring* out, ea_t ea) {
    return WriteQ(out, get_short_name(ea));
}
ssize_t get_long_name(qstring* out, ea_t ea) {
    return WriteQ(out, get_long_name(ea));
}
ssize_t get_ea_name(qstring* out, ea_t ea, int /*flags*/) {
    return WriteQ(out, get_name(ea));
}
ssize_t get_cmt(qstring* out, ea_t ea, bool repeatable) {
    return WriteQ(out, get_cmt(ea, repeatable));
}
ssize_t get_segm_name(qstring* out, const segment_t* seg) {
    return WriteQ(out, get_segm_name(seg));
}
ssize_t inf_get_procname(qstring* out) {
    return WriteQ(out, inf_get_procname());
}

// -------- get_name_ea (reverse lookup) --------

ea_t get_name_ea(ea_t /*from*/, const char* name) {
    if (!name) return BADADDR;
    auto* Db = State().Db;
    if (!Db) return BADADDR;
    QString Wanted = QString::fromUtf8(name);
    ea_t Found = BADADDR;
    for (auto It = Db->GetAllNames().constBegin(); It != Db->GetAllNames().constEnd(); ++It) {
        if (It.value() == Wanted) { Found = It.key(); break; }
    }
    return Found;
}

// -------- flags64_t alias --------

flags64_t get_flags64(ea_t ea) { return static_cast<flags64_t>(get_flags(ea)); }

// -------- Instruction decoding --------

int decode_insn(insn_t* out, ea_t ea) {
    if (!out) return 0;
    auto* Db = State().Db;
    if (!Db) return 0;
    if (!Db->HasInstruction(ea)) return 0;
    auto I = Db->GetInstruction(ea);
    out->ea = ea;
    out->size = I.Size;
    out->itype = 0;
    if (I.BranchTarget != 0) {
        out->ops[0].type = o_near;
        out->ops[0].addr = I.BranchTarget;
    }
    return I.Size;
}

bool is_call_insn(const insn_t& insn) {
    auto* Db = State().Db;
    if (!Db) return false;
    if (!Db->HasInstruction(insn.ea)) return false;
    return Db->GetInstruction(insn.ea).IsCall;
}

bool is_ret_insn(const insn_t& insn) {
    auto* Db = State().Db;
    if (!Db) return false;
    if (!Db->HasInstruction(insn.ea)) return false;
    return Db->GetInstruction(insn.ea).IsRet;
}

bool is_indirect_jump_insn(const insn_t& insn) {
    auto* Db = State().Db;
    if (!Db) return false;
    if (!Db->HasInstruction(insn.ea)) return false;
    return Db->GetInstruction(insn.ea).IsIndirectJump;
}

ea_t next_head(ea_t ea, ea_t /*maxea*/) {
    auto* Db = State().Db;
    if (!Db) return BADADDR;
    if (!Db->HasInstruction(ea)) return BADADDR;
    return ea + Db->GetInstruction(ea).Size;
}

ea_t prev_head(ea_t ea, ea_t /*minea*/) {
    if (ea == 0) return BADADDR;
    return ea - 1;  // very approximate
}

// -------- Imports / exports (subset) --------

uint get_import_module_qty() {
    auto* Db = State().Db;
    if (!Db) return 0;
    std::set<QString> Dlls;
    for (const auto& I : Db->GetBinaryInfo().Imports) Dlls.insert(I.DllName);
    return static_cast<uint>(Dlls.size());
}

bool get_import_module_name(qstring* out, int idx) {
    if (!out) return false;
    auto* Db = State().Db;
    if (!Db) return false;
    std::set<QString> Dlls;
    for (const auto& I : Db->GetBinaryInfo().Imports) Dlls.insert(I.DllName);
    int i = 0;
    for (const auto& D : Dlls) {
        if (i == idx) { *out = D.toStdString(); return true; }
        ++i;
    }
    return false;
}

int enum_import_names(int idx, import_enum_cb_t cb, void* ctx) {
    if (!cb) return 0;
    auto* Db = State().Db;
    if (!Db) return 0;
    std::set<QString> Dlls;
    for (const auto& I : Db->GetBinaryInfo().Imports) Dlls.insert(I.DllName);
    QString Target;
    int i = 0;
    for (const auto& D : Dlls) {
        if (i == idx) { Target = D; break; }
        ++i;
    }
    if (Target.isEmpty()) return 0;
    int Called = 0;
    for (const auto& I : Db->GetBinaryInfo().Imports) {
        if (I.DllName != Target) continue;
        auto NameStd = I.FuncName.toStdString();
        int Rc = cb(I.IatAddress, NameStd.c_str(), I.Ordinal, ctx);
        ++Called;
        if (Rc == 0) break;
    }
    return Called;
}

size_t get_entry_qty() {
    auto* Db = State().Db;
    return Db ? static_cast<size_t>(Db->GetBinaryInfo().Exports.size()) : 0;
}

ea_t get_entry(uint64_t ordinal) {
    auto* Db = State().Db;
    if (!Db) return BADADDR;
    for (const auto& E : Db->GetBinaryInfo().Exports) {
        if (E.Ordinal == ordinal) return E.Addr;
    }
    return BADADDR;
}

uint64_t get_entry_ordinal(size_t idx) {
    auto* Db = State().Db;
    if (!Db) return 0;
    const auto& Exp = Db->GetBinaryInfo().Exports;
    if (idx >= static_cast<size_t>(Exp.size())) return 0;
    return Exp[idx].Ordinal;
}

ssize_t get_entry_name(qstring* out, uint64_t ord) {
    if (!out) return 0;
    auto* Db = State().Db;
    if (!Db) return 0;
    for (const auto& E : Db->GetBinaryInfo().Exports) {
        if (E.Ordinal == ord) { *out = E.Name.toStdString(); return E.Name.size(); }
    }
    return 0;
}

// -------- Binary hash --------

bool retrieve_input_file_md5(uchar out[16]) {
    if (!out) return false;
    std::memset(out, 0, 16);
    auto* Db = State().Db;
    if (!Db) return false;
    // Fidra does not persist a computed MD5 yet; derive a stable pseudo-hash
    // from the file path so callers get deterministic-but-fake identity.
    QString P = Db->GetBinaryInfo().FilePath;
    auto B = P.toUtf8();
    for (int i = 0; i < B.size(); ++i) out[i % 16] ^= static_cast<uchar>(B[i]);
    return true;
}

bool retrieve_input_file_sha256(uchar out[32]) {
    if (!out) return false;
    std::memset(out, 0, 32);
    auto* Db = State().Db;
    if (!Db) return false;
    QString P = Db->GetBinaryInfo().FilePath;
    auto B = P.toUtf8();
    for (int i = 0; i < B.size(); ++i) out[i % 32] ^= static_cast<uchar>(B[i]);
    return true;
}

qstring get_input_file_path() {
    auto* Db = State().Db;
    return Db ? qstring(Db->GetBinaryInfo().FilePath.toStdString()) : qstring();
}

qstring get_root_filename() {
    auto* Db = State().Db;
    return Db ? qstring(Db->GetBinaryInfo().FileName.toStdString()) : qstring();
}

// -------- Netnode (in-memory KV keyed by node name) --------

namespace {
struct NetnodeStore {
    std::mutex Mtx;
    struct Node {
        std::map<uint64_t, std::vector<uint8_t>> Blobs;
        std::map<uint64_t, uint32_t> Alt;
        std::map<uint64_t, std::vector<uint8_t>> Sup;
        std::map<std::string, std::vector<uint8_t>> Hash;
    };
    std::unordered_map<std::string, Node> Nodes;

    Node& NodeFor(const std::string& Name) { return Nodes[Name]; }
};
NetnodeStore& NNS() { static NetnodeStore S; return S; }
}

ssize_t netnode::supval(nodeidx_t alt, void* buf, size_t maxsize, char tag) const {
    if (!buf || maxsize == 0) return -1;
    uint64_t Key = (uint64_t(tag) << 32) | alt;
    auto& S = NNS();
    std::lock_guard<std::mutex> Lock(S.Mtx);
    auto& N = S.Nodes[node_name];
    auto It = N.Sup.find(Key);
    if (It == N.Sup.end()) return -1;
    size_t Copy = std::min(maxsize, It->second.size());
    std::memcpy(buf, It->second.data(), Copy);
    return static_cast<ssize_t>(Copy);
}

bool netnode::supset(nodeidx_t alt, const void* value, size_t length, char tag) {
    if (!value) return false;
    uint64_t Key = (uint64_t(tag) << 32) | alt;
    auto& S = NNS();
    std::lock_guard<std::mutex> Lock(S.Mtx);
    auto& V = S.Nodes[node_name].Sup[Key];
    V.assign(reinterpret_cast<const uint8_t*>(value),
             reinterpret_cast<const uint8_t*>(value) + (length ? length : std::strlen(reinterpret_cast<const char*>(value))));
    return true;
}

bool netnode::supdel(nodeidx_t alt, char tag) {
    uint64_t Key = (uint64_t(tag) << 32) | alt;
    auto& S = NNS();
    std::lock_guard<std::mutex> Lock(S.Mtx);
    return S.Nodes[node_name].Sup.erase(Key) > 0;
}

uint32_t netnode::altval(nodeidx_t alt, char tag) const {
    uint64_t Key = (uint64_t(tag) << 32) | alt;
    auto& S = NNS();
    std::lock_guard<std::mutex> Lock(S.Mtx);
    auto& N = S.Nodes[node_name];
    auto It = N.Alt.find(Key);
    return It == N.Alt.end() ? 0 : It->second;
}

bool netnode::altset(nodeidx_t alt, uint32_t value, char tag) {
    uint64_t Key = (uint64_t(tag) << 32) | alt;
    auto& S = NNS();
    std::lock_guard<std::mutex> Lock(S.Mtx);
    S.Nodes[node_name].Alt[Key] = value;
    return true;
}

bool netnode::altdel(nodeidx_t alt, char tag) {
    uint64_t Key = (uint64_t(tag) << 32) | alt;
    auto& S = NNS();
    std::lock_guard<std::mutex> Lock(S.Mtx);
    return S.Nodes[node_name].Alt.erase(Key) > 0;
}

ssize_t netnode::getblob(void* out, nodeidx_t start, char tag) const {
    if (!out) return -1;
    uint64_t Key = (uint64_t(tag) << 32) | start;
    auto& S = NNS();
    std::lock_guard<std::mutex> Lock(S.Mtx);
    auto& N = S.Nodes[node_name];
    auto It = N.Blobs.find(Key);
    if (It == N.Blobs.end()) return -1;
    std::memcpy(out, It->second.data(), It->second.size());
    return static_cast<ssize_t>(It->second.size());
}

bool netnode::setblob(const void* data, size_t size, nodeidx_t start, char tag) {
    if (!data) return false;
    uint64_t Key = (uint64_t(tag) << 32) | start;
    auto& S = NNS();
    std::lock_guard<std::mutex> Lock(S.Mtx);
    auto& V = S.Nodes[node_name].Blobs[Key];
    V.assign(reinterpret_cast<const uint8_t*>(data),
             reinterpret_cast<const uint8_t*>(data) + size);
    return true;
}

bool netnode::delblob(nodeidx_t start, char tag) {
    uint64_t Key = (uint64_t(tag) << 32) | start;
    auto& S = NNS();
    std::lock_guard<std::mutex> Lock(S.Mtx);
    return S.Nodes[node_name].Blobs.erase(Key) > 0;
}

ssize_t netnode::hashval(const char* idx, void* buf, size_t maxsize, char tag) const {
    if (!idx || !buf) return -1;
    std::string Key = std::string(1, tag) + idx;
    auto& S = NNS();
    std::lock_guard<std::mutex> Lock(S.Mtx);
    auto& N = S.Nodes[node_name];
    auto It = N.Hash.find(Key);
    if (It == N.Hash.end()) return -1;
    size_t Copy = std::min(maxsize, It->second.size());
    std::memcpy(buf, It->second.data(), Copy);
    return static_cast<ssize_t>(Copy);
}

bool netnode::hashset(const char* idx, const void* value, size_t length, char tag) {
    if (!idx || !value) return false;
    std::string Key = std::string(1, tag) + idx;
    auto& S = NNS();
    std::lock_guard<std::mutex> Lock(S.Mtx);
    auto& V = S.Nodes[node_name].Hash[Key];
    V.assign(reinterpret_cast<const uint8_t*>(value),
             reinterpret_cast<const uint8_t*>(value) + (length ? length : std::strlen(reinterpret_cast<const char*>(value))));
    return true;
}

bool netnode::hashdel(const char* idx, char tag) {
    if (!idx) return false;
    std::string Key = std::string(1, tag) + idx;
    auto& S = NNS();
    std::lock_guard<std::mutex> Lock(S.Mtx);
    return S.Nodes[node_name].Hash.erase(Key) > 0;
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

// -------- nalt.hpp / entry.hpp deferred impls --------

#include <fidra/ida-compat/nalt.hpp>
#include <fidra/ida-compat/entry.hpp>

ea_t get_imagebase() {
    auto* Db = Fidra::IdaShim::CurrentDb();
    return Db ? Db->GetBinaryInfo().ImageBase : 0;
}

int get_import_module_qty() {
    auto* Db = Fidra::IdaShim::CurrentDb();
    return Db ? Db->GetBinaryInfo().Imports.size() : 0;
}

size_t get_entry_qty() {
    auto* Db = Fidra::IdaShim::CurrentDb();
    return Db ? static_cast<size_t>(Db->GetBinaryInfo().Exports.size()) : 0;
}

uval_t get_entry_ordinal(size_t idx) {
    auto* Db = Fidra::IdaShim::CurrentDb();
    if (!Db) return 0;
    const auto& E = Db->GetBinaryInfo().Exports;
    return idx < static_cast<size_t>(E.size()) ? E[idx].Ordinal : 0;
}
