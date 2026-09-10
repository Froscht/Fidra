#pragma once

// Fidra IDA-SDK compatibility shim.
// Provides the subset of IDA Pro C++ SDK types + free functions used by ported
// AiDAPrivate modules (vuln, emulation, graphrag, multibinary). All primitives
// are backed by Fidra::AnalysisDatabase — no runtime IDA dependency.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>

#include <fidra/Types.h>

namespace Fidra {
class AnalysisDatabase;
class ICore;
}

using ea_t = uint64_t;
using asize_t = uint64_t;
using sval_t = int64_t;
using uval_t = uint64_t;
using flags_t = uint32_t;
using tid_t = uint64_t;
using sel_t = uint64_t;
using nodeidx_t = uint32_t;

constexpr ea_t BADADDR = static_cast<ea_t>(-1);
constexpr sel_t BADSEL = static_cast<sel_t>(-1);
constexpr nodeidx_t BADNODE = static_cast<nodeidx_t>(-1);

// Segment class flags (subset)
constexpr uint32_t SEG_NORM  = 0;
constexpr uint32_t SEG_CODE  = 2;
constexpr uint32_t SEG_DATA  = 3;
constexpr uint32_t SEG_BSS   = 9;
constexpr uint32_t SEG_XTRN  = 1;

// func_t.flags subset
constexpr uint32_t FUNC_NORET      = 0x00000001;
constexpr uint32_t FUNC_FAR        = 0x00000002;
constexpr uint32_t FUNC_LIB        = 0x00000004;
constexpr uint32_t FUNC_STATICDEF  = 0x00000008;
constexpr uint32_t FUNC_FRAME      = 0x00000010;
constexpr uint32_t FUNC_USERFAR    = 0x00000020;
constexpr uint32_t FUNC_HIDDEN     = 0x00000040;
constexpr uint32_t FUNC_THUNK      = 0x00000080;
constexpr uint32_t FUNC_BOTTOMBP   = 0x00000100;
constexpr uint32_t FUNC_TAIL       = 0x00008000;

struct func_t {
    ea_t start_ea = 0;
    ea_t end_ea = 0;
    asize_t size = 0;
    uint32_t flags = 0;
    uint32_t argsize = 0;
    uint32_t frsize = 0;
    uint16_t frregs = 0;
    int32_t regvarqty = 0;
    int32_t regargqty = 0;
    int32_t pntqty = 0;

    bool does_return() const { return (flags & FUNC_NORET) == 0; }
    bool is_far() const { return (flags & FUNC_FAR) != 0; }
    bool is_lib() const { return (flags & FUNC_LIB) != 0; }
    bool is_thunk() const { return (flags & FUNC_THUNK) != 0; }
    bool empty() const { return start_ea == BADADDR || start_ea == end_ea; }
    bool contains(ea_t ea) const { return ea >= start_ea && ea < end_ea; }
};

struct segment_t {
    ea_t start_ea = 0;
    ea_t end_ea = 0;
    sel_t sel = 0;
    uint32_t type = 0;
    uint32_t align = 0;
    uint32_t comb = 0;
    uint32_t perm = 0;
    uint32_t bitness = 0;
    uint32_t flags = 0;
    tid_t defsr[16]{};

    bool contains(ea_t ea) const { return ea >= start_ea && ea < end_ea; }
    asize_t size() const { return end_ea - start_ea; }
};

// Reference (xref) class type
enum cref_t {
    fl_U   = 0,
    fl_CF  = 16,
    fl_CN  = 17,
    fl_JF  = 18,
    fl_JN  = 19,
    fl_F   = 21,
};
enum dref_t {
    dr_U = 0,
    dr_O = 1,
    dr_W = 2,
    dr_R = 3,
    dr_T = 4,
    dr_I = 5,
};

struct xrefblk_t {
    ea_t from = 0;
    ea_t to = 0;
    uint8_t iscode = 0;
    uint8_t type = 0;
    uint8_t user = 0;

    bool first_from(ea_t ea, int flags = 0);
    bool next_from();
    bool first_to(ea_t ea, int flags = 0);
    bool next_to();

private:
    std::vector<std::pair<ea_t, uint8_t>> pending;
    size_t cursor = 0;
    ea_t anchor = 0;
    bool to_direction = false;
};

// -------------- Fidra binding surface --------------

namespace Fidra::IdaShim {
    void Bind(AnalysisDatabase* Db, ICore* Core = nullptr);
    AnalysisDatabase* CurrentDb();
    ICore* CurrentCore();
    void Clear();
}

// Forward declaration of qstring (definition later in file).
class qstring {
public:
    qstring() = default;
    qstring(const char* s) : Str(s ? s : "") {}
    qstring(const std::string& s) : Str(s) {}
    const char* c_str() const { return Str.c_str(); }
    size_t length() const { return Str.size(); }
    size_t size() const { return Str.size(); }
    bool empty() const { return Str.empty(); }
    qstring& operator+=(const char* s) { Str += s; return *this; }
    qstring& operator+=(const qstring& o) { Str += o.Str; return *this; }
    operator const char*() const { return Str.c_str(); }
    operator std::string() const { return Str; }
    std::string Str;
};

// -------------- Address / func APIs --------------

func_t* get_func(ea_t ea);
func_t* getn_func(size_t n);
size_t get_func_qty();
ea_t get_func_start(ea_t ea);
ea_t get_func_end(ea_t ea);
bool func_contains(func_t* pfn, ea_t ea);

// -------------- Byte / word / dword / qword reads --------------

ssize_t get_bytes(void* buf, size_t size, ea_t ea);
uint8_t get_byte(ea_t ea);
uint16_t get_word(ea_t ea);
uint32_t get_dword(ea_t ea);
uint64_t get_qword(ea_t ea);
ea_t get_ea(ea_t ea);
flags_t get_flags(ea_t ea);

// -------------- Name / comment APIs --------------

std::string get_name(ea_t ea);
std::string get_func_name(ea_t ea);
std::string get_true_name(ea_t ea);
std::string get_short_name(ea_t ea);
std::string get_long_name(ea_t ea);
bool set_name(ea_t ea, const char* name, int flags = 0);

// Out-parameter form used in some code paths
inline ssize_t get_name(qstring* out, ea_t ea) {
    if (!out) return 0;
    out->Str = get_name(ea);
    return static_cast<ssize_t>(out->Str.size());
}
inline ssize_t get_ea_name(qstring* out, ea_t ea, int /*flags*/ = 0) {
    return get_name(out, ea);
}
inline ssize_t get_func_name(qstring* out, ea_t ea) {
    if (!out) return 0;
    out->Str = get_func_name(ea);
    return static_cast<ssize_t>(out->Str.size());
}

std::string get_cmt(ea_t ea, bool repeatable = false);
bool set_cmt(ea_t ea, const char* comment, bool repeatable = false);
bool append_cmt(ea_t ea, const char* comment, bool repeatable = false);

// -------------- Segment APIs --------------

segment_t* getseg(ea_t ea);
segment_t* get_first_seg();
segment_t* get_next_seg(ea_t ea);
size_t get_segm_qty();
segment_t* getnseg(int n);
std::string get_segm_name(const segment_t* seg);
uint32_t segtype(ea_t ea);

// -------------- Binary meta (inf_get_*) --------------

int inf_get_app_bitness();
int inf_get_cc_id();
uint32_t inf_get_database_change_count();
uint16_t inf_get_filetype();
ea_t inf_get_max_ea();
ea_t inf_get_min_ea();
std::string inf_get_procname();
ea_t inf_get_start_ea();
bool inf_is_64bit();
bool inf_is_dll();

// filetype constants (subset of ida.hpp f_*)
constexpr uint16_t f_PE     = 11;
constexpr uint16_t f_ELF    = 18;
constexpr uint16_t f_MACHO  = 25;
constexpr uint16_t f_BIN    = 0;

// Calling convention constants (cm_t subset)
constexpr uint8_t CM_CC_UNKNOWN  = 0x00;
constexpr uint8_t CM_CC_CDECL    = 0x30;
constexpr uint8_t CM_CC_STDCALL  = 0x50;
constexpr uint8_t CM_CC_FASTCALL = 0x40;
constexpr uint8_t CM_CC_THISCALL = 0x60;
constexpr uint8_t CM_CC_MANUAL   = 0x20;

// MSVC-specific numeric parse aliases used in vuln code
#ifndef _MSC_VER
inline unsigned long long _strtoui64(const char* str, char** endptr, int base) {
    return std::strtoull(str, endptr, base);
}
inline long long _strtoi64(const char* str, char** endptr, int base) {
    return std::strtoll(str, endptr, base);
}
#endif

// ---------- IDA extras for vuln port (stubs) ----------

// qstring defined earlier in file.

constexpr size_t QMAXPATH = 512;
constexpr int PATH_TYPE_IDB = 0;
constexpr int PATH_TYPE_ID0 = 1;
constexpr int PATH_TYPE_CMD = 2;

// Segment permissions (bit flags)
constexpr uint32_t SEGPERM_READ  = 4;
constexpr uint32_t SEGPERM_WRITE = 2;
constexpr uint32_t SEGPERM_EXEC  = 1;

// Instruction decoding — minimal insn_t/op_t shape used by vuln iteration loops
constexpr int UA_MAXOP = 8;

enum optype_t {
    o_void  = 0,
    o_reg   = 1,
    o_mem   = 2,
    o_phrase= 3,
    o_displ = 4,
    o_imm   = 5,
    o_far   = 6,
    o_near  = 7,
    o_idpspec0 = 8,
};

struct op_t {
    optype_t type = o_void;
    uint8_t  n = 0;
    uint8_t  dtype = 0;
    uint16_t reg = 0;
    uint32_t flags = 0;
    int64_t  value = 0;
    ea_t     addr = 0;
    int64_t  specval = 0;
    uint8_t  specflag1 = 0;
    uint8_t  specflag2 = 0;
    uint8_t  specflag3 = 0;
    uint8_t  specflag4 = 0;
};

struct insn_t {
    ea_t ea = 0;
    uint16_t itype = 0;
    uint8_t  size = 0;
    uint8_t  flags = 0;
    op_t     ops[UA_MAXOP];
    op_t&       Op1() { return ops[0]; }
    const op_t& Op1() const { return ops[0]; }
    op_t&       Op2() { return ops[1]; }
    const op_t& Op2() const { return ops[1]; }
};

inline int decode_insn(insn_t* /*out*/, ea_t /*ea*/) { return 0; }
inline int print_insn_mnem(qstring* /*out*/, ea_t /*ea*/) { return 0; }
inline int get_predef_insn_cmt(qstring* /*out*/, const insn_t& /*ins*/) { return 0; }

// Control flow graph types (qflow_chart_t is IDA's basic-block flowchart)
struct qbasic_block_t {
    ea_t start_ea = 0;
    ea_t end_ea = 0;
    std::vector<int> succ;
    std::vector<int> pred;
    size_t size() const { return end_ea - start_ea; }
};

enum { FC_PREDS = 1, FC_APPND = 2, FC_NOEXT = 4, FC_CALL_ENDS = 8 };

struct qflow_chart_t {
    qstring title;
    func_t* pfn = nullptr;
    ea_t bounds_start = 0;
    ea_t bounds_end = 0;
    int flags = 0;
    std::vector<qbasic_block_t> blocks;
    qflow_chart_t() = default;
    qflow_chart_t(const char* /*t*/, func_t* p, ea_t s, ea_t e, int f)
        : pfn(p), bounds_start(s), bounds_end(e), flags(f) {}
    void create(const char* /*t*/, func_t* p, ea_t s, ea_t e, int f) {
        pfn = p; bounds_start = s; bounds_end = e; flags = f;
    }
    size_t size() const { return blocks.size(); }
    const qbasic_block_t& operator[](size_t i) const { return blocks[i]; }
    qbasic_block_t& operator[](size_t i) { return blocks[i]; }
    int nsucc(int /*n*/) const { return 0; }
    int npred(int /*n*/) const { return 0; }
    int succ(int /*n*/, int /*i*/) const { return -1; }
    int pred(int /*n*/, int /*i*/) const { return -1; }
};

// Auto queue / analyzer
inline bool auto_is_ok() { return true; }
inline void auto_wait() {}

// Binary-info extras
inline ea_t get_imagebase() { return inf_get_min_ea(); }
inline bool inf_is_kernel_mode() { return false; }
inline bool inf_is_be() { return false; }
inline int inf_get_procname(qstring* /*out*/) { return 0; }
inline int retrieve_input_file_md5(uint8_t* /*out16*/) { return 0; }
inline int retrieve_input_file_sha256(uint8_t* /*out32*/) { return 0; }
inline uint32_t retrieve_input_file_crc32() { return 0; }
inline int get_input_file_path(char* buf, size_t bufsize) { if (buf && bufsize) buf[0] = 0; return 0; }
inline const char* get_path(int /*type*/) { return ""; }
inline int get_root_filename(char* buf, size_t bufsize) { if (buf && bufsize) buf[0] = 0; return 0; }
inline qstring inf_get_procname_qs() { return {}; }

// Segment helpers
inline int get_segm_class(qstring* /*out*/, const segment_t* /*seg*/) { return 0; }
inline int get_segm_class(const segment_t* /*seg*/, qstring* /*out*/) { return 0; }
inline int get_segm_class(const segment_t* /*seg*/, char* buf, size_t bufsize) {
    if (buf && bufsize) buf[0] = 0; return 0;
}
inline int get_segm_name(qstring* /*out*/, const segment_t* /*seg*/) { return 0; }

// Type info (opaque stubs)
class tinfo_t {
public:
    bool empty() const { return true; }
    bool is_struct() const { return false; }
    bool is_udt() const { return false; }
    bool is_ptr() const { return false; }
    bool is_func() const { return false; }
    bool is_void() const { return false; }
    bool is_scalar() const { return false; }
    bool is_integral() const { return false; }
    size_t get_size() const { return 0; }
    qstring dstr() const { return {}; }
    qstring get_type_name() const { return {}; }
    bool get_type_name(qstring* /*out*/) const { return false; }
    bool get_udt_details(struct udt_type_data_t* /*out*/) const { return false; }
    bool get_pointed_object(tinfo_t* /*out*/) const { return false; }
    bool remove_ptr_or_array() { return false; }
    tinfo_t& operator=(const tinfo_t&) { return *this; }
    bool operator==(const tinfo_t&) const { return false; }
};

struct udt_member_t {
    qstring name;
    tinfo_t type;
    uint64_t offset = 0;
    uint64_t size = 0;
};

struct udt_type_data_t : std::vector<udt_member_t> {
    size_t total_size = 0;
    bool is_union = false;
};

using udt = udt_type_data_t;

// Fill iterator (fii)
struct func_item_iterator_t {
    ea_t cur = BADADDR;
    bool set(func_t* /*pfn*/) { return false; }
    bool set(func_t* /*pfn*/, ea_t /*ea*/) { return false; }
    bool set_range(ea_t /*start*/, ea_t /*end*/) { return false; }
    bool first() { return false; }
    bool last() { return false; }
    bool next_code() { return false; }
    bool prev_code() { return false; }
    bool next(bool /*code_only*/ = true) { return false; }
    bool prev(bool /*code_only*/ = true) { return false; }
    bool next_head() { return false; }
    bool prev_head() { return false; }
    ea_t current() const { return cur; }
};

// Head navigation (free-standing IDA functions)
inline ea_t next_head(ea_t /*ea*/, ea_t /*maxea*/ = BADADDR) { return BADADDR; }
inline ea_t prev_head(ea_t /*ea*/, ea_t /*minea*/ = 0) { return BADADDR; }
inline ea_t next_addr(ea_t /*ea*/) { return BADADDR; }
inline ea_t prev_addr(ea_t /*ea*/) { return BADADDR; }
inline ea_t get_item_head(ea_t ea) { return ea; }
inline ea_t get_item_end(ea_t ea) { return ea + 1; }
inline asize_t get_item_size(ea_t /*ea*/) { return 1; }
inline bool is_code(flags_t f) { return (f & 0x600) == 0x600; }
inline bool is_data(flags_t f) { return (f & 0x400) == 0x400; }
inline bool is_head(flags_t /*f*/) { return true; }
inline bool is_tail(flags_t /*f*/) { return false; }
inline bool is_loaded(ea_t /*ea*/) { return true; }
inline bool is_unknown(flags_t /*f*/) { return false; }
inline bool is_mapped(ea_t /*ea*/) { return true; }
inline bool has_name(flags_t /*f*/) { return false; }

// Instruction mnemonic constants (subset — vuln references NN_call/callni/callfi)
enum : uint16_t {
    NN_null = 0,
    NN_call = 16,
    NN_callfi = 17,
    NN_callni = 18,
    NN_jmp = 19,
    NN_jmpfi = 20,
    NN_jmpni = 21,
    NN_ret = 22,
    NN_retn = 23,
    NN_retf = 24,
};

// Netnode (persistent K/V) — minimal stub
class netnode {
public:
    netnode() = default;
    netnode(const char* /*name*/, size_t /*namlen*/ = 0, bool /*do_create*/ = false) {}
    netnode(nodeidx_t /*idx*/) {}
    bool create(const char* /*name*/) { return false; }
    void kill() {}
    operator nodeidx_t() const { return 0; }
    ea_t altval(nodeidx_t /*idx*/, char /*tag*/ = 'A') const { return 0; }
    ea_t altval_ea(nodeidx_t /*idx*/, char /*tag*/ = 'A') const { return 0; }
    bool altset(nodeidx_t /*idx*/, ea_t /*val*/, char /*tag*/ = 'A') { return false; }
    bool altset_ea(nodeidx_t /*idx*/, ea_t /*val*/, char /*tag*/ = 'A') { return false; }
    std::string supval(nodeidx_t /*idx*/, char /*tag*/ = 'S') const { return {}; }
    bool supset(nodeidx_t /*idx*/, const void* /*data*/, size_t /*size*/, char /*tag*/ = 'S') { return false; }
    bool supset(nodeidx_t /*idx*/, const char* /*s*/, char /*tag*/ = 'S') { return false; }
    bool supdel(nodeidx_t /*idx*/, char /*tag*/ = 'S') { return false; }
    ssize_t hashval(const char* /*key*/, void* /*buf*/, size_t /*size*/) const { return 0; }
    std::string hashval_str(const char* /*key*/) const { return {}; }
    bool hashset(const char* /*key*/, const void* /*data*/, size_t /*size*/, char /*tag*/ = 'H') { return false; }
    bool hashset(const char* /*key*/, const char* /*value*/, char /*tag*/ = 'H') { return false; }
    bool hashdel(const char* /*key*/, char /*tag*/ = 'H') { return false; }
    nodeidx_t alt1st(char /*tag*/ = 'A') const { return BADNODE; }
    nodeidx_t altnxt(nodeidx_t /*idx*/, char /*tag*/ = 'A') const { return BADNODE; }
    nodeidx_t sup1st(char /*tag*/ = 'S') const { return BADNODE; }
    nodeidx_t supnxt(nodeidx_t /*idx*/, char /*tag*/ = 'S') const { return BADNODE; }
};

// Agent tools return type
struct tool_result_t {
    bool ok = false;
    std::string message;
    std::string error;
    std::string result_json;
    std::string content;
    bool is_error = false;
};

// Demangling
inline int demangle_name(qstring* /*out*/, const char* /*mangled*/, uint32_t /*disable_mask*/ = 0) { return 0; }
inline std::string demangle(const std::string& s) { return s; }

// Xref flag constants
constexpr int XREF_ALL  = 0;
constexpr int XREF_DATA = 1;
constexpr int XREF_FAR  = 2;

// Extra flowchart flag
constexpr int FC_RESERVED = 0x100;

// Decompile helpers
constexpr int DECOMP_NO_WAIT = 1;
constexpr int DECOMP_NO_CACHE = 2;
constexpr int DECOMP_NO_XREFS = 4;

// util helpers (json)
inline void sanitize_json_utf8_inplace(std::string& /*s*/) {}
inline std::string sanitize_json_utf8(const std::string& s) { return s; }

// String literal type ids (IDA STRTYPE_*)
constexpr int32_t STRTYPE_C          = 0;
constexpr int32_t STRTYPE_C_16       = 1;
constexpr int32_t STRTYPE_C_32       = 2;
constexpr int32_t STRTYPE_PASCAL     = 3;
constexpr int32_t STRTYPE_PASCAL_16  = 4;
constexpr int32_t STRTYPE_LEN2       = 5;
constexpr int32_t STRTYPE_LEN2_16    = 6;
constexpr int32_t STRTYPE_LEN4       = 7;
constexpr int32_t STRTYPE_LEN4_16    = 8;
constexpr int32_t STRTYPE_TERMCHR    = 9;

// Agent tools registry stub
namespace agent_tools {
    class ToolRegistry {
    public:
        static ToolRegistry& instance() { static ToolRegistry S; return S; }
        template<typename... Args> void register_tool(Args&&...) {}
        template<typename... Args> void register_tools(Args&&...) {}
    };
}

// Segment fill / boundary helpers
inline int get_max_strlit_length(ea_t /*ea*/, int32_t /*strtype*/, int /*flags*/ = 0) { return 0; }
inline int get_strlit_contents(qstring* /*out*/, ea_t /*ea*/, size_t /*len*/, int32_t /*strtype*/ = 0) { return 0; }
inline int get_strlit_contents(char* /*buf*/, size_t /*bufsize*/, ea_t /*ea*/, size_t /*len*/, int32_t /*strtype*/ = 0) { return 0; }

// Global additional
inline void refresh_idaview_anyway() {}
inline void refresh_choosers() {}
inline void request_refresh(int /*mask*/ = 0) {}
inline void refresh_ui() {}

// IDA UI opaque type
struct TWidget;
inline TWidget* find_widget(const char* /*caption*/) { return nullptr; }
inline void activate_widget(TWidget* /*widget*/, bool /*take_focus*/ = true) {}
inline void close_widget(TWidget* /*widget*/, int /*options*/ = 0) {}
inline TWidget* open_custom_viewer(const char* /*title*/, void* /*strvec*/ = nullptr, int /*flags*/ = 0) { return nullptr; }
inline void set_dock_pos(const char* /*src*/, const char* /*dst*/, int /*orient*/ = 0) {}

// String vector (IDA line renderer)
struct simpleline_t {
    qstring line;
    uint8_t color = 0;
    uint8_t bgcolor = 0;
    simpleline_t() = default;
    simpleline_t(const char* s) : line(s) {}
    simpleline_t(const qstring& s) : line(s) {}
    simpleline_t(const std::string& s) : line(s) {}
};

using strvec_t = std::vector<simpleline_t>;
