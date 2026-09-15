#pragma once

// Fidra IDA-SDK compatibility shim.
// Provides the subset of IDA Pro C++ SDK types + free functions used by ported
// AiDAPrivate modules (vuln, emulation, graphrag, multibinary). All primitives
// are backed by Fidra::AnalysisDatabase — no runtime IDA dependency.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <functional>
#include <map>

#include <fidra/Types.h>

namespace Fidra {
class AnalysisDatabase;
class ICore;
}

// IDA calling-convention macros — no-op on non-Windows/non-IDA
#ifndef idaapi
#define idaapi
#endif
#ifndef ida_export
#define ida_export
#endif

// Segment permission bits
constexpr uint32_t SEGPERM_EXEC  = 1;
constexpr uint32_t SEGPERM_WRITE = 2;
constexpr uint32_t SEGPERM_READ  = 4;

using ea_t = uint64_t;
using asize_t = uint64_t;
using sval_t = int64_t;
using uval_t = uint64_t;
using flags_t = uint32_t;
using flags64_t = uint64_t;
using tid_t = uint64_t;
using sel_t = uint64_t;
using nodeidx_t = uint32_t;
using uchar = unsigned char;
using uint = unsigned int;

// IDA's qvector is a std::vector alias for our purposes.
template<typename T> using qvector = std::vector<T>;

// IDA's platform calling-convention marker — no-op on host compiler.
#ifndef idaapi
#define idaapi
#endif

constexpr ea_t BADADDR = static_cast<ea_t>(-1);
constexpr sel_t BADSEL = static_cast<sel_t>(-1);
constexpr nodeidx_t BADNODE = static_cast<nodeidx_t>(-1);
constexpr uint32_t BADNODE32 = static_cast<uint32_t>(-1);

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

// Decompile flags (hexrays)
constexpr int DECOMP_NO_WAIT   = 0x0004;
constexpr int DECOMP_WARNINGS  = 0x0008;
constexpr int DECOMP_NO_CACHE  = 0x0001;

// SN_* flags for set_name
constexpr int SN_CHECK = 0x00;
constexpr int SN_NOCHECK = 0x01;
constexpr int SN_PUBLIC = 0x02;
constexpr int SN_NON_PUBLIC = 0x04;
constexpr int SN_WEAK = 0x08;
constexpr int SN_AUTO = 0x40;
constexpr int SN_FORCE = 0x800;

// Xref flags (X_*)
constexpr int XREF_ALL  = 0x00;
constexpr int XREF_FAR  = 0x01;
constexpr int XREF_DATA = 0x02;

// -------- qstring (IDA's string type) --------
class qstring {
public:
    qstring() = default;
    qstring(const char* s) : buf(s ? s : "") {}
    qstring(const std::string& s) : buf(s) {}
    qstring(const qstring&) = default;
    qstring(qstring&&) = default;
    qstring& operator=(const qstring&) = default;
    qstring& operator=(qstring&&) = default;
    qstring& operator=(const char* s) { buf = s ? s : ""; return *this; }
    qstring& operator=(const std::string& s) { buf = s; return *this; }

    const char* c_str() const { return buf.c_str(); }
    size_t length() const { return buf.size(); }
    size_t size() const { return buf.size(); }
    bool empty() const { return buf.empty(); }
    void clear() { buf.clear(); }
    void append(const char* s) { buf.append(s ? s : ""); }
    void append(const qstring& s) { buf.append(s.buf); }
    void append(const std::string& s) { buf.append(s); }
    void append(char c) { buf.push_back(c); }

    qstring& operator+=(const char* s) { append(s); return *this; }
    qstring& operator+=(const qstring& s) { append(s); return *this; }
    qstring& operator+=(char c) { append(c); return *this; }

    bool operator==(const qstring& o) const { return buf == o.buf; }
    bool operator!=(const qstring& o) const { return buf != o.buf; }
    bool operator<(const qstring& o) const { return buf < o.buf; }

    char& operator[](size_t i) { return buf[i]; }
    const char& operator[](size_t i) const { return buf[i]; }

    // reserve for buffer-out API (get_func_name etc.)
    void resize(size_t n) { buf.resize(n); }
    void reserve(size_t n) { buf.reserve(n); }

    std::string& str() { return buf; }
    const std::string& str() const { return buf; }

    std::string buf;
};

inline int qsnprintf(char* dst, size_t n, const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int r = std::vsnprintf(dst, n, fmt, ap);
    va_end(ap);
    return r;
}

// -------- func_t --------
struct func_t {
    ea_t start_ea = 0;
    ea_t end_ea = 0;
    uint32_t flags = 0;
    uint32_t argsize = 0;
    uint32_t frsize = 0;
    uint16_t frregs = 0;
    int32_t regvarqty = 0;
    int32_t regargqty = 0;
    int32_t pntqty = 0;

    asize_t size() const { return end_ea > start_ea ? end_ea - start_ea : 0; }
    bool does_return() const { return (flags & FUNC_NORET) == 0; }
    bool is_far() const { return (flags & FUNC_FAR) != 0; }
    bool is_lib() const { return (flags & FUNC_LIB) != 0; }
    bool is_thunk() const { return (flags & FUNC_THUNK) != 0; }
    bool empty() const { return start_ea == BADADDR || start_ea == end_ea; }
    bool contains(ea_t ea) const { return ea >= start_ea && ea < end_ea; }
};

// -------- segment_t --------
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

// -------- Instruction (insn_t / op_t) --------
struct op_t {
    uint8_t n = 0;
    uint8_t type = 0;    // o_reg, o_mem, o_phrase, o_displ, o_imm, o_far, o_near
    uint8_t offb = 0;
    uint8_t offo = 0;
    uint8_t flags = 0;
    uint8_t dtype = 0;
    uint16_t reg = 0;
    uint64_t value = 0;
    uint64_t addr = 0;
    uint32_t specflag1 = 0;
    uint32_t specflag2 = 0;
    uint32_t specflag3 = 0;
    uint32_t specflag4 = 0;
    bool shown() const { return true; }
};

// op_t.type
constexpr uint8_t o_void   = 0;
constexpr uint8_t o_reg    = 1;
constexpr uint8_t o_mem    = 2;
constexpr uint8_t o_phrase = 3;
constexpr uint8_t o_displ  = 4;
constexpr uint8_t o_imm    = 5;
constexpr uint8_t o_far    = 6;
constexpr uint8_t o_near   = 7;
constexpr uint8_t o_idpspec0 = 8;
constexpr uint8_t o_idpspec1 = 9;

struct insn_t {
    ea_t ea = 0;
    uint16_t itype = 0;
    uint16_t size = 0;
    uint16_t auxpref = 0;
    uint8_t segpref = 0;
    uint8_t insnpref = 0;
    op_t ops[8]{};

    op_t& Op1 = ops[0];
    op_t& Op2 = ops[1];
    op_t& Op3 = ops[2];

    insn_t() : Op1(ops[0]), Op2(ops[1]), Op3(ops[2]) {}
    insn_t(const insn_t& o) : ea(o.ea), itype(o.itype), size(o.size),
        auxpref(o.auxpref), segpref(o.segpref), insnpref(o.insnpref),
        Op1(ops[0]), Op2(ops[1]), Op3(ops[2]) {
        for (int i = 0; i < 8; ++i) ops[i] = o.ops[i];
    }
    insn_t& operator=(const insn_t& o) {
        if (this != &o) {
            ea = o.ea; itype = o.itype; size = o.size;
            auxpref = o.auxpref; segpref = o.segpref; insnpref = o.insnpref;
            for (int i = 0; i < 8; ++i) ops[i] = o.ops[i];
        }
        return *this;
    }
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
flags64_t get_flags64(ea_t ea);

inline bool is_code(flags_t f) { return (f & 0x00000600u) == 0x00000600u; }
inline bool is_data(flags_t f) { return (f & 0x00000400u) != 0; }
inline bool is_head(flags_t f) { return (f & 0x00000400u) != 0; }
inline bool is_tail(flags_t f) { return (f & 0x00000200u) != 0; }
inline bool is_unknown(flags_t f) { return f == 0; }
inline bool is_func(flags_t f) { return (f & 0x10000000u) != 0; }
inline bool is_loaded(flags_t f) { return f != 0; }
inline bool has_value(flags_t f) { return f != 0; }
inline bool has_value(flags64_t f) { return f != 0; }

// -------------- Name / comment APIs --------------

std::string get_name(ea_t ea);
std::string get_func_name(ea_t ea);
// qstring* overload (IDA form)
ssize_t get_func_name(qstring* out, ea_t ea);
ssize_t get_name(qstring* out, ea_t ea);
ssize_t get_short_name(qstring* out, ea_t ea);
ssize_t get_long_name(qstring* out, ea_t ea);
std::string get_true_name(ea_t ea);
std::string get_short_name(ea_t ea);
std::string get_long_name(ea_t ea);
bool set_name(ea_t ea, const char* name, int flags = 0);

// Reverse-lookup name -> ea (returns BADADDR if not found)
ea_t get_name_ea(ea_t from, const char* name);
inline ea_t get_name_ea_simple(const char* name) { return get_name_ea(BADADDR, name); }

// Out-parameter forms: definitions live in IdaShim.cpp
ssize_t get_ea_name(qstring* out, ea_t ea, int flags = 0);

std::string get_cmt(ea_t ea, bool repeatable = false);
ssize_t get_cmt(qstring* out, ea_t ea, bool repeatable = false);
bool set_cmt(ea_t ea, const char* comment, bool repeatable = false);
bool append_cmt(ea_t ea, const char* comment, bool repeatable = false);

// -------------- Segment APIs --------------

segment_t* getseg(ea_t ea);
segment_t* get_first_seg();
segment_t* get_next_seg(ea_t ea);
size_t get_segm_qty();
segment_t* getnseg(int n);
std::string get_segm_name(const segment_t* seg);
ssize_t get_segm_name(qstring* out, const segment_t* seg);
uint32_t segtype(ea_t ea);

// -------------- Binary meta (inf_get_*) --------------

int inf_get_app_bitness();
int inf_get_cc_id();
uint32_t inf_get_database_change_count();
uint16_t inf_get_filetype();
ea_t inf_get_max_ea();
ea_t inf_get_min_ea();
std::string inf_get_procname();
ssize_t inf_get_procname(qstring* out);
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

// -------------- Instruction decoding --------------

int decode_insn(insn_t* out, ea_t ea);
bool is_call_insn(const insn_t& insn);
bool is_ret_insn(const insn_t& insn);
bool is_indirect_jump_insn(const insn_t& insn);
ea_t next_head(ea_t ea, ea_t maxea = BADADDR);
ea_t prev_head(ea_t ea, ea_t minea = 0);

// print_insn_mnem etc (very stubby)
inline ssize_t print_insn_mnem(qstring* out, ea_t /*ea*/) { if (out) out->clear(); return 0; }
inline ssize_t print_operand(qstring* out, ea_t /*ea*/, int /*n*/) { if (out) out->clear(); return 0; }

// -------------- Imports/exports (subset) --------------

int get_import_module_qty();
bool get_import_module_name(qstring* out, int idx);
using import_enum_cb_t = int (*)(ea_t ea, const char* name, uval_t ord, void* ctx);
int enum_import_names(int idx, import_enum_cb_t cb, void* ctx = nullptr);

size_t get_entry_qty();
ea_t get_entry(uint64_t ordinal);
uint64_t get_entry_ordinal(size_t idx);
ssize_t get_entry_name(qstring* out, uint64_t ord);

// -------------- Binary hash --------------

bool retrieve_input_file_md5(uchar out[16]);
bool retrieve_input_file_sha256(uchar out[32]);
qstring get_input_file_path();
qstring get_root_filename();

// -------------- IDA user dir --------------

inline qstring get_user_idadir() {
    const char* home = std::getenv("HOME");
    qstring q(home ? home : "/tmp");
    q.append("/.fidra");
    return q;
}

// -------------- Netnode (persistent KV) --------------

class netnode {
public:
    netnode() = default;
    netnode(const char* name, size_t /*namelen*/ = 0, bool /*do_create*/ = false)
        : node_name(name ? name : "") {}
    netnode(nodeidx_t idx) : node_idx(idx) {}

    // supval/altval/hashval interface (in-memory)
    ssize_t supval(nodeidx_t alt, void* buf, size_t maxsize, char tag = 'S') const;
    bool supset(nodeidx_t alt, const void* value, size_t length = 0, char tag = 'S');
    bool supdel(nodeidx_t alt, char tag = 'S');
    uint32_t altval(nodeidx_t alt, char tag = 'A') const;
    bool altset(nodeidx_t alt, uint32_t value, char tag = 'A');
    bool altdel(nodeidx_t alt, char tag = 'A');

    // blob API
    ssize_t getblob(void* out, nodeidx_t start, char tag = 'B') const;
    bool setblob(const void* data, size_t size, nodeidx_t start, char tag = 'B');
    bool delblob(nodeidx_t start, char tag = 'B');

    // hash API
    ssize_t hashval(const char* idx, void* buf, size_t maxsize, char tag = 'H') const;
    bool hashset(const char* idx, const void* value, size_t length = 0, char tag = 'H');
    bool hashdel(const char* idx, char tag = 'H');

    nodeidx_t netnode_index() const { return node_idx; }
    operator bool() const { return !node_name.empty() || node_idx != BADNODE; }

private:
    std::string node_name;
    nodeidx_t node_idx = BADNODE;
};

// -------------- simpleline_t / strvec_t --------------
struct simpleline_t {
    qstring line;
    uchar color = 0;
    uchar bgcolor = 0;
    simpleline_t() = default;
    simpleline_t(const qstring& l) : line(l) {}
    simpleline_t(const char* l) : line(l ? l : "") {}
};
using strvec_t = std::vector<simpleline_t>;

inline void tag_remove(qstring* out, const qstring& in) { if (out) *out = in; }
inline void tag_remove(qstring* out, const char* in) { if (out) *out = in ? in : ""; }
inline qstring tag_remove(const qstring& in) { return in; }

// -------------- Image base --------------
ea_t get_imagebase();

// -------------- Line generation (stub — returns raw addr) --------------
constexpr int GENDSM_REMOVE_TAGS = 0x0004;
constexpr int GENDSM_MULTI_LINE = 0x0001;
inline ssize_t generate_disasm_line(qstring* out, ea_t /*ea*/, int /*flags*/ = 0) {
    if (out) out->clear();
    return 0;
}

// -------------- Xref flag constants --------------
constexpr int XREF_CODE = 0x01;
constexpr int XREF_DATA_LOCAL = 0x02;
constexpr int XREF_NOFLOW = 0x04;
constexpr int XREF_MASK = 0x0F;
constexpr int XREF_TAIL = 0x40;
constexpr int XREF_USER = 0x20;

// -------------- Auto/refresh --------------
inline void auto_make_code(ea_t /*ea*/) {}
inline void auto_make_proc(ea_t /*ea*/) {}
inline bool is_mapped(ea_t /*ea*/) { return true; }

// -------------- Type info (very minimal) --------------

class tinfo_t {
public:
    tinfo_t() = default;
    bool empty() const { return true; }
    bool is_valid() const { return false; }
    qstring dstr() const { return qstring(""); }
};

// -------------- Callbacks — auto_wait, refresh --------------

inline bool auto_wait() { return true; }
inline bool auto_is_ok() { return true; }
inline void request_refresh(int /*mask*/ = 0) {}
using builtin_widgets_mask_t = uint32_t;

// -------------- Additional shim symbols for vuln port --------------

constexpr size_t QMAXPATH = 4096;
constexpr int PATH_TYPE_CMD = 0;
constexpr int PATH_TYPE_IDB = 1;
constexpr int PATH_TYPE_ID0 = 2;

inline uint32_t retrieve_input_file_crc32() { return 0; }
inline bool inf_is_kernel_mode() { return false; }
inline bool inf_is_be() { return false; }

inline int get_segm_class(qstring* /*out*/, const segment_t* /*seg*/) { return 0; }
inline int get_segm_class(const segment_t* /*seg*/, char* buf, size_t bufsize) {
    if (buf && bufsize) buf[0] = 0; return 0;
}

// next_head/prev_head implemented in IdaShim.cpp
inline ea_t next_addr(ea_t /*ea*/) { return BADADDR; }
inline ea_t prev_addr(ea_t /*ea*/) { return BADADDR; }
inline ea_t get_item_head(ea_t ea) { return ea; }
inline ea_t get_item_end(ea_t ea) { return ea + 1; }
inline asize_t get_item_size(ea_t /*ea*/) { return 1; }

// STRTYPE_*
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

// NN_* instruction mnemonic constants (subset)
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

// qflow_chart_t / qbasic_block_t
struct qbasic_block_t {
    ea_t start_ea = 0;
    ea_t end_ea = 0;
    std::vector<int> succ_list;
    std::vector<int> pred_list;
    size_t size() const { return end_ea - start_ea; }
};

enum { FC_PREDS = 1, FC_APPND = 2, FC_NOEXT = 4, FC_CALL_ENDS = 8, FC_RESERVED = 0x100 };

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

// tool_result_t (agent tools return)
struct tool_result_t {
    bool ok = false;
    std::string message;
    std::string error;
    std::string result_json;
    std::string content;
    bool is_error = false;
};

// Agent tools registry stub
namespace agent_tools {
    class ToolRegistry {
    public:
        static ToolRegistry& instance() { static ToolRegistry S; return S; }
        template<typename... Args> void register_tool(Args&&...) {}
        template<typename... Args> void register_tools(Args&&...) {}
    };
}

// Extra segment/name helpers
inline int get_max_strlit_length(ea_t /*ea*/, int32_t /*strtype*/, int /*flags*/ = 0) { return 0; }
inline int get_strlit_contents(qstring* /*out*/, ea_t /*ea*/, size_t /*len*/, int32_t /*strtype*/ = 0) { return 0; }

// Demangling
inline int demangle_name(qstring* /*out*/, const char* /*mangled*/, uint32_t /*disable_mask*/ = 0) { return 0; }
inline std::string demangle(const std::string& s) { return s; }

// TWidget / open_custom_viewer
struct TWidget;
inline TWidget* find_widget(const char* /*caption*/) { return nullptr; }
inline void activate_widget(TWidget* /*widget*/, bool /*take_focus*/ = true) {}
inline void close_widget(TWidget* /*widget*/, int /*options*/ = 0) {}
inline TWidget* open_custom_viewer(const char* /*title*/, void* /*strvec*/ = nullptr, int /*flags*/ = 0) { return nullptr; }
inline void set_dock_pos(const char* /*src*/, const char* /*dst*/, int /*orient*/ = 0) {}

inline void refresh_idaview_anyway() {}
inline void refresh_choosers() {}
inline void refresh_ui() {}

// MSVC-only numeric aliases
#ifndef _MSC_VER
inline unsigned long long _strtoui64(const char* str, char** endptr, int base) {
    return std::strtoull(str, endptr, base);
}
inline long long _strtoi64(const char* str, char** endptr, int base) {
    return std::strtoll(str, endptr, base);
}
#endif

// JSON sanitize helpers
inline void sanitize_json_utf8_inplace(std::string& /*s*/) {}
inline std::string sanitize_json_utf8(const std::string& s) { return s; }

// udt structs
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
