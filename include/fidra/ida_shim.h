#pragma once

// Fidra IDA-SDK compatibility shim.
// Provides the subset of IDA Pro C++ SDK types + free functions used by ported
// AiDAPrivate modules (vuln, emulation, graphrag, multibinary). All primitives
// are backed by Fidra::AnalysisDatabase — no runtime IDA dependency.

#include <cstdint>
#include <cstddef>
#include <cstring>
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

// IDA's platform calling-convention marker — no-op on host compiler.
#ifndef idaapi
#define idaapi
#endif

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
