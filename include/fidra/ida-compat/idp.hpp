#pragma once
#include <fidra/ida_shim.h>
#include <fidra/ida-compat/kernwin.hpp>
#include <fidra/ida-compat/ua.hpp>
#include <cstddef>

// Processor helper struct — IDA global 'PH'.
struct processor_t {
    int id = 0;                 // PLFM_386 etc.
    int flag = 0;
    int cnbits = 8;
    int dnbits = 8;
    const char** psnames = nullptr;
    const char** plnames = nullptr;
    const char** psnames_default = nullptr;
    int regs_num = 0;
    const char** reg_names = nullptr;

    ssize_t get_reg_name(qstring* out, int reg, size_t /*width*/ = 0) const {
        if (out) { *out = qstring("r"); out->append(std::to_string(reg)); }
        return out ? out->length() : 0;
    }
};

inline processor_t& ph_instance() { static processor_t P; return P; }
#define PH ph_instance()

constexpr int PLFM_386   = 15;
constexpr int PLFM_ARM   = 13;
constexpr int PLFM_MIPS  = 6;
constexpr int PLFM_PPC   = 14;

// Free-function get_reg_name (some code calls it directly)
inline ssize_t get_reg_name(qstring* out, int reg, size_t /*width*/ = 0) {
    return PH.get_reg_name(out, reg);
}

inline ssize_t print_operand(qstring* out, ea_t /*ea*/, int /*n*/) {
    if (out) out->clear();
    return 0;
}
