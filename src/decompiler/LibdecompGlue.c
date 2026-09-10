#ifdef FIDRA_HAS_LIBDECOMP

#include <libdecomp/libdecomp.h>
#include <libdecomp/backend/capstone.h>
#include <capstone/capstone.h>
#include <stdlib.h>
#include <string.h>

struct FidraDecompCtx {
    cs_insn* insns;
    size_t count;
};

static void* fidra_libdecomp_query(void* ctx, size_t index) {
    struct FidraDecompCtx* q = (struct FidraDecompCtx*)ctx;
    if (index >= q->count) return NULL;
    return &q->insns[index];
}

int fidra_libdecomp_run(const uint8_t* code_bytes,
                        const size_t* insn_offsets,
                        const size_t* insn_sizes,
                        const uint64_t* insn_addrs,
                        size_t insn_count,
                        int arch,
                        int mode,
                        int opt_level,
                        char* out_buf,
                        size_t out_buf_size) {
    if (!code_bytes || !insn_offsets || !insn_sizes || !insn_addrs || insn_count == 0
        || !out_buf || out_buf_size == 0) {
        return -1;
    }

    csh handle = 0;
    if (cs_open((cs_arch)arch, (cs_mode)mode, &handle) != CS_ERR_OK) return -2;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* built = (cs_insn*)calloc(insn_count, sizeof(cs_insn));
    if (!built) { cs_close(&handle); return -3; }

    size_t got = 0;
    for (size_t i = 0; i < insn_count; ++i) {
        cs_insn* tmp = NULL;
        size_t n = cs_disasm(handle,
                             code_bytes + insn_offsets[i],
                             insn_sizes[i],
                             insn_addrs[i],
                             1,
                             &tmp);
        if (n == 1) {
            built[got] = *tmp;
            cs_free(tmp, 1);
            ++got;
        }
    }

    if (got == 0) {
        free(built);
        cs_close(&handle);
        return -4;
    }

    struct FidraDecompCtx qctx;
    qctx.insns = built;
    qctx.count = got;

    DCProgram* prog = DC_ProgramCreate();
    if (!prog) {
        free(built);
        cs_close(&handle);
        return -5;
    }

    DCDisassemblerBackend backend = DC_DisassemblerCapstone((cs_arch)arch, (cs_mode)mode);
    DC_ProgramSetBackend(prog, &backend);
    DC_ProgramSetImage(prog, fidra_libdecomp_query, &qctx, qctx.count);
    DC_ProgramSetOptimizationLevel(prog, opt_level);

    memset(out_buf, 0, out_buf_size);
    DCError err = DC_ProgramDecompile(prog, out_buf, out_buf_size);
    free(prog);
    free(built);
    cs_close(&handle);
    return (int)err;
}

#endif
