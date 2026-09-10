# Multibinary port notes

Source: `src/imports/aida/multibinary/multibinary_{index,project}.{cpp,hpp}` (AiDA).

## Status

- `fidra_multibinary` STATIC library **compiles + links** (opt-in via `-DFIDRA_BUILD_MULTIBINARY=ON`).
- **Only `MultibinaryProject.cpp` is currently in the build.**
- `MultibinaryIndex.cpp` is present on disk but excluded from the CMake target — see below.

## What compiles

`MultibinaryProject.{h,cpp}` (~1180 LOC):

- Project/inventory JSON schema (`aida.ida.project.inventory.v1`), corpus records, canonical addresses.
- Wired against Fidra `AnalysisDatabase` via the IDA shim (`include/fidra/ida-compat/`).
- Import module / entry point iteration returns Fidra `BinaryInfo::Imports` / `Exports` sizes (real data can be lit up incrementally once the shim's `enum_import_names`/`get_entry_ordinal` walk real DB entries).
- `execute_sync(exec_request_t&)` currently runs inline on the calling thread — fine for compile+link; real UI thread marshalling belongs behind Fidra's Qt event loop.

## What is NOT compiled — MultibinaryIndex.cpp

2740 LOC of deep IDA hexrays/kernwin integration. It was reduced to **88 build errors** after aggressive shim work, but the remaining ones sit on API surfaces that are effectively a hexrays reimplementation:

- `cfunc_t` ctree traversal — `ctree_visitor_t::visit_insn/visit_expr` real dispatch, `cinsn_t::cswitch` (switch statement decompilation), `cexpr_t` operand tree.
- `decompile_func` with `DECOMP_NO_WAIT` / `DECOMP_WARNINGS` flags and `vd_failure_t` exception unwinding.
- `execute_sync` where the request captures a live `hexrays_failure_t` and rethrows.
- `netnode` blob store round-tripping large corpus records (needs backing SQLite / QSettings).

**Path forward**: bridge hexrays_shim.h to Fidra's own decompiler (`src/decompiler/`) so `decompile()` yields something walkable, then either
(a) rewrite the ctree visitors against Fidra's SSA IR, or
(b) generate cinsn_t/cexpr_t stubs from Fidra's decompiler output.

Estimated: 1–2 additional sessions.

## What was stubbed / degraded

`src/multibinary/VulnStub.h` — minimal `vuln::chain::` namespace shim: `corpus_record_t`, `canonical_address_t`, `snapshot_current_idb_corpus`, `to_json`, `normalize_ea`. Empty data at runtime; JSON output shape preserved.

`microcode_engine_t` and `verification_engine_t` are no-op classes.

## Shim additions this port pulled in

- `include/fidra/ida-compat/{diskio.hpp, prodir.h}` (new pass-throughs)
- `nalt.hpp` — `PATH_TYPE_IDB`, `get_path`, `get_input_file_path`, `retrieve_input_file_{md5,sha256}`, `get_imagebase`, `get_import_module_qty`, `enum_import_names`, `get_user_idadir`.
- `entry.hpp` — `get_entry_qty`, `get_entry_ordinal`, `get_entry`, `get_entry_name`.
- `kernwin.hpp` — `qstring`, `tag_remove` (single-arg overload), `execute_sync`, `exec_request_t`, `MFF_READ`/`MFF_WRITE`, `auto_is_ok`, `hook_to_notification_point`.
- `name.hpp` — `get_ea_name`, `GN_*` flags, `is_loaded`, `get_nlist_*`, qstring overloads of `get_name` / `get_func_name`.
- `idp.hpp` — `processor_t` (+`reg_names`, `regs_num`, `get_reg_name`), `PH`, `PLFM_*`, `print_operand`.
- `ua.hpp` — `insn_t`, `op_t`, `optype_t` (o_reg / o_mem / o_imm / …), `UA_MAXOP`, `decode_insn` (stub).
- `allins.hpp` — `NN_*` mnemonic enum (call/jmp/j*/mov/… subset).
- `netnode.hpp` — `netnode` class with alt/sup/blob API (in-memory).
- `xref.hpp` — `XREF_FAR`, cref/dref walker stubs.
- `ida_shim.h` — `idaapi` macro (empty on host).

## Runtime state

**No runtime testing done.** Target was compile+link only. Every AiDA path that reads a real IDA database will produce empty output. Fidra AnalysisDatabase pass-through is wired for `get_imagebase`, `get_import_module_qty`, `get_entry_qty`, `get_entry_ordinal`, `get_name`, `get_func_name`.
