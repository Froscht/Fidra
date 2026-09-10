# vuln Port Notes

Initial port pass: **19 of 37 .cpp files compile**. Remaining 16 excluded pending deeper shim work or algorithmic rewrite. Runtime correctness NOT yet validated — this is a compile+link pass.

## Compiled (19)

Chain analysis core: alias, binary_corpus, boundary, budget, cross_domain, lifetime,
model, path_trace, protocol, regression_specs, report, schema, side_effects, solver,
state_contracts, state, transfer, trigger_trace. Plus vuln_tools.

## Excluded — top blocker classes

| File | Errors | Blocker |
|------|--------|---------|
| chain_extraction.cpp | 236 | deep hexrays cfunc_t traversal in extractor pipeline |
| vuln_callsites.cpp | 198 | `vd_failure_t`, `decompile_cache_t`, per-callsite decompile |
| taint_engine.cpp | 189 | mop_t/minsn_t taint propagation over microcode graph |
| cfg_engine.cpp | 127 | `tinfo_t::get_named_type`, `udt_type_data_t::is_vftable`, `ToolRegistry` binding |
| verification_tools.cpp | 72 | verification result plumbing depends on excluded engine |
| chain_verify_service.cpp | 60 | `execute_sync(MFF_READ)` IDA thread-marshal + UI dispatch |
| vuln_strings.cpp | 54 | STRTYPE_* handling + ctree visitor with untyped `visit_expr` |
| microcode_engine.cpp | 294 | `gen_microcode(mba_ranges_t, ..., MMAT_*)` — real hexrays microcode API |
| surface_engine.cpp | 211 | heavy hexrays ctree traversal for attack-surface heuristics |
| chain_verifier.cpp | 19 | multibinary+hexrays deep integration (needs both real backends) |
| chain_verification_engine.cpp | 11 | microcode-level verification pass |
| chain_store.cpp | 9 | `execute_sync(MFF_READ)` IDA thread-marshal for durable store |
| chain_report_view.cpp | 16 | IDA UI (`custom_viewer_t`, `simpleline_place_t`, `WOPN_*`) |
| kernel_engine.cpp | 91 | IDA kernel-mode analysis primitives |
| ida_gateway.cpp | 22 | IDA plugin-gateway (`hook_to_notification_point`, action defs) |
| symbolic_engine.cpp | — | guarded via `FIDRA_ENABLE_TRITON`, off by default |

## Shims added under `include/fidra/`

Expanded during this port:

- `ida_shim.h`: `qstring`, `insn_t` / `op_t` / `decode_insn`, `qflow_chart_t` / `qbasic_block_t`,
  `tinfo_t` / `udt_type_data_t`, `func_item_iterator_t`, `netnode`, `tool_result_t`,
  `TWidget` opaque, `simpleline_t` / `strvec_t`, STRTYPE_*, SEGPERM_*, PATH_TYPE_*,
  NN_call / NN_callfi / NN_callni, `demangle_name`, `sanitize_json_utf8_inplace`,
  `agent_tools::ToolRegistry` stub, MSVC `_strtoui64` alias.
- `hexrays_shim.h`: `mba_t` / `mblock_t` / `minsn_t` / `mop_t`, `mopcode_t` / `mopt_t`,
  `mba_maturity_t`, `mlist_t`, `cif_t` / `cfor_t` / `cwhile_t` / `cswitch_t` / `ccase_t` /
  `creturn_t` / `cgoto_t` / `casm_t`, `til_t`, `get_idati`, `gen_microcode`, `decompile_func`.

## AiDA-internal stubs under `src/vuln/aida_stubs/`

- `aida_pro.hpp` — thin umbrella including std / json + shims.
- `analysis_db.hpp` — `aida_db::AnalysisDB::instance()` (no-op backing).
- `settings.hpp` — `settings_t` shape only, all methods no-op.
- `ida_utils.hpp` — `is_safely_decompilable`, `set_clipboard_text` no-ops.
- `agent_tools.hpp` — `tool_result_t`, `ToolRegistry`, helpers.
- `aida_ipc.hpp` — `send` / `subscribe` no-ops.
- `multibinary_project.hpp` / `multibinary_index.hpp` — `project_io_result_t` +
  `current_idb_inventory`, `list_projects`, etc no-op returns.

## Next steps (out of scope for this pass)

1. Bridge `decompile()` to Fidra's own decompiler or `LibdecompBackend` so
   many of the excluded files can be re-enabled without runtime no-op.
2. Real `netnode` backing (SQLite-backed KV under project data dir).
3. Port UI-heavy `chain_report_view.cpp` to Qt (QListView + custom item delegate)
   as a Fidra dock widget instead of IDA `simpleline_place_t`.
4. `MFF_READ` marshal — Fidra already runs analysis off UI thread; map to
   `QMetaObject::invokeMethod(..., Qt::BlockingQueuedConnection)`.
5. `kernel_engine.cpp` / `microcode_engine.cpp` — needs real microcode source
   (Ghidra P-Code or Triton IR) since Fidra's decompiler is SSA IR.
