# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Fidra is

Native reverse-engineering IDE — C++20 / Qt 6, Linux primary (Windows/MSVC also supported). Combines disassembler, decompiler, ptrace debugger, memory scanner, hex editor, network/web-sec tooling, and a 300+ tool MCP server into one Qt application. Backends: Capstone (disasm), LIEF (used only by the unpacker; fetched via CMake), nlohmann_json.

## Build & run

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

- Presets exist (`CMakePresets.json`): `cmake --preset linux-release` / `linux-debug` (Ninja, binary dir `build/<preset>`, exports `compile_commands.json`); `windows-msvc` uses vcpkg via `$VCPKG_ROOT`.
- Warnings: `-Wall -Wextra -Wpedantic` (GCC/Clang), `/W4` (MSVC). No separate linter.
- WebEngine (Browser module) is optional — auto-detected. Disable: `cmake .. -DCMAKE_DISABLE_FIND_PACKAGE_Qt6WebEngineWidgets=TRUE`.
- LIEF is FetchContent-pulled (tag 0.15.1) on first configure — first build is slow. Its headers miss `<cstdint>`, so the root CMakeLists force-includes it for GCC 13+. nlohmann_json is also fetched if no config package is found.
- Deps: `qt6-base-dev qt6-webengine-dev libcapstone-dev nlohmann-json3-dev pkg-config`. Capstone: CMake config package first, pkg-config fallback.
- Optional submodule backends (off by default, need `git submodule update --init --recursive`): `-DFIDRA_ENABLE_LIBDECOMP=ON` (alt decompiler), `-DFIDRA_ENABLE_TRITON=ON` (symbolic exec / vuln chains), `-DFIDRA_ENABLE_UNICORN=ON` (emulation module). `-DFIDRA_BUILD_MULTIBINARY=OFF` drops the multibinary module (on by default).
- Run: `./Fidra` (GUI) · `./Fidra /path/to/binary` (open directly).

### Headless / testing

No unit-test framework. The only test is `test_analysis.cpp`, a smoke driver built when `-DFIDRA_BUILD_TESTS=ON` (target `fidra_test_analysis`, registered as ctest `analysis_smoke`; run with `ctest -R analysis_smoke` in the build dir). To exercise the analysis pipeline without the GUI, use headless mode:

```bash
./Fidra --headless <binary> --output-json out.json --output-functions funcs.txt \
        --output-strings s.txt --output-xrefs x.txt --output-imports i.txt \
        --timeout 300 --script post.lua
```

Headless flags are parsed by hand in `src/core/main.cpp` (`FindArgValue`/`HasArg`), not `QCommandLineParser`.

## Architecture

### Module system — the core abstraction

Every feature is an `IModule` (`include/fidra/IModule.h`). A module owns its widgets, dock panels, menu/toolbar contributions, and shortcuts. Modules never call each other directly — they talk through:

- **`ICore`** (`include/fidra/ICore.h`) — the host surface: dock management, module lookup (`GetModule(name)`), logging, `QSettings`, process attach/detach + memory R/W, and navigation/analysis callbacks (`OnFunctionNavigated`, `OnAnalysisStarted`, `OnProcessAttached`).
- **`AnalysisDatabase`** (`src/analysis/`) — thread-safe shared state (`QReadWriteLock` + `QMap`). This is where functions, instructions, xrefs, strings, symbols live. All modules read/write it.
- **Qt signals** for live updates.

`Application` (`src/core/Application.cpp`) implements `ICore` as the `QMainWindow`. Modules are instantiated and registered in `src/core/main.cpp` (~line 495, `MainWindow.RegisterModule(new Fidra::XxxModule())`) — **adding a module means editing both its `CMakeLists.txt`/`add_subdirectory` line in the root `CMakeLists.txt` AND the registration list in `main.cpp`.**

### Analysis pipeline

`AnalysisWorker` (`src/analysis/AnalysisEngine.h/.cpp`) runs the whole analysis off the UI thread and emits `ProgressChanged`/`Finished`. Order: load binary (`LoadPe`/`LoadElf`/`LoadMachO` — hand-written parsers, not LIEF; ELF imports come from `.rela.plt`/`.rela.dyn` + PLT stubs) → multi-threaded recursive descent (`RunRecursiveDescentMT`) → `FindFunctions` (entry/exports/vtables/code pointers/pattern scan) → `AnalyzeFunctions` (basic blocks, dominance, loops, calling convention, stack frame, arg count) → strings → xrefs → import/export naming → `.pdata`/SEH. Results land in `AnalysisDatabase`. Signature matching lives in `SignatureMatcher.*` (signatures with module `"common"` are code idioms and never rename functions).

`.eh_frame` (`EhFrame.*`, ELF/MinGW/Mach-O): every FDE seeds a function start and is treated like a sized symbol, so stripped binaries get exact function extents. The PLT's FDE is skipped (it spans all stubs).

Library signatures (`LibrarySignatures.*`, FLIRT-like): whole-function hash with relocated bytes masked via Capstone, keyed by (size, hash). `.fsig` files are auto-loaded in `MatchSignatures` from `<GenericDataLocation>/Fidra/sigs`, `<appdir>/sigs` and `$FIDRA_SIG_PATH`; headless `--make-sigs out.fsig [--sig-module name]` writes them from a binary with symbols, `--sigs <file|dir>` applies extra ones. Only `sub_` functions are renamed; x86/x86_64 only.

DWARF (`DwarfInfo.*`): `LoadDebugInfo` reads the binary's own `.debug_*`, else a separate file via build-id (`/usr/lib/debug/.build-id/…`, debuginfod cache) or `.gnu_debuglink`; DWARF 2–5, zlib-compressed sections (zstd unsupported). Functions seed starts/extents and name `sub_`s; prototypes and stack locals are stored per entry in `AnalysisDatabase::SetDebugFunction` and used by the decompiler (signature, callee prototypes, local names via CFA offsets). This is separate from the older name-only DWARF reader in `src/symbols/SymbolResolver`.

PDB (`PdbInfo.cpp`, same `DebugInfo` result): for PE files `LoadDebugInfo` dispatches to `LoadPdbInfo`, which reads the CodeView RSDS entry and looks for the PDB next to the binary, at its recorded path, or in symbol stores from `$FIDRA_SYMBOL_PATH` / `$_NT_SYMBOL_PATH` (`<store>/<name>/<GUID><age>/<name>`, local only — no download). MSF 7.00 only; GUID must match. Reads procedures + TPI/IPI prototypes, `S_REGREL32` / `S_LOCAL`+`S_DEFRANGE_*` stack locals (rsp-based only; `FrameBase::SpAfterPrologue`, converted to CFA in the Lifter via `PrologueRspDelta`), and `S_PUB32` code publics (`DebugInfo::Publics`, seeded and used to name `sub_`s).

Go binaries: `GoPclntab.*` parses `.gopclntab` (survives `strip`) for exact function entries and names. When found, the prologue byte scan is skipped and non-pclntab starts inside Go code are dropped. Function bodies are bounded by the next function start (`ComputeFunctionBoundaryCFG`'s `Limit`).

Huge binaries (300 MB+ PE) are a recurring pain point. Instructions are not held in RAM: `InstructionStore` (`src/analysis/InstructionStore.*`) is a disk-backed, mmapped record store under `$TMPDIR/fidra-insns-<pid>/`, with an instruction cap. Hot loops in `AnalysisEngine` work on local snapshots rather than taking DB locks per item. ICore callbacks must be safe to call from the worker thread. Keep these constraints in mind when touching the pipeline.

### Decompiler

`src/decompiler`: `Lifter` (Capstone → 3-address IR, temps are block-local) → `Optimizer` (copy/const propagation, liveness-based DCE, parameter recovery per `CallingConv`: SysV / Win64 / Go register ABI) → `CodeGenerator` (region structuring via post-dominators + natural loops with `goto` fallback; every block emitted exactly once; single-use temps inlined as expressions). Instructions the IR can't model are emitted as `__asm("...")` with their register effects from `cs_regs_access`, never dropped. Calls: `TypeLibrary` (`src/analysis/TypeLibrary.*`, built-in libc/POSIX/WinAPI headers in `TypeLibraryData.cpp`, extra `*.h` from `<GenericDataLocation>/Fidra/types` / `$FIDRA_TYPE_PATH`) gives prototypes; `Lifter::BindCallArguments` turns the last write of each argument register (and Win64/SysV outgoing stack slots) into a temp stored in `IrInst::CallArgs`, so every pass that walks operands must also walk `CallArgs`. Without a prototype the callee is lifted once to count its register parameters. printf-style calls take their extra argument count from the constant format string; noreturn calls cut the block. Headless `--decompile <addr|name,...|all>` prints pseudo-C. `Optimizer::RunPrologueEpilogueCleanup` strips register saves/frame setup/stack allocation and their restores, also when interleaved with unrelated register moves (stops at control flow or any rsp/stack access). `lea reg, [rsp/rbp+N]` lifts as `AddressOf` a stack slot (`&var`; arrays print as `buf`); `IrFunction::FramePointerCfa` records where the prologue put rbp (also `lea rbp, [rsp+N]`) for mapping rbp slots to debug-info names. `DecompilerModule` arms the Hexrays-shim bridge and calls `IdaShim::Bind` on analysis completion; MCP `decompile_function` goes through that bridge.

### MCP server

`src/mcp/` hosts an in-process MCP server exposing 300+ tools to AI clients. Tools are registered in `McpToolRegistry` (`RegisterTool(Name, Description, InputSchema, Handler)`, schemas via `McpSchemaBuilder.h`), with implementations split by domain across `McpTools*.cpp` (Ai, Analysis, Codegen, Debugger, Encoding, File, Memory, Network, Scripting, Utility); protocol/transport in `McpProtocol.*` / `McpServer.*`. `McpModule` auto-starts a TCP server on launch at the first free port in 3333–3432, so several Fidra instances can run side by side. Tools operate on the same `AnalysisDatabase` and live process, so they mirror the GUI's capabilities.

### Module directory map

`src/core` (host/`ICore`), `analysis` (engine + DB), `disasm`, `decompiler` (SSA IR → C), `debugger` (ptrace), `scanner` (Cheat-Engine-style + YARA), `hex/structeditor/typeeditor`, `unpacker`, `dumper`, `network`, `websec` (MITM proxy), `browser` (WebEngine, optional), `mcp`, `scripting` (Lua), `plugin`/`plugins`, `bindiff`/`diff`, `callgraph`, `symbols`, `project`, plus modules ported from AiDA: `graphrag`, `vuln` (vulnerability chain analysis, optional Triton), `multibinary` (cross-binary index/project), `emulation` (Unicorn-backed scaffold). The ported dirs carry `PORT_NOTES.md` explaining what was stubbed or excluded (e.g. `src/vuln/aida_stubs`, `src/multibinary/VulnStub.h`) — read it before editing them.

## Gotchas

- **Two plugin dirs exist** (`src/plugin` and `src/plugins`) — only `src/plugins` is in the root `CMakeLists.txt` and registered. `src/driver` and `src/typeeditor` also exist on disk but are **not** in the build. Verify a dir is wired into CMake before assuming it compiles.
- **Naming convention (enforced repo-wide):** UpperCamelCase / PascalCase for everything — variables, locals, members, and methods (`RunRecursiveDescentMT`, `AnalyzedFunction Func`). Match it; no snake_case, no camelCase.
- `build/` and `build2/` are committed build trees but gitignored for outputs — don't edit generated files under them.
- Plugin ABI: shared-object plugins export `fidra_create_module` / `fidra_plugin_info`.
