# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Fidra is

Native reverse-engineering IDE — C++20 / Qt 6, Linux. Combines disassembler, decompiler, ptrace debugger, memory scanner, hex editor, network/web-sec tooling, and a 300+ tool MCP server into one Qt application. Backends: Capstone (disasm), LIEF (binary parsing, fetched via CMake), nlohmann_json.

## Build & run

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

- WebEngine (Browser module) is optional — auto-detected. Disable: `cmake .. -DCMAKE_DISABLE_FIND_PACKAGE_Qt6WebEngineWidgets=TRUE`.
- LIEF is FetchContent-pulled (tag 0.15.1) on first configure — first build is slow.
- Deps: `qt6-base-dev qt6-webengine-dev libcapstone-dev nlohmann-json3-dev pkg-config` (Capstone found via pkg-config, not CMake package).
- Run: `./Fidra` (GUI) · `./Fidra /path/to/binary` (open directly).

### Headless / testing

No unit-test framework wired into CMake. `test_analysis.cpp` is a standalone driver (not in any CMakeLists), not a suite. To exercise the analysis pipeline without the GUI, use headless mode:

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

`Application` (`src/core/Application.cpp`) implements `ICore` as the `QMainWindow`. Modules are instantiated and registered in `src/core/main.cpp` (~line 476, `RegisterModule(new XxxModule())`) — **adding a module means editing both its `CMakeLists.txt`/`add_subdirectory` line in the root `CMakeLists.txt` AND the registration list in `main.cpp`.**

### Analysis pipeline

`AnalysisWorker` (`src/analysis/AnalysisEngine.h/.cpp`) runs the whole analysis off the UI thread and emits `ProgressChanged`/`Finished`. Order: load binary (`LoadPe`/`LoadElf`/`LoadMachO` via LIEF) → multi-threaded recursive descent (`RunRecursiveDescentMT`) → `FindFunctions` (entry/exports/vtables/code pointers/pattern scan) → `AnalyzeFunctions` (basic blocks, dominance, loops, calling convention, stack frame, arg count) → strings → xrefs → import/export naming → `.pdata`/SEH. Results land in `AnalysisDatabase`. Signature matching lives in `SignatureMatcher.*`.

### MCP server

`src/mcp/` hosts an in-process MCP server exposing 300+ tools to AI clients. Tool implementations are split across `McpToolsAi.cpp`, `McpToolsAnalysis.cpp` (and siblings); protocol/transport in `McpProtocol.*` / `McpServer.*`. Tools operate on the same `AnalysisDatabase` and live process, so they mirror the GUI's capabilities.

### Module directory map

`src/core` (host/`ICore`), `analysis` (engine + DB), `disasm`, `decompiler` (SSA IR → C), `debugger` (ptrace), `scanner` (Cheat-Engine-style + YARA), `hex/structeditor/typeeditor`, `unpacker`, `dumper`, `network`, `websec` (MITM proxy), `browser` (WebEngine, optional), `mcp`, `scripting` (Lua), `plugin`/`plugins`, `bindiff`/`diff`, `callgraph`, `symbols`, `project`.

## Gotchas

- **Two plugin dirs exist** (`src/plugin` and `src/plugins`) — only `src/plugins` is in the root `CMakeLists.txt` and registered. `src/driver` and `src/typeeditor` also exist on disk but are **not** in the build. Verify a dir is wired into CMake before assuming it compiles.
- **Naming convention (enforced repo-wide):** UpperCamelCase / PascalCase for everything — variables, locals, members, and methods (`RunRecursiveDescentMT`, `AnalyzedFunction Func`). Match it; no snake_case, no camelCase.
- `build/` and `build2/` are committed build trees but gitignored for outputs — don't edit generated files under them.
- Plugin ABI: shared-object plugins export `fidra_create_module` / `fidra_plugin_info`.
