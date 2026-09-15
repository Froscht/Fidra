## AiDA Import Staging

Verbatim copy of selected files from AiDAPrivate for porting to Fidra.

**Not compiled.** No `add_subdirectory` entry. Reference only.

Origin: /media/frost/Coding Stuf/Work/AiDAPrivate (github.com/sigwl/AiDAPrivate, commit dc3d1f75).

### Layout

- `vuln/`             — 73 chain analysis files (52k LOC). Target: `src/vuln/` after shim.
- `emulation/`        — emulation_engine.{cpp,hpp} (1.7k LOC). Target: `src/emulation/`.
- `graphrag/`         — graphrag.{cpp,hpp} (5.1k LOC). Target: `src/graphrag/`.
- `multibinary/`      — multibinary_index/project (4k LOC). Target: extension of `src/project/`.
- `analysis_db.hpp`, `aida_pro.hpp`, `aida_ipc.*`, `agent_tools.*`, `settings.*`, `ida_utils.*` — shared AiDA headers referenced by ports.
- `comm.h`, `mcp_standalone.hpp`, `diag_log.hpp` — misc dependencies.

### Port workflow

1. `include/fidra/ida_shim.h` maps IDA SDK to Fidra `AnalysisDatabase`.
2. Copy target file(s) from here to real module path.
3. Replace `#include <ida.hpp>` / `<hexrays.hpp>` / `<pro.h>` etc with `#include "fidra/ida_shim.h"`.
4. Wire into module `CMakeLists.txt` + `main.cpp` `RegisterModule`.
5. Fix remaining errors iteratively — never delete this staging copy until port compiles + runs.

### Hexrays gap

64 `decompile()` / `cfunc_t` uses in vuln/. Two options:
- Bridge to `src/decompiler/` Fidra own SSA→C output.
- Bridge to libdecomp (`FIDRA_ENABLE_LIBDECOMP=ON`).

Both produce different AST than hexrays — chain code needs adapter layer over decompiler output, not literal cfunc_t translation.
