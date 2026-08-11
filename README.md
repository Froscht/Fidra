<p align="center">
  <img src="docs/fidra-banner.png" alt="Fidra" width="800"/>
</p>

<h1 align="center">Fidra</h1>

<p align="center">
  <strong>Open-Source Reverse Engineering IDE for Linux</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#building">Building</a> •
  <a href="#usage">Usage</a> •
  <a href="#scripting">Scripting</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="License: GPL v3"/>
  <img src="https://img.shields.io/badge/C%2B%2B-20-blue.svg" alt="C++20"/>
  <img src="https://img.shields.io/badge/Qt-6.4+-green.svg" alt="Qt 6.4+"/>
  <img src="https://img.shields.io/badge/Platform-Linux-lightgrey.svg" alt="Platform: Linux"/>
  <img src="https://img.shields.io/badge/Lines_of_Code-75k+-orange.svg" alt="Lines of Code: 75k+"/>
</p>

---

**Fidra** is a fully-featured, native reverse engineering IDE built from scratch in C++20 with Qt 6. It combines the capabilities of tools like IDA Pro, Ghidra, Binary Ninja, x64dbg, ImHex, and Cheat Engine into a single, unified application — completely free and open source.

No Java. No Electron. No Python wrappers around CLI tools. Just fast, native C++ with a modern Qt interface.

---

## Features

### Disassembler & Analysis Engine
- **Multi-architecture disassembly** — x86, x86-64, ARM, ARM64 via Capstone
- **Multi-threaded recursive descent** — parallel disassembly across all CPU cores
- **Multi-format support** — PE (32/64), ELF (32/64), Mach-O (32/64/FAT/Universal)
- **Automatic function discovery** — entry points, exports, pattern scanning, vtable scanning, code pointers, tail call detection, jump table resolution
- **Control Flow Graph** — interactive graph view with BFS layered layout, minimap, search, PNG export
- **Cross-references** — bidirectional xref tracking with color-coded types (call/jump/data)
- **RTTI parsing** — C++ class hierarchy recovery from `type_info` and vtable structures
- **Demangling** — C++ (`_Z`), Rust (`_R` v0 + legacy), Go, Swift (`$s`), D lang
- **Non-returning function detection** — iterative propagation with 22+ known signatures
- **SEH/Exception parsing** — `.pdata` RUNTIME_FUNCTION + UNWIND_INFO chain following
- **Auto-comments** — 70+ libc functions, 35+ Windows APIs, syscall annotations, known constants
- **Packer/Compiler detection** — Rich Header parsing, section name heuristics, entropy analysis, `.comment`/`.note` section parsing
- **FLIRT-style signature matching** — pattern-based function identification
- **Stack variable recovery** — automatic local/argument naming from frame analysis
- **Operand formatting** — hex, decimal, octal, binary, char, symbolic offset display

### Decompiler
- **Full decompilation pipeline** — disassembly → IR lifting → optimization → C output
- **SSA-based IR** — proper SSA form with phi nodes
- **Optimization passes** — dead code elimination, copy propagation, constant propagation, constant folding, expression simplification, stack variable recovery, type recovery
- **Type inference** — from usage patterns, known function signatures (System V AMD64 ABI), pointer analysis
- **C-like output** — with syntax highlighting and proper control flow structuring

### Debugger
- **Linux ptrace debugger** — attach/launch with full register control
- **Hardware & software breakpoints** — with conditional expressions
- **Register widget** — GPR, flags, segments, FPU/SSE/AVX with inline editing
- **Stack widget** — call stack with frame navigation
- **Instruction tracing** — ptrace single-step recording with full register snapshots
- **Code coverage** — execution count visualization, drcov/lcov import, HTML report export, coverage diff

### Memory Scanner (Cheat Engine-style)
- **Value scanning** — byte, short, int, long, float, double, string, AOB patterns
- **Scan filters** — exact, greater/less than, changed/unchanged, between range
- **Iterative narrowing** — first scan → next scan → next scan workflow
- **Pointer scanner** — multi-level pointer chain discovery
- **YARA integration** — standalone YARA rule parser + Boyer-Moore-Horspool matcher + rule generator
- **Results list** — with freeze, type change, and live value display

### Hex Editor
- **Dual-pane hex/ASCII** — with synchronized scrolling
- **Binary patching** — patch bytes, NOP out, assemble, with full undo/redo
- **Mini x86-64 assembler** — mov, push, pop, call, jmp, conditional jumps, arithmetic, test/cmp, shifts, and more
- **Data Inspector** — 32 simultaneous type interpretations (integers, floats, timestamps, GUID, IPv4, RGB...)
- **Binary templates** — ImHex/010 Editor-style pattern language with built-in PE, ELF, ZIP, PNG templates
- **Byte histogram** — frequency distribution with entropy, chi-squared, compression ratio analysis
- **Hash panel** — CRC32, Adler-32, MD5, SHA-1, SHA-256, SHA-512, xxHash32, xxHash64
- **Entropy map** — visual entropy heatmap across binary

### Data Processor
- **Node-based visual pipeline** — drag-and-drop byte transformation graphs
- **38 node types** — input, transform (XOR, shift, rotate), crypto (RC4, base64), compress (zlib), hash, string operations, math
- **Save/load pipelines** — reusable transformation chains as JSON

### Network Analysis
- **Packet capture** — raw socket sniffing with BPF filters
- **Protocol dissectors** — HTTP, DNS, TLS, TCP, UDP, ICMP with deep parsing
- **Hex packet view** — with protocol-layer coloring
- **Connection tracking** — TCP stream reassembly and session analysis

### Web Security
- **Intercepting proxy** — HTTP/HTTPS man-in-the-middle with on-the-fly certificate generation
- **Request/response editor** — modify traffic in transit
- **Repeater** — resend and modify requests
- **Scanner** — automated vulnerability detection

### Anti-Detect Browser
- **Chromium-based** — Qt WebEngine with fingerprint spoofing
- **JavaScript injection** — console hooks, XHR/fetch/WebSocket interception
- **Profile management** — isolated browser profiles
- **User script support** — Greasemonkey-compatible script injection

### Additional Tools
- **Binary diffing** — side-by-side function comparison with similarity scoring
- **Process dumper** — memory dump with import reconstruction
- **PE unpacker** — automatic unpacking with IAT rebuilding and entropy analysis
- **Structure editor** — visual C struct/union editor with nested types
- **Symbol management** — import/export symbols, PDB-lite support
- **Call graph** — interactive function call graph visualization
- **Bookmark manager** — categorized, color-coded address bookmarks with import/export
- **Memory map** — visual address space layout with density overlays
- **Project system** — save/load analysis state with full database serialization

### Scripting & Extensibility
- **Lua scripting engine** — full API access to analysis database, debugger, scanner
- **Plugin system** — C++ plugin API with `fidra_create_module` / `fidra_plugin_info` exports
- **MCP integration** — 300+ AI-powered tools via Model Context Protocol
- **Headless mode** — command-line analysis with JSON output

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Fidra Application                     │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│  Disasm  │ Debugger │ Scanner  │ Decompiler│  Network   │
│  Module  │  Module  │  Module  │  Module   │  Module    │
├──────────┼──────────┼──────────┼──────────┼─────────────┤
│ CFG View │ Register │ Value    │ IR Lift  │ Dissector   │
│ Hex View │ Stack    │ Pointer  │ SSA Opt  │ Proxy       │
│ Xrefs    │ Trace    │ YARA     │ Type Rec │ Repeater    │
│ Imports  │ Coverage │ AOB Scan │ C Output │ WebSocket   │
│ Segments │ Breakpts │ Results  │          │             │
│ Patches  │          │          │          │             │
│ DataProc │          │          │          │             │
│ Templates│          │          │          │             │
├──────────┴──────────┴──────────┴──────────┴─────────────┤
│              Analysis Database (Thread-Safe)             │
│         QReadWriteLock + QMap-based storage              │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│ Unpacker │ Browser  │  WebSec  │   MCP    │  Scripting  │
│  Module  │  Module  │  Module  │  Module  │   Module    │
├──────────┼──────────┼──────────┼──────────┼─────────────┤
│ PE Parse │ Profiles │ Intercpt │ 300+Tools│ Lua Engine  │
│ IAT Fix  │ JS Inject│ Scanner  │ AI Agent │ Plugin API  │
│ Entropy  │ Spoof    │ Repeater │ Protocol │ Hot Reload  │
├──────────┴──────────┴──────────┴──────────┴─────────────┤
│            Core: Application, Theme, Undo, Logging       │
│            Qt 6.4+ / C++20 / Capstone / LIEF            │
└─────────────────────────────────────────────────────────┘
```

### Module System

Every feature is an `IModule` — a self-contained unit with its own widgets, dock panels, menus, and toolbar actions. Modules communicate through the `AnalysisDatabase` and Qt signals.

```
233 source files  •  75,000+ lines of C++  •  23 modules
```

---

## Building

### Dependencies

```bash
# Ubuntu/Debian
sudo apt install build-essential cmake qt6-base-dev qt6-base-dev-tools \
    libqt6opengl6-dev qt6-webengine-dev libcapstone-dev pkg-config

# Fedora
sudo dnf install cmake gcc-c++ qt6-qtbase-devel qt6-qtwebengine-devel \
    capstone-devel pkg-config

# Arch
sudo pacman -S cmake qt6-base qt6-webengine capstone pkgconf
```

LIEF is fetched automatically via CMake FetchContent.

### Build

```bash
git clone https://github.com/user/fidra.git
cd fidra
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Build without WebEngine (lighter)

```bash
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_DISABLE_FIND_PACKAGE_Qt6WebEngineWidgets=TRUE
```

### Run

```bash
./Fidra                          # Launch GUI
./Fidra /path/to/binary          # Open binary directly
./Fidra --headless binary.exe    # Headless analysis (JSON output)
```

---

## Usage

### Quick Start

1. **File → Open** or drag-and-drop a binary
2. Analysis runs automatically — progress shown in status bar
3. Navigate: double-click functions, xrefs, or press **G** to go to address
4. Right-click anything for context menu (rename, retype, patch, comment)
5. **Ctrl+Z / Ctrl+Y** — full undo/redo for all modifications

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `G` | Go to address |
| `N` | Rename symbol |
| `;` | Add comment |
| `X` | Show xrefs |
| `H` | Format as hex |
| `D` | Format as decimal |
| `O` | Format as octal |
| `B` | Format as binary |
| `Space` | Toggle disasm / graph view |
| `Ctrl+F` | Search |
| `Ctrl+Z` | Undo |
| `Ctrl+Y` | Redo |
| `F5` | Decompile function |
| `F7` | Step into (debugger) |
| `F8` | Step over (debugger) |
| `F9` | Continue (debugger) |
| `F2` | Toggle breakpoint |

---

## Scripting

Fidra embeds a Lua scripting engine with full access to the analysis database:

```lua
-- List all functions
local Funcs = fidra.functions()
for i, F in ipairs(Funcs) do
    print(string.format("0x%X  %s", F.address, F.name))
end

-- Read memory
local Addr = 0x400000
print(string.format("u32: %d", fidra.read_u32(Addr)))

-- Pattern scan
local Results = fidra.scan_pattern("48 89 5C 24 ?? 48 89 74 24 ??")
for _, R in ipairs(Results) do
    print(string.format("Found at 0x%X", R))
end

-- Disassemble
local Instrs = fidra.disasm(0x400000, 20)
for _, I in ipairs(Instrs) do
    print(string.format("0x%X  %s %s", I.address, I.mnemonic, I.operands))
end
```

### Plugin Development

```cpp
#include <fidra/IModule.h>
#include <fidra/IPlugin.h>

class MyModule : public Fidra::IModule {
    // Implement your module...
};

extern "C" {
    Fidra::IModule* fidra_create_module(Fidra::ICore* Core) {
        return new MyModule(Core);
    }
    const char* fidra_plugin_info() {
        return "My Plugin|1.0|Author|Description";
    }
}
```

Place compiled `.so` in `~/.fidra/plugins/` or `/usr/lib/fidra/plugins/`.

---

## Project Structure

```
fidra/
├── include/fidra/       # Public headers (IModule, ICore, IPlugin, Types)
├── src/
│   ├── core/            # Application shell, theme, undo/redo, logging
│   ├── analysis/        # Binary loading, disassembly, analysis passes
│   ├── disasm/          # Disasm view, hex editor, CFG, patches, templates
│   ├── decompiler/      # IR lifter, SSA optimizer, C code emitter
│   ├── debugger/        # ptrace debugger, trace recording, coverage
│   ├── scanner/         # Value scanner, pointer scanner, YARA engine
│   ├── unpacker/        # PE parser, IAT rebuilder, entropy widget
│   ├── network/         # Packet capture, protocol dissectors
│   ├── websec/          # Intercepting proxy, vulnerability scanner
│   ├── browser/         # Anti-detect browser, JS injection
│   ├── mcp/             # Model Context Protocol AI integration
│   ├── scripting/       # Lua scripting engine
│   ├── plugin/          # Plugin loader and manager
│   ├── symbols/         # Symbol import/export
│   ├── callgraph/       # Call graph visualization
│   ├── bindiff/         # Binary diffing
│   ├── diff/            # General diff utilities
│   ├── dumper/          # Process memory dumper
│   ├── structeditor/    # Structure/union editor
│   ├── project/         # Project save/load
│   ├── driver/          # Kernel driver interface
│   └── typeeditor/      # Type system editor
├── CMakeLists.txt       # Root build configuration
├── LICENSE              # GPLv3
└── README.md
```

---

## Comparison

| Feature | Fidra | IDA Pro | Ghidra | Binary Ninja | x64dbg |
|---------|:-----:|:-------:|:------:|:------------:|:------:|
| Price | **Free** | $1,800+ | Free | $300+ | Free |
| License | **GPLv3** | Proprietary | Apache 2.0 | Proprietary | GPLv3 |
| Disassembler | Yes | Yes | Yes | Yes | Yes |
| Decompiler | Yes | Yes | Yes | Yes | No |
| Debugger | Yes | Yes | Limited | No | Yes |
| Memory Scanner | Yes | No | No | No | Plugin |
| Hex Editor | Yes | Minimal | Minimal | Minimal | Yes |
| Binary Templates | Yes | No | No | No | No |
| Data Processor | Yes | No | No | No | No |
| Network Analysis | Yes | No | No | No | No |
| Web Proxy | Yes | No | No | No | No |
| YARA Scanner | Yes | Plugin | Plugin | Plugin | Plugin |
| Scripting | Lua | IDC/Python | Java/Python | Python | Plugin |
| AI Integration | MCP | Plugin | Plugin | Plugin | No |
| Binary Patching | Yes | Yes | Yes | Yes | Yes |
| Trace Recording | Yes | Trace | No | No | Yes |
| Code Coverage | Yes | Lumina | Plugin | Plugin | Plugin |
| Native Performance | **C++/Qt** | C++/Qt | Java/Swing | C++/Qt | C++ |

---

## Contributing

Contributions welcome! Fidra is a community-driven project.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Areas that need help

- Additional architecture support (MIPS, PowerPC, RISC-V)
- PDB/DWARF debug info parsing
- Symbolic execution (Z3 integration)
- .NET / Java bytecode analysis
- Emulation support (Unicorn Engine)
- UI/UX improvements and themes
- Documentation and tutorials
- Testing on various Linux distributions

---

## License

Fidra is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License v3.0** as published by the Free Software Foundation.

See [LICENSE](LICENSE) for the full license text.

```
Copyright (C) 2024-2026 Fidra Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
```

---

<p align="center">
  <strong>Built with obsession. Free forever.</strong>
</p>
