<p align="center">
  <img src="docs/fidra-banner.png" alt="Fidra" width="800"/>
</p>

<h1 align="center">Fidra</h1>

<p align="center">
  <strong>Open-Source Reverse Engineering IDE for Linux</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#mcp-tools">MCP Tools</a> •
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
- **MCP integration** — [304 AI-powered tools](#mcp-tools) via Model Context Protocol across 10 categories
- **Headless mode** — command-line analysis with JSON output

---

## MCP Tools

Fidra integrates the [Model Context Protocol](https://modelcontextprotocol.io/) with **304 tools** across 10 categories. Any MCP-compatible AI client (Claude, GPT, local LLMs) can connect and use these tools to analyze binaries, debug processes, generate code, and more — all through natural language.

### AI Analysis (35 tools)

| Tool | Description |
|------|-------------|
| `summarize_binary` | Summarize a PE binary: headers, sections, imports, exports, entropy, entry point |
| `summarize_function` | Disassemble function and return metrics: instruction count, calls, branches, stack usage |
| `summarize_module` | Summarize a loaded module: base, size, entry point, import/export count, sections |
| `describe_memory_region` | Describe the memory region containing a given address |
| `suggest_breakpoints` | Analyze function and suggest interesting breakpoint locations (calls, branches, loops) |
| `suggest_next_analysis` | Suggest what to analyze next based on current state |
| `find_interesting_functions` | Find security-relevant imported functions: crypto, network, file I/O, registry, process |
| `find_interesting_strings` | Scan memory for strings containing security-relevant keywords |
| `map_api_usage` | Categorize all imported functions by type: file I/O, network, crypto, memory, process, registry, GUI |
| `identify_library` | Identify statically or dynamically linked libraries by checking import patterns |
| `analyze_data_layout` | Read memory and interpret as a potential struct: find pointers, strings, counters, padding |
| `find_encryption_keys` | Scan memory for high-entropy blocks that might be encryption keys (16/24/32 byte aligned) |
| `analyze_error_handling` | Scan function for error-handling patterns: test eax/cmp eax followed by conditional jump |
| `detect_design_patterns` | Check for software design patterns: singleton, factory, observer by analyzing code/data patterns |
| `find_game_objects` | Scan memory for common game patterns: float arrays (positions), health-like values, pointer arrays |
| `analyze_vtable` | Read vtable at address, resolve entries, disassemble first instructions of each virtual function |
| `map_class_hierarchy` | Follow vtable pointers and RTTI type descriptors to build class hierarchy |
| `estimate_function_complexity` | Calculate cyclomatic complexity and other metrics for a function |
| `find_similar_functions` | Find functions with similar opcode sequences to the given function |
| `trace_data_flow` | Trace data flow: find where values at an address are read from and written to |
| `find_magic_numbers` | Scan memory for well-known constants: PI, file signatures, hash init values |
| `detect_backdoors` | Check for suspicious patterns: hardcoded IPs, base64 commands, hidden socket creation |
| `analyze_authentication` | Find functions that reference password/login/auth strings and analyze their structure |
| `analyze_network_usage` | Find imported network/socket functions and identify protocols used |
| `get_binary_metadata` | Comprehensive binary metadata: architecture, compiler, linker, timestamps, subsystem, checksums |
| `get_import_hash` | Calculate imphash (MD5 of sorted DLL.function import names) — standard malware fingerprint |
| `get_section_hashes` | Calculate MD5 and SHA256 hashes for each PE section |
| `find_packed_sections` | Identify sections with high entropy (>7.0), unusual names, or zero raw size indicating packing |
| `analyze_resources` | Parse PE resources and categorize by type |
| `get_compilation_timestamp` | Read PE TimeDateStamp and convert to human-readable datetime |
| `detect_debug_artifacts` | Look for debug strings, PDB paths, assert macros, and debug-build indicators |
| `find_config_data` | Scan for configuration-like data: IP addresses, URLs, file paths, registry keys |
| `analyze_stack_usage` | Analyze function stack frame: size from sub rsp,N, local variable count estimate |
| `get_function_args` | Analyze function to determine number of arguments by checking register usage (rcx/rdx/r8/r9) |
| `get_calling_convention` | Analyze function to determine calling convention by checking register usage and stack cleanup |

### Binary Analysis (56 tools)

| Tool | Description |
|------|-------------|
| `analyze_function` | Disassemble and analyze a function: call targets, branches, stack usage |
| `rename_function` | Assign a name to a function address for future reference |
| `rename_variable` | Assign a name to a variable address for future reference |
| `detect_crypto` | Scan memory for known cryptographic constants (AES S-box, SHA256, MD5, CRC32, RC4) |
| `detect_compiler` | Detect the compiler and linker used by examining PE headers and Rich header |
| `find_vulnerabilities` | Scan code for dangerous patterns: unsafe function calls, stack overflows, format strings |
| `decompile_function` | Generate pseudocode from disassembled instructions |
| `explain_assembly` | Disassemble instructions and return natural language explanations |
| `find_strings` | Scan a memory region for printable ASCII strings with minimum length |
| `find_strings_regex` | Search strings in a memory region matching a regex pattern |
| `classify_binary` | Classify a binary by checking for packer signatures, entropy, suspicious characteristics |
| `diff_regions` | Compare two memory regions byte by byte and return differences |
| `find_vtables` | Scan memory for C++ vtable patterns (consecutive valid function pointers) |
| `recover_struct` | Read memory and suggest struct field layout based on alignment and value heuristics |
| `detect_obfuscation` | Analyze code for obfuscation: junk instructions, opaque predicates, control flow flattening |
| `find_antidbg` | Scan code for anti-debugging techniques (API calls, timing checks, int 2d) |
| `get_call_graph` | Disassemble a function and extract all CALL targets to build a call graph |
| `get_xrefs_to` | Scan code for cross-references to a target address (calls, lea, mov) |
| `get_xrefs_from` | Disassemble at address and list all addresses referenced by those instructions |
| `find_functions` | Scan memory for function prologues (push rbp; mov rbp,rsp and similar) |
| `get_function_bounds` | Find the start and end of a function by scanning for prologue and return instructions |
| `get_basic_blocks` | Split a function into basic blocks at branch and call boundaries |
| `find_switch_tables` | Look for indirect jump patterns indicating switch/case jump tables |
| `find_loop_structures` | Detect backward jumps in code indicating loop constructs |
| `get_data_refs` | Find RIP-relative data references in code (LEA, MOV with RIP-relative addressing) |
| `find_string_refs` | Find code locations that reference a given string |
| `get_section_info` | Parse PE section headers and return detailed section information |
| `get_entry_point` | Get the entry point address from the PE optional header |
| `get_pe_info` | Full PE header parsing: DOS header, COFF header, Optional header fields |
| `find_constants` | Scan disassembly for interesting immediate values and constants |
| `detect_packing` | Check for packing indicators: section entropy, unusual names, small imports |
| `get_entropy` | Calculate Shannon entropy of a memory region (0-8 scale) |
| `find_code_caves` | Find regions of consecutive zero or INT3 bytes in code sections |
| `get_relocations` | Parse the PE relocation directory |
| `find_tls_callbacks` | Parse the TLS directory for callback function addresses |
| `get_debug_directory` | Parse the PE debug directory |
| `find_exception_handlers` | Parse .pdata section for exception handler entries (x64) |
| `get_rich_header` | Parse and decode the Rich header from a PE file |
| `detect_overlay` | Check if PE has overlay data beyond the last section |
| `find_resources` | List PE resource entries from the resource directory |
| `extract_resource` | Read raw data from a specific PE resource |
| `get_certificates` | Parse the PE certificate/security directory |
| `find_delay_imports` | Parse the delay import directory of a PE |
| `get_bound_imports` | Parse the bound import directory of a PE |
| `analyze_control_flow` | Analyze control flow patterns in disassembled code |
| `find_dead_code` | Find unreachable code after unconditional jumps or returns |
| `detect_api_hashing` | Scan for API hashing patterns: ROR/ROL + ADD/XOR loops typical of shellcode |
| `resolve_api_hash` | Resolve an API hash to a function name using known hash databases |
| `find_syscalls` | Find direct syscall patterns (mov r10,rcx; mov eax,N; syscall) |
| `get_instruction_detail` | Detailed instruction info: operands, reads, writes, flags |
| `find_gadgets` | Find ROP gadgets: short instruction sequences ending in RET |
| `find_jmp_chains` | Follow JMP instructions to find the final target address |
| `get_pe_checksum` | Calculate the PE checksum for the module in memory |
| `validate_pe` | Validate PE structure integrity: magic numbers, section alignment, header sizes |
| `find_mutations` | Find potential self-modifying code patterns (writes to executable memory) |
| `get_disassembly` | Extended disassembly with annotations: resolved call targets, string references, function names |

### Code Generation (28 tools)

| Tool | Description |
|------|-------------|
| `generate_inline_hook` | Generate x64 inline hook C++ code with trampoline, backup, and unhook |
| `generate_iat_hook` | Generate IAT hook C++ code that walks PEB, finds module, replaces import entry |
| `generate_vmt_hook` | Generate VMT (virtual method table) hook C++ code |
| `generate_detour` | Generate Microsoft Detours-style hook code |
| `generate_trampoline` | Generate trampoline hook with stolen bytes and jump-back stub |
| `generate_ida_signature` | Read bytes at address, generate IDA-style signature with wildcard relative offsets |
| `generate_yara_rule` | Read bytes at address, generate a YARA rule |
| `generate_struct_def` | Generate C++ struct definition with proper padding from field list |
| `generate_class_def` | Generate C++ class definition with virtual functions and member fields |
| `generate_sdk_header` | Generate SDK header with function pointer typedefs from module exports |
| `generate_ida_script` | Generate IDA Python script for common actions |
| `generate_ghidra_script` | Generate Ghidra script (Java) for common RE actions |
| `generate_frida_script` | Generate Frida JavaScript hook script |
| `generate_driver_template` | Generate complete KMDF/WDM kernel driver template |
| `generate_ioctl_handler` | Generate IOCTL dispatch handler with switch-case for custom codes |
| `generate_shellcode_x64` | Generate x64 shellcode hex bytes for common payloads |
| `generate_dll_template` | Generate DllMain template with thread creation |
| `generate_inject_code` | Generate DLL injection code using CreateRemoteThread + LoadLibraryA |
| `generate_pattern_scan` | Generate C++ pattern scan function with wildcard support |
| `generate_enum_def` | Generate C++ enum definition from name/value pairs |
| `generate_function_typedef` | Generate C++ function pointer typedef |
| `generate_vtable_struct` | Generate vtable struct with function pointer array and call macros |
| `generate_syscall_stub` | Generate x64 direct syscall stub that bypasses ntdll |
| `generate_pe_parser` | Generate C++ code that parses PE headers from a buffer |
| `generate_exception_handler` | Generate VEH/SEH exception handler code |
| `generate_thread_hijack` | Generate thread hijacking injection code |
| `generate_manual_map` | Generate manual mapping DLL loader outline |
| `generate_process_hollow` | Generate process hollowing code |

### Debugger (25 tools)

| Tool | Description |
|------|-------------|
| `debug_status` | Get current debugger status: module availability, process attached, debug state |
| `debug_run` | Continue execution of the debugged process |
| `debug_pause` | Pause/break execution of the debugged process |
| `step_into` | Single-step into the next instruction, following calls |
| `step_over` | Step over the next instruction, not entering calls |
| `step_out` | Run until the current function returns |
| `run_to_address` | Set temporary breakpoint at address and continue until hit |
| `set_hw_breakpoint` | Set hardware breakpoint using debug registers (DR0-DR3): execute, write, read/write |
| `set_memory_breakpoint` | Set memory access breakpoint using PAGE_GUARD |
| `list_breakpoints` | List all breakpoints with type, address, and enabled status |
| `enable_breakpoint` | Enable a previously disabled breakpoint |
| `disable_breakpoint` | Disable a breakpoint without removing it |
| `set_conditional_breakpoint` | Set breakpoint that triggers only when a register matches a value |
| `get_register` | Read a single CPU register by name |
| `set_register` | Set a CPU register value |
| `get_all_registers` | Get all general-purpose x64 registers (RAX-R15, RIP, RSP, RBP, RFLAGS) |
| `get_flags` | Parse RFLAGS into individual CPU flags (CF, ZF, SF, OF, PF, AF, DF, IF, TF) |
| `get_xmm_registers` | Get XMM0-XMM15 SSE register values |
| `get_stack_values` | Read N qword values from RSP with string/code reference detection |
| `get_call_stack` | Walk the call stack by following the RBP chain |
| `disassemble_at_rip` | Disassemble N instructions at current instruction pointer |
| `get_exception_info` | Get last debug exception information |
| `trace_instructions` | Disassemble next N instructions with natural language explanations |
| `evaluate_condition` | Evaluate condition expressions against register values (e.g. `rax == 0`) |
| `get_return_value` | Read RAX (return value) and interpret in common formats |

### Encoding & Crypto (28 tools)

| Tool | Description |
|------|-------------|
| `encode_base64` | Base64 encode a string |
| `decode_base64` | Base64 decode — returns decoded text and hex |
| `encode_base64url` | Base64url encode (URL-safe, no padding) |
| `decode_base64url` | Decode base64url encoded string |
| `encode_hex` | Hex encode a string |
| `decode_hex` | Decode hex string to text |
| `encode_url` | URL-encode (percent encode) a string |
| `decode_url` | URL-decode (percent decode) a string |
| `encode_html` | HTML entity encode special characters |
| `decode_html` | Decode HTML entities |
| `hash_md5` | Calculate MD5 hash |
| `hash_sha1` | Calculate SHA1 hash |
| `hash_sha256` | Calculate SHA256 hash |
| `hash_sha512` | Calculate SHA512 hash |
| `hash_crc32` | Calculate CRC32 checksum |
| `hash_all` | Calculate all hashes at once (MD5, SHA1, SHA256, SHA512, CRC32) |
| `xor_encrypt` | XOR data with a repeating key (hex inputs) |
| `xor_single_byte` | XOR all bytes with a single byte key |
| `xor_bruteforce` | Bruteforce single-byte XOR — top 10 keys producing most printable ASCII |
| `rot13` | ROT13 encode/decode (self-inverse) |
| `rot_n` | ROT-N cipher with configurable shift |
| `caesar_bruteforce` | Try all 26 Caesar cipher shifts |
| `rc4_crypt` | RC4 encrypt/decrypt (symmetric) |
| `convert_endian` | Swap byte order (reverse bytes) of hex data |
| `int_to_float` | Reinterpret 4-byte hex as IEEE 754 float |
| `float_to_int` | Convert float to 4-byte hex representation |
| `int_to_double` | Reinterpret 8-byte hex as IEEE 754 double |
| `double_to_int` | Convert double to 8-byte hex representation |

### File Operations (25 tools)

| Tool | Description |
|------|-------------|
| `open_binary_file` | Open binary file — returns size, first 64 bytes, detected type |
| `get_file_info` | File metadata: path, size, permissions, created/modified dates |
| `calculate_file_hash` | Calculate MD5, SHA1, and SHA256 hashes of a file |
| `calculate_hash` | Hash arbitrary hex data (md5, sha1, sha256, sha512) |
| `check_pe_signature` | Verify MZ and PE signatures |
| `extract_strings_from_file` | Extract printable ASCII strings from file |
| `extract_unicode_strings_from_file` | Extract UTF-16LE strings from file |
| `patch_file` | Write hex bytes at a given offset in file |
| `create_file_backup` | Create .bak backup copy of a file |
| `compare_files` | Compare two files byte by byte |
| `get_file_entropy` | Calculate Shannon entropy of entire file (0-8) |
| `get_file_entropy_map` | Entropy per block across file — array of {offset, entropy} |
| `detect_file_type` | Detect file type by magic bytes |
| `hex_dump_file` | Hex dump with offset, hex, and ASCII columns |
| `read_file_bytes` | Read N bytes from file at offset as hex string |
| `write_file_bytes` | Write hex-encoded bytes to file at offset |
| `get_pe_sections_from_file` | Parse PE section headers from file |
| `get_pe_imports_from_file` | Parse PE import table from file |
| `get_pe_exports_from_file` | Parse PE export table from file |
| `get_pe_resources_from_file` | Parse PE resource directory from file |
| `get_pe_version_info` | Parse VS_VERSION_INFO from PE resources |
| `get_elf_info` | Parse ELF header: class, endianness, type, machine, entry point |
| `get_elf_sections` | Parse ELF section headers |
| `search_file_bytes` | Search for hex byte pattern in file |
| `file_size` | Get file size in bytes |

### Memory (32 tools)

| Tool | Description |
|------|-------------|
| `read_memory_typed` | Read memory as typed value (int8-uint64, float, double, pointer) |
| `write_memory_typed` | Write a typed value to memory |
| `read_pointer` | Read pointer-sized value (4/8 bytes) at address |
| `read_unicode_string` | Read null-terminated UTF-16LE string from address |
| `write_string` | Write ASCII string to memory (with null terminator) |
| `write_unicode_string` | Write UTF-16LE string to memory (with null terminator) |
| `find_pointer_chain` | Resolve multi-level pointer chain: base → offset → read → offset → ... |
| `memory_compare` | Compare two memory regions byte-by-byte |
| `aob_generate` | Generate Array of Bytes pattern from memory at address |
| `dump_region` | Read entire memory region as hex string |
| `find_pattern_in_module` | Scan for byte pattern within a specific module |
| `create_snapshot` | Create named memory snapshot for comparison or restoration |
| `restore_snapshot` | Write snapshot back to original memory location |
| `compare_snapshots` | Compare two snapshots — byte-level differences |
| `list_snapshots` | List all stored memory snapshots |
| `delete_snapshot` | Delete a named snapshot |
| `patch_bytes` | Write bytes with backup for undo |
| `unpatch_bytes` | Restore original bytes from previous patch |
| `list_patches` | List all active undoable patches |
| `nop_instruction` | NOP out instruction at address (auto-detects length) |
| `nop_range` | NOP out N bytes at address |
| `freeze_value` | Register address+value to be written repeatedly |
| `unfreeze_value` | Remove frozen value registration |
| `list_frozen` | List all frozen value registrations |
| `get_page_info` | Get memory page protection info for address |
| `memory_fill` | Fill N bytes at address with a single byte |
| `memory_copy` | Copy N bytes from source to destination in target process |
| `get_memory_stats` | Summary statistics about process memory layout |
| `find_module_base` | Find base address of a module by name |
| `get_module_size` | Get total mapped size of a module |
| `read_struct_fields` | Read multiple typed fields from base address with offsets |
| `write_struct_field` | Write typed value at base_address + offset |

### Network (30 tools)

| Tool | Description |
|------|-------------|
| `get_network_interfaces` | List interfaces with name, MAC, IP addresses, flags |
| `get_connections` | List active TCP connections (local/remote address, state) |
| `resolve_hostname` | Resolve hostname to IP addresses via DNS |
| `decode_jwt` | Decode JWT token — base64url-decode header and payload |
| `encode_jwt` | Encode unsigned JWT from header and payload JSON |
| `generate_curl` | Generate curl command from method, URL, headers, body |
| `generate_wget` | Generate wget command from method, URL, headers, body |
| `parse_url` | Parse URL into components: scheme, host, port, path, query, fragment |
| `build_url` | Build URL from components |
| `decode_base64_payload` | Detect and decode base64 strings within text |
| `extract_urls` | Extract all URLs from text via regex |
| `extract_emails` | Extract all email addresses from text via regex |
| `extract_ip_addresses` | Extract all IPv4 and IPv6 addresses from text |
| `parse_http_request` | Parse raw HTTP request into method, path, version, headers, body |
| `parse_http_response` | Parse raw HTTP response into status, reason, headers, body |
| `build_http_request` | Build raw HTTP request from components |
| `build_http_response` | Build raw HTTP response from components |
| `analyze_headers` | Analyze HTTP headers for security issues (missing CSP, HSTS, X-Frame-Options) |
| `detect_waf` | Detect WAF from HTTP response headers |
| `parse_cookie` | Parse Set-Cookie header into name, value, domain, path, flags |
| `build_cookie` | Build Cookie header from name-value pairs |
| `calculate_content_length` | Calculate byte length of request/response body |
| `url_encode_params` | URL-encode key-value parameters into query string |
| `url_decode_params` | URL-decode query string into key-value pairs |
| `parse_multipart` | Parse multipart/form-data body into parts |
| `generate_boundary` | Generate random multipart boundary string |
| `format_json` | Pretty-print JSON with indentation |
| `minify_json` | Minify JSON by removing whitespace |
| `validate_json` | Validate JSON string — returns validity and parse errors |
| `compare_json` | Compare two JSON objects — added, removed, changed keys |

### Scripting & Automation (25 tools)

| Tool | Description |
|------|-------------|
| `create_bookmark` | Create named bookmark at address for quick navigation |
| `list_bookmarks` | List all saved bookmarks |
| `delete_bookmark` | Delete a bookmark by name |
| `goto_bookmark` | Look up bookmark by name and return its address |
| `add_label` | Add label/name to an address |
| `get_label` | Get label assigned to an address |
| `list_labels` | List all labels with addresses |
| `delete_label` | Remove label from an address |
| `create_macro` | Create named sequence of tool calls for automation |
| `run_macro` | Execute stored macro by name |
| `list_macros` | List all macros with names and descriptions |
| `delete_macro` | Delete a stored macro |
| `export_to_json` | Export data as formatted JSON (optionally to file) |
| `export_to_csv` | Export array of objects as CSV (optionally to file) |
| `export_function_list` | Scan memory for function prologues and export list |
| `export_string_list` | Scan memory for strings and export them |
| `export_module_list` | Export loaded modules as JSON |
| `import_labels` | Import labels from JSON file |
| `import_bookmarks` | Import bookmarks from JSON file |
| `run_tool_sequence` | Run sequence of tool calls inline without storing as macro |
| `log_to_file` | Append message to log file |
| `read_from_file` | Read file contents as string |
| `write_to_file` | Write string content to file |
| `get_tool_list` | List all registered MCP tools with descriptions |
| `get_tool_info` | Get detailed tool info including input schema |

### System & Utility (20 tools)

| Tool | Description |
|------|-------------|
| `get_system_info` | Comprehensive system info: OS, CPU, memory, kernel version |
| `get_os_version` | Detailed OS version and distribution info |
| `get_cpu_info` | CPU details: model, cores, frequency, features |
| `get_memory_usage` | System memory: total, available, free, buffers, cached, swap |
| `get_process_info` | Detailed process info by PID |
| `get_cpu_usage` | CPU usage statistics including per-core |
| `get_loaded_drivers` | List loaded kernel modules |
| `get_environment` | Environment variables of Fidra or specific process |
| `get_process_maps` | Full memory map from /proc/PID/maps |
| `get_process_threads` | List all threads of a process |
| `get_io_counters` | I/O statistics: read/write bytes, syscall counts |
| `is_process_64bit` | Check if process is 64-bit via ELF header |
| `get_process_times` | CPU time: user, system, start time, uptime |
| `get_command_line` | Full command line of a process |
| `get_current_directory` | Current working directory of a process |
| `get_uptime` | System uptime and idle time |
| `get_disk_usage` | Disk space for mounted filesystems |
| `get_network_interfaces` | Network interfaces with addresses |
| `get_fidra_info` | Fidra version, build info, loaded modules, tool count |
| `list_all_tools` | List all MCP tools with filtering by name or keyword |

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
