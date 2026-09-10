#pragma once
#include <fidra/ida_shim.h>
#include <string>
#include <cstdint>
#include <unordered_map>
#include <vector>
#include <mutex>

// Minimal netnode shim — persistent-KV lookalike backed by in-memory maps.
// Real IDA netnodes persist to the .idb; Fidra ships this as compile-only.

class netnode {
public:
    netnode() = default;
    netnode(const char* name, size_t /*name_len*/ = 0, bool /*create*/ = false) : Name_(name ? name : "") {}
    netnode(nodeidx_t idx) : Idx_(idx) {}

    bool create(const char* name = nullptr) { if (name) Name_ = name; return true; }
    bool kill() { return true; }
    bool exist() const { return true; }
    void set_name(const char* name) { Name_ = name ? name : ""; }
    const std::string& get_name() const { return Name_; }

    // Value tag storage
    void set(const void* /*value*/, size_t /*length*/ = 0, uint8_t /*tag*/ = 'S') {}
    ssize_t supstr(char* /*buf*/, size_t /*bufsize*/, nodeidx_t /*idx*/, uint8_t /*tag*/ = 'S') const { return 0; }
    ssize_t supset(nodeidx_t /*idx*/, const char* /*str*/, size_t /*len*/ = 0, uint8_t /*tag*/ = 'S') { return 0; }
    bool supdel(nodeidx_t /*idx*/, uint8_t /*tag*/ = 'S') { return false; }

    // Alt/sup accessors (numeric)
    uval_t altval(nodeidx_t /*idx*/, uint8_t /*tag*/ = 'A') const { return 0; }
    bool altset(nodeidx_t /*idx*/, uval_t /*v*/, uint8_t /*tag*/ = 'A') { return false; }
    bool altdel(nodeidx_t /*idx*/, uint8_t /*tag*/ = 'A') { return false; }
    nodeidx_t altfirst(uint8_t /*tag*/ = 'A') const { return BADNODE; }
    nodeidx_t altnext(nodeidx_t /*idx*/, uint8_t /*tag*/ = 'A') const { return BADNODE; }

    nodeidx_t supfirst(uint8_t /*tag*/ = 'S') const { return BADNODE; }
    nodeidx_t supnext(nodeidx_t /*idx*/, uint8_t /*tag*/ = 'S') const { return BADNODE; }

    // Blob store
    ssize_t getblob(void* /*buf*/, size_t* /*size*/, nodeidx_t /*idx*/, uint8_t /*tag*/ = 'B') const { return 0; }
    bool setblob(const void* /*buf*/, size_t /*size*/, nodeidx_t /*idx*/, uint8_t /*tag*/ = 'B') { return false; }
    bool delblob(nodeidx_t /*idx*/, uint8_t /*tag*/ = 'B') { return false; }

    operator nodeidx_t() const { return Idx_; }

private:
    std::string Name_;
    nodeidx_t Idx_ = 0;
};

using node = netnode;
