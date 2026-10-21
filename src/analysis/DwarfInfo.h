#pragma once

#include "AnalysisTypes.h"
#include "TypeLibrary.h"
#include <QList>
#include <QString>

namespace Fidra {

struct DebugVariable {
    enum class FrameBase {
        Cfa,              // address = CFA + Offset (CFA = caller's rsp before the call, i.e. entry rsp + 8)
        SpAfterPrologue,  // address = rsp after the prologue + Offset (CodeView/PDB on x64)
        FramePointer,     // address = rbp + Offset, rbp as set up by the prologue (CodeView/PDB)
    };
    QString Name;
    QString Type;
    int64_t CfaOffset = 0;  // the offset, relative to Base
    FrameBase Base = FrameBase::Cfa;
};

struct DebugFunction {
    Address Low = 0;
    Address High = 0;
    QString Name;          // linkage (mangled) name if present, else the source name
    QString SourceName;    // DW_AT_name
    FuncPrototype Proto;   // Proto.Name == Name
    QList<DebugVariable> Locals;  // stack variables with a fixed frame location
};

struct DebugInfo {
    bool Found = false;
    QString Path;          // file the DWARF came from
    QString Error;         // why nothing was loaded (missing, zstd, ...)
    int Units = 0;
    QList<DebugFunction> Functions;  // sorted by Low
    // Named code addresses without extent (PDB public symbols).
    QList<QPair<Address, QString>> Publics;
};

// Locates DWARF for the binary — inside it, via build-id under
// /usr/lib/debug/.build-id and the debuginfod cache, or via .gnu_debuglink —
// and reads every concrete function: extent, name, prototype and stack
// locals. Handles DWARF 2-5 and zlib-compressed sections.
DebugInfo LoadDebugInfo(const BinaryInfo& Info);

// Reads DWARF from one ELF file.
DebugInfo ParseDwarfFile(const QString& Path);

// PE: finds the PDB named in the CodeView debug entry (next to the binary,
// at its recorded path, or in a symbol store from $_NT_SYMBOL_PATH /
// $FIDRA_SYMBOL_PATH) and reads it (PdbInfo.cpp).
DebugInfo LoadPdbInfo(const BinaryInfo& Info);
DebugInfo ParsePdbFile(const QString& PdbPath, Address ImageBase, const QByteArray& ExpectedGuid = {});

}
