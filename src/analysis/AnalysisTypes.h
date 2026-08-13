#pragma once

#include <fidra/Types.h>
#include <QString>
#include <QByteArray>
#include <QList>
#include <QMap>
#include <QSet>

namespace Fidra {

enum class SegmentType {
    Code,
    Data,
    Bss,
    Import,
    Export,
    Resource,
    Reloc,
    Unknown
};

enum class XrefType {
    CodeCall,
    CodeJump,
    CodeCondJump,
    DataRead,
    DataWrite,
    DataOffset
};

enum class ItemType {
    Unexplored,
    Code,
    Data,
    String,
    WideString,
    Pointer,
    Alignment,
    Function
};

enum class AnalysisState {
    Idle,
    Loading,
    Disassembling,
    FindingFunctions,
    BuildingXrefs,
    FindingStrings,
    AnalyzingFunctions,
    Complete,
    Failed
};

enum class CallingConvention {
    Unknown,
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Win64,
    SysVAmd64
};

struct Segment {
    QString Name;
    Address VirtualAddress;
    size_t VirtualSize;
    size_t RawSize;
    size_t RawOffset;
    uint32_t Characteristics;
    SegmentType Type;
    QByteArray Data;
    bool IsReadable;
    bool IsWritable;
    bool IsExecutable;
};

struct AnalyzedInstruction {
    Address Addr;
    uint8_t Bytes[15];
    uint8_t Size;
    QString Mnemonic;
    QString Operands;
    QString Comment;
    bool IsCall;
    bool IsJump;
    bool IsRet;
    bool IsConditional;
    bool IsNop;
    bool IsPush;
    bool IsPop;
    bool IsIndirectJump;
    bool IsIndirectCall;
    bool IsHalt;
    Address BranchTarget;
    Address MemoryRef;
};

struct BasicBlock {
    Address Start;
    Address End;
    int InstructionCount;
    QList<Address> Successors;
    QList<Address> Predecessors;
    Address ImmDominator = 0;
    bool IsLoopHeader = false;
    int DominanceDepth = 0;
};

struct AnalyzedFunction {
    QString Name;
    QString DemangledName;
    Address Start;
    Address End;
    size_t Size;
    int InstructionCount;
    int BasicBlockCount;
    int StackFrameSize;
    int ArgCount;
    bool IsImported;
    bool IsExported;
    bool IsThunk;
    bool IsNoReturn = false;
    bool HasExceptionHandler = false;
    bool HasTailCalls = false;
    Address ExceptionHandler = 0;
    CallingConvention Convention = CallingConvention::Unknown;
    int LoopCount = 0;
    QList<Address> Callers;
    QList<Address> Callees;
    QList<BasicBlock> Blocks;
};

struct Xref {
    Address From;
    Address To;
    XrefType Type;
};

struct AnalyzedString {
    Address Addr;
    QString Value;
    bool IsWide;
    int Length;
    QList<Address> References;
};

struct ImportEntry {
    QString DllName;
    QString FuncName;
    uint16_t Ordinal;
    Address IatAddress;
    Address ThunkAddress;
    bool IsBound;
};

struct ExportEntry {
    QString Name;
    uint16_t Ordinal;
    Address Addr;
    uint32_t Rva;
    bool IsForwarder;
    QString ForwarderName;
};

struct BinaryInfo {
    QString FilePath;
    QString FileName;
    Architecture Arch;
    Address ImageBase;
    Address EntryPoint;
    size_t ImageSize;
    bool Is64Bit;
    bool IsDll;
    bool IsDriver;
    uint32_t TimeDateStamp;
    uint16_t Subsystem;
    QString LinkerVersion;
    QString Compiler;
    QString Packer;
    bool IsPacked = false;
    QList<Segment> Segments;
    QList<ImportEntry> Imports;
    QList<ExportEntry> Exports;
};

struct AnalysisProgress {
    AnalysisState State;
    int Percentage;
    QString StatusMessage;
    int FunctionsFound;
    int InstructionsDisassembled;
    int StringsFound;
    int XrefsBuilt;
    QString CurrentSection;
    Address CurrentAddress = 0;
    qint64 ElapsedMs = 0;
};

}
