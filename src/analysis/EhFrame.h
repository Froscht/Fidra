#pragma once

#include "AnalysisTypes.h"
#include <QList>

namespace Fidra {

struct EhFrameRange {
    Address Start = 0;
    Address End = 0;
};

struct EhFrameInfo {
    bool Found = false;
    int CieCount = 0;
    QList<EhFrameRange> Ranges;  // one per FDE, sorted by Start
};

// Reads the DWARF call-frame info in .eh_frame (ELF, MinGW PE) / __eh_frame
// (Mach-O). Every FDE covers one function or one split-off part (.cold), so
// it gives exact function extents even for stripped binaries.
EhFrameInfo ParseEhFrame(const BinaryInfo& Info);

}
