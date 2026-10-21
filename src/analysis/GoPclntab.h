#pragma once

#include "AnalysisTypes.h"
#include <QList>
#include <QString>

namespace Fidra {

struct GoFunctionEntry {
    Address Entry = 0;
    QString Name;
};

struct GoPclntabInfo {
    bool Found = false;
    QString Version;   // "1.2", "1.16", "1.18", "1.20+"
    Address TextEnd = 0;  // end of Go code (functab's sentinel entry)
    QList<GoFunctionEntry> Functions;
};

// Reads the Go runtime's function table (pclntab). It survives `strip`, so
// it yields exact function entries and full symbol names for any Go binary.
GoPclntabInfo ParseGoPclntab(const BinaryInfo& Info);

}
