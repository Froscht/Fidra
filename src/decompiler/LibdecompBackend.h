#pragma once

#include <fidra/Types.h>
#include <QString>

namespace Fidra {

class AnalysisDatabase;

class LibdecompBackend {
public:
    static bool IsAvailable();
    static QString DecompileFunction(const AnalysisDatabase& Db, Address FunctionStart, int OptLevel = 1);
};

}
