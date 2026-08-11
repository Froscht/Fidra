#pragma once

#include <fidra/Types.h>
#include <QString>

namespace Fidra {

struct SymbolInfo {
    Address Addr;
    QString Name;
    QString Module;
    QString Source;
    int Size;
};

}
