#pragma once

#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>

namespace Fidra {

struct FuncParam {
    QString Type;  // C type text, e.g. "const char*"
    QString Name;
};

struct FuncPrototype {
    QString Name;
    QString ReturnType;
    QList<FuncParam> Params;
    bool Variadic = false;
    bool NoReturn = false;

    bool ReturnsVoid() const { return ReturnType == "void"; }
    // printf-style: index of the format-string parameter, or -1.
    int FormatParam() const;
    QString ToString() const;
};

// Function prototypes for library/API calls (the idea behind IDA's .til
// files). Built-in headers cover libc/POSIX and core WinAPI; extra headers
// are read from <GenericDataLocation>/Fidra/types/*.h and $FIDRA_TYPE_PATH.
//
// Header syntax: one C prototype per line ending in ';'. A leading
// "noreturn" marks a function that never returns. A leading "AW" registers
// the ANSI and wide variants (NameA / NameW) with LPCTSTR / LPTSTR / TCHAR
// replaced accordingly. Function-pointer parameters are written as void*.
class TypeLibrary {
public:
    // Built-in plus user headers, loaded once. Thread-safe.
    static const TypeLibrary& Instance();

    // Looks the name up as is, then with import decorations removed
    // (__imp_, @plt, @N, DLL!, __isoc99_, leading underscore, ...).
    const FuncPrototype* Find(const QString& Name) const;

    // Adds the declarations in Text; returns how many were added.
    int ParseDeclarations(const QString& Text);
    int Count() const { return static_cast<int>(Protos.size()); }

    static QStringList UserDirectories();

private:
    void Add(const FuncPrototype& Proto);
    QHash<QString, FuncPrototype> Protos;
};

}
