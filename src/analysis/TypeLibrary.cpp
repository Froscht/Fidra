#include "TypeLibrary.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QStandardPaths>
#include <cstring>

namespace Fidra {

// TypeLibraryData.cpp
extern const char* const BuiltinTypeHeaders[];
extern const int BuiltinTypeHeaderCount;

namespace {

QString CleanType(QString T) {
    T = T.simplified();
    T.replace(" *", "*");
    T.replace("* ", "*");
    T.replace("*", "* ");
    return T.trimmed();
}

// Splits "const char* name" into type and name. A lone type has no name.
FuncParam SplitParam(const QString& Text, int Index) {
    static const QRegularExpression TrailingIdent(R"(^(.*?[\s\*])([A-Za-z_]\w*)$)");
    static const QStringList TypeWords = {"int", "char", "long", "short", "unsigned", "signed", "void",
                                          "float", "double", "const", "volatile", "struct", "enum"};
    FuncParam P;
    const QString S = Text.simplified();
    const auto M = TrailingIdent.match(S);
    if (M.hasMatch() && !TypeWords.contains(M.captured(2)) && !M.captured(1).trimmed().isEmpty() &&
        M.captured(1).trimmed() != "const" && M.captured(1).trimmed() != "unsigned") {
        P.Type = CleanType(M.captured(1));
        P.Name = M.captured(2);
    } else {
        P.Type = CleanType(S);
        P.Name = QString("a%1").arg(Index + 1);
    }
    return P;
}

bool ParseOne(QString Line, FuncPrototype& Out) {
    Line = Line.trimmed();
    if (Line.endsWith(';')) Line.chop(1);
    const int Open = Line.indexOf('(');
    const int Close = Line.lastIndexOf(')');
    if (Open <= 0 || Close < Open) return false;

    QString Head = Line.left(Open).simplified();
    if (Head.startsWith("noreturn ")) {
        Out.NoReturn = true;
        Head = Head.mid(9).trimmed();
    }
    for (const char* Cc : {"WINAPI ", "__stdcall ", "__cdecl ", "NTAPI ", "APIENTRY ", "extern "})
        Head.replace(Cc, "");
    static const QRegularExpression NameAtEnd(R"(^(.*?[\s\*])([A-Za-z_]\w*)$)");
    const auto M = NameAtEnd.match(Head.simplified());
    if (!M.hasMatch()) return false;
    Out.ReturnType = CleanType(M.captured(1));
    Out.Name = M.captured(2);

    const QString Args = Line.mid(Open + 1, Close - Open - 1).trimmed();
    if (Args.isEmpty() || Args == "void") return true;
    const QStringList Parts = Args.split(',');
    for (int I = 0; I < Parts.size(); ++I) {
        const QString Part = Parts[I].trimmed();
        if (Part == "...") { Out.Variadic = true; continue; }
        Out.Params.append(SplitParam(Part, I));
    }
    return true;
}

QString Narrow(QString S, bool Wide) {
    S.replace("LPCTSTR", Wide ? "LPCWSTR" : "LPCSTR");
    S.replace("LPTSTR", Wide ? "LPWSTR" : "LPSTR");
    S.replace("TCHAR", Wide ? "WCHAR" : "CHAR");
    return S;
}

}

int FuncPrototype::FormatParam() const {
    if (!Variadic) return -1;
    for (int I = static_cast<int>(Params.size()) - 1; I >= 0; --I) {
        const QString& N = Params[I].Name;
        if ((N == "fmt" || N == "format") && Params[I].Type.contains("char")) return I;
    }
    return -1;
}

QString FuncPrototype::ToString() const {
    QStringList Parts;
    for (const FuncParam& P : Params) Parts << P.Type + " " + P.Name;
    if (Variadic) Parts << "...";
    QString Ret = ReturnType + " ";
    return (NoReturn ? "noreturn " : "") + Ret + Name + "(" + (Parts.isEmpty() ? "void" : Parts.join(", ")) + ")";
}

void TypeLibrary::Add(const FuncPrototype& Proto) {
    Protos.insert(Proto.Name, Proto);
}

int TypeLibrary::ParseDeclarations(const QString& Text) {
    int Added = 0;
    for (QString Line : Text.split('\n')) {
        const int Comment = Line.indexOf("//");
        if (Comment >= 0) Line.truncate(Comment);
        Line = Line.trimmed();
        if (Line.isEmpty() || Line.startsWith('#')) continue;

        if (Line.startsWith("AW ")) {
            const QString Body = Line.mid(3);
            for (bool Wide : {false, true}) {
                FuncPrototype P;
                if (!ParseOne(Narrow(Body, Wide), P)) continue;
                P.Name += Wide ? "W" : "A";
                Add(P);
                ++Added;
            }
            continue;
        }
        FuncPrototype P;
        if (ParseOne(Line, P)) {
            Add(P);
            ++Added;
        }
    }
    return Added;
}

QStringList TypeLibrary::UserDirectories() {
    QStringList Dirs;
    for (const QString& Base : QStandardPaths::standardLocations(QStandardPaths::GenericDataLocation))
        Dirs << Base + "/Fidra/types";
    if (QCoreApplication::instance()) Dirs << QCoreApplication::applicationDirPath() + "/types";
    const QString Env = qEnvironmentVariable("FIDRA_TYPE_PATH");
    if (!Env.isEmpty()) Dirs << Env.split(QDir::listSeparator(), Qt::SkipEmptyParts);
    return Dirs;
}

const TypeLibrary& TypeLibrary::Instance() {
    static const TypeLibrary Lib = [] {
        TypeLibrary L;
        for (int I = 0; I < BuiltinTypeHeaderCount; ++I) L.ParseDeclarations(QString::fromLatin1(BuiltinTypeHeaders[I]));
        for (const QString& Path : UserDirectories()) {
            QFileInfoList Files;
            const QFileInfo Fi(Path);
            if (Fi.isFile()) Files << Fi;
            else Files = QDir(Path).entryInfoList({"*.h"}, QDir::Files, QDir::Name);
            for (const QFileInfo& F : Files) {
                QFile File(F.absoluteFilePath());
                if (File.open(QIODevice::ReadOnly | QIODevice::Text)) L.ParseDeclarations(QString::fromUtf8(File.readAll()));
            }
        }
        return L;
    }();
    return Lib;
}

const FuncPrototype* TypeLibrary::Find(const QString& Name) const {
    if (Name.isEmpty()) return nullptr;
    auto Hit = [this](const QString& N) -> const FuncPrototype* {
        auto It = Protos.constFind(N);
        return It == Protos.constEnd() ? nullptr : &It.value();
    };
    if (const FuncPrototype* P = Hit(Name)) return P;

    QString N = Name;
    const int Bang = N.indexOf('!');                 // "KERNEL32.dll!CreateFileW"
    if (Bang >= 0) N = N.mid(Bang + 1);
    const int Scope = N.lastIndexOf("::");           // "KERNEL32::CreateFileW"
    if (Scope >= 0 && !Hit(N)) N = N.mid(Scope + 2);
    for (const char* Suffix : {"@plt", "@got", "@PLT"})
        if (N.endsWith(QLatin1String(Suffix))) N.chop(static_cast<int>(strlen(Suffix)));
    static const QRegularExpression VersionOrStdcall(R"(@@?[\w.]+$|@\d+$)");  // printf@GLIBC_2.2.5, _Foo@8
    N.remove(VersionOrStdcall);
    for (const char* Prefix : {"__imp__", "__imp_", "_imp__", "j_", "__isoc99_", "__isoc23_", "__GI_", "__mingw_", "__ms_"})
        if (N.startsWith(QLatin1String(Prefix))) N = N.mid(static_cast<int>(strlen(Prefix)));
    if (const FuncPrototype* P = Hit(N)) return P;
    if (N.startsWith('_')) {                         // Mach-O / 32-bit cdecl decoration
        if (const FuncPrototype* P = Hit(N.mid(1))) return P;
    }
    return nullptr;
}

}
