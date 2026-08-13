#include "Application.h"
#include <QApplication>
#include <QCoreApplication>
#include <QCommandLineParser>
#include <QTimer>
#include <QFile>
#include <QTextStream>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFileInfo>
#include <QElapsedTimer>
#include <cstring>
#include <cstdio>
#include <unistd.h>

#include "../analysis/AnalysisEngine.h"
#include "../analysis/AnalysisDatabase.h"

#include "../disasm/DisasmModule.h"
#include "../debugger/DebuggerModule.h"
#include "../scanner/ScannerModule.h"
#include "../unpacker/UnpackerModule.h"
#include "../network/NetworkModule.h"
#include "../websec/WebSecModule.h"
#include "../mcp/McpModule.h"
#include "../dumper/DumperModule.h"
#include "../structeditor/StructEditorModule.h"
#include "../diff/DiffModule.h"
#include "../decompiler/DecompilerModule.h"
#include "../callgraph/CallGraphModule.h"
#include "../plugins/PluginModule.h"
#include "../bindiff/BinDiffModule.h"
#include "../project/ProjectModule.h"
#include "../symbols/SymbolModule.h"
#include "../scripting/ScriptModule.h"

#ifdef FIDRA_HAS_WEBENGINE
#include "../browser/BrowserModule.h"
#endif

static void PrintUsage() {
    printf("Fidra - Reverse Engineering IDE\n");
    printf("Usage:\n");
    printf("  Fidra                                   Launch GUI\n");
    printf("  Fidra --headless <binary> [options]      Run headless analysis\n");
    printf("\n");
    printf("Headless options:\n");
    printf("  --headless                 Run without GUI\n");
    printf("  --output-json <file>       Export full analysis database to JSON\n");
    printf("  --output-functions <file>  Export function list (address, name, size)\n");
    printf("  --output-strings <file>    Export all discovered strings\n");
    printf("  --output-xrefs <file>      Export all cross-references\n");
    printf("  --output-imports <file>    Export import table\n");
    printf("  --timeout <seconds>        Analysis timeout (default: 300)\n");
    printf("  --script <lua_file>        Run Lua script after analysis\n");
    printf("\n");
    printf("General options:\n");
    printf("  --help, -h                 Show this help\n");
    printf("  --version, -v              Show version\n");
}

static void PrintVersion() {
    const char Msg[] = "Fidra v1.0.0\n";
    write(STDOUT_FILENO, Msg, sizeof(Msg) - 1);
}

static QString FindArgValue(int Argc, char* Argv[], const QString& Flag) {
    for (int I = 1; I < Argc - 1; ++I) {
        if (QString::fromLocal8Bit(Argv[I]) == Flag) {
            return QString::fromLocal8Bit(Argv[I + 1]);
        }
    }
    return {};
}

static bool HasArg(int Argc, char* Argv[], const QString& Flag) {
    for (int I = 1; I < Argc; ++I) {
        if (QString::fromLocal8Bit(Argv[I]) == Flag) {
            return true;
        }
    }
    return false;
}

static QString FindBinaryPath(int Argc, char* Argv[]) {
    QSet<QString> FlagsWithValues = {
        QStringLiteral("--output-json"),
        QStringLiteral("--output-functions"),
        QStringLiteral("--output-strings"),
        QStringLiteral("--output-xrefs"),
        QStringLiteral("--output-imports"),
        QStringLiteral("--timeout"),
        QStringLiteral("--script")
    };

    for (int I = 1; I < Argc; ++I) {
        QString Arg = QString::fromLocal8Bit(Argv[I]);
        if (Arg == QStringLiteral("--headless")) {
            continue;
        }
        if (FlagsWithValues.contains(Arg)) {
            ++I;
            continue;
        }
        if (!Arg.startsWith(QStringLiteral("--")) && !Arg.startsWith(QStringLiteral("-"))) {
            return Arg;
        }
    }
    return {};
}

static bool WriteOutputFunctions(Fidra::AnalysisDatabase* Db, const QString& Path) {
    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }
    QTextStream Stream(&File);
    Stream << QString("%1 %2 %3\n")
              .arg(QStringLiteral("Address"), -18)
              .arg(QStringLiteral("Name"), -60)
              .arg(QStringLiteral("Size"));
    Stream << QString("-").repeated(90) << "\n";

    QList<Fidra::AnalyzedFunction> AllFunctions = Db->GetAllFunctions();
    for (const auto& Func : AllFunctions) {
        Stream << QString("0x%1 %2 %3\n")
                  .arg(Func.Start, 16, 16, QChar('0'))
                  .arg(Func.Name.isEmpty() ? QStringLiteral("sub_%1").arg(Func.Start, 0, 16) : Func.Name, -60)
                  .arg(Func.Size);
    }
    File.close();
    return true;
}

static bool WriteOutputStrings(Fidra::AnalysisDatabase* Db, const QString& Path) {
    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }
    QTextStream Stream(&File);
    Stream << QString("%1 %2 %3 %4\n")
              .arg(QStringLiteral("Address"), -18)
              .arg(QStringLiteral("Type"), -6)
              .arg(QStringLiteral("Len"), -6)
              .arg(QStringLiteral("Value"));
    Stream << QString("-").repeated(100) << "\n";

    QList<Fidra::AnalyzedString> AllStrings = Db->GetAllStrings();
    for (const auto& Str : AllStrings) {
        QString TypeStr = Str.IsWide ? QStringLiteral("wide") : QStringLiteral("ascii");
        QString Escaped = Str.Value;
        Escaped.replace(QStringLiteral("\n"), QStringLiteral("\\n"));
        Escaped.replace(QStringLiteral("\r"), QStringLiteral("\\r"));
        Escaped.replace(QStringLiteral("\t"), QStringLiteral("\\t"));

        Stream << QString("0x%1 %2 %3 %4\n")
                  .arg(Str.Addr, 16, 16, QChar('0'))
                  .arg(TypeStr, -6)
                  .arg(Str.Length, -6)
                  .arg(Escaped);
    }
    File.close();
    return true;
}

static bool WriteOutputXrefs(Fidra::AnalysisDatabase* Db, const QString& Path) {
    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }
    QTextStream Stream(&File);
    Stream << QString("%1 %2 %3\n")
              .arg(QStringLiteral("From"), -18)
              .arg(QStringLiteral("To"), -18)
              .arg(QStringLiteral("Type"));
    Stream << QString("-").repeated(60) << "\n";

    QList<Fidra::AnalyzedFunction> AllFunctions = Db->GetAllFunctions();
    QSet<Fidra::Address> Visited;

    auto XrefTypeName = [](Fidra::XrefType Type) -> QString {
        switch (Type) {
        case Fidra::XrefType::CodeCall:     return QStringLiteral("call");
        case Fidra::XrefType::CodeJump:     return QStringLiteral("jump");
        case Fidra::XrefType::CodeCondJump: return QStringLiteral("cond_jump");
        case Fidra::XrefType::DataRead:     return QStringLiteral("data_read");
        case Fidra::XrefType::DataWrite:    return QStringLiteral("data_write");
        case Fidra::XrefType::DataOffset:   return QStringLiteral("data_offset");
        }
        return QStringLiteral("unknown");
    };

    for (const auto& Func : AllFunctions) {
        QList<Fidra::Xref> Xrefs = Db->GetXrefsFrom(Func.Start);
        for (const auto& Ref : Xrefs) {
            uint64_t Key = (Ref.From << 32) ^ Ref.To;
            if (Visited.contains(Key)) {
                continue;
            }
            Visited.insert(Key);
            Stream << QString("0x%1 0x%2 %3\n")
                      .arg(Ref.From, 16, 16, QChar('0'))
                      .arg(Ref.To, 16, 16, QChar('0'))
                      .arg(XrefTypeName(Ref.Type));
        }

        for (const auto& Block : Func.Blocks) {
            QList<Fidra::AnalyzedInstruction> Insts = Db->GetInstructions(Block.Start, Block.End);
            for (const auto& Inst : Insts) {
                QList<Fidra::Xref> InstXrefs = Db->GetXrefsFrom(Inst.Addr);
                for (const auto& Ref : InstXrefs) {
                    uint64_t Key = (Ref.From << 32) ^ Ref.To;
                    if (Visited.contains(Key)) {
                        continue;
                    }
                    Visited.insert(Key);
                    Stream << QString("0x%1 0x%2 %3\n")
                              .arg(Ref.From, 16, 16, QChar('0'))
                              .arg(Ref.To, 16, 16, QChar('0'))
                              .arg(XrefTypeName(Ref.Type));
                }
            }
        }
    }

    Stream << "\nTotal cross-references in database: " << Db->XrefCount() << "\n";
    File.close();
    return true;
}

static bool WriteOutputImports(Fidra::AnalysisDatabase* Db, const QString& Path) {
    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }
    QTextStream Stream(&File);
    Stream << QString("%1 %2 %3 %4\n")
              .arg(QStringLiteral("IAT Address"), -18)
              .arg(QStringLiteral("DLL"), -30)
              .arg(QStringLiteral("Ordinal"), -8)
              .arg(QStringLiteral("Function"));
    Stream << QString("-").repeated(90) << "\n";

    Fidra::BinaryInfo Info = Db->GetBinaryInfo();
    for (const auto& Imp : Info.Imports) {
        Stream << QString("0x%1 %2 %3 %4\n")
                  .arg(Imp.IatAddress, 16, 16, QChar('0'))
                  .arg(Imp.DllName, -30)
                  .arg(Imp.Ordinal, -8)
                  .arg(Imp.FuncName);
    }

    Stream << "\nTotal imports: " << Info.Imports.size() << "\n";
    File.close();
    return true;
}

static bool WriteOutputJson(Fidra::AnalysisDatabase* Db, const QString& Path) {
    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }
    QJsonObject Root = Db->ExportToJson();
    QJsonDocument Doc(Root);
    File.write(Doc.toJson(QJsonDocument::Indented));
    File.close();
    return true;
}

static int RunHeadless(int Argc, char* Argv[]) {
    QCoreApplication App(Argc, Argv);
    App.setApplicationName("Fidra");
    App.setApplicationVersion("1.0.0");
    App.setOrganizationName("Fidra");

    QTextStream StdOut(stdout);
    QTextStream StdErr(stderr);

    QString BinaryPath = FindBinaryPath(Argc, Argv);
    if (BinaryPath.isEmpty()) {
        StdErr << "Error: no binary file specified\n";
        StdErr << "Usage: Fidra --headless <binary> [options]\n" << Qt::flush;
        return 1;
    }

    QFileInfo BinaryFile(BinaryPath);
    if (!BinaryFile.exists()) {
        StdErr << "Error: file not found: " << BinaryPath << "\n" << Qt::flush;
        return 1;
    }
    if (!BinaryFile.isFile()) {
        StdErr << "Error: not a regular file: " << BinaryPath << "\n" << Qt::flush;
        return 1;
    }

    QString OutputJsonPath = FindArgValue(Argc, Argv, QStringLiteral("--output-json"));
    QString OutputFunctionsPath = FindArgValue(Argc, Argv, QStringLiteral("--output-functions"));
    QString OutputStringsPath = FindArgValue(Argc, Argv, QStringLiteral("--output-strings"));
    QString OutputXrefsPath = FindArgValue(Argc, Argv, QStringLiteral("--output-xrefs"));
    QString OutputImportsPath = FindArgValue(Argc, Argv, QStringLiteral("--output-imports"));
    QString ScriptPath = FindArgValue(Argc, Argv, QStringLiteral("--script"));

    QString TimeoutStr = FindArgValue(Argc, Argv, QStringLiteral("--timeout"));
    int TimeoutSeconds = 300;
    if (!TimeoutStr.isEmpty()) {
        bool Ok = false;
        int Parsed = TimeoutStr.toInt(&Ok);
        if (Ok && Parsed > 0) {
            TimeoutSeconds = Parsed;
        } else {
            StdErr << "Warning: invalid timeout value '" << TimeoutStr << "', using default 300s\n" << Qt::flush;
        }
    }

    StdOut << "Fidra v1.0.0 Headless Mode\n";
    StdOut << "Binary: " << BinaryFile.absoluteFilePath() << "\n";
    StdOut << "Size:   " << BinaryFile.size() << " bytes\n";
    StdOut << "Timeout: " << TimeoutSeconds << "s\n";
    StdOut << Qt::flush;

    Fidra::AnalysisEngine* Engine = new Fidra::AnalysisEngine(&App);
    int ExitCode = 1;
    QElapsedTimer ElapsedTimer;
    ElapsedTimer.start();

    QObject::connect(Engine, &Fidra::AnalysisEngine::ProgressChanged, [&StdOut](Fidra::AnalysisProgress Progress) {
        QString StateStr;
        switch (Progress.State) {
        case Fidra::AnalysisState::Idle:               StateStr = QStringLiteral("Idle"); break;
        case Fidra::AnalysisState::Loading:            StateStr = QStringLiteral("Loading"); break;
        case Fidra::AnalysisState::Disassembling:      StateStr = QStringLiteral("Disassembling"); break;
        case Fidra::AnalysisState::FindingFunctions:   StateStr = QStringLiteral("Finding Functions"); break;
        case Fidra::AnalysisState::BuildingXrefs:      StateStr = QStringLiteral("Building Xrefs"); break;
        case Fidra::AnalysisState::FindingStrings:     StateStr = QStringLiteral("Finding Strings"); break;
        case Fidra::AnalysisState::AnalyzingFunctions: StateStr = QStringLiteral("Analyzing Functions"); break;
        case Fidra::AnalysisState::Complete:           StateStr = QStringLiteral("Complete"); break;
        case Fidra::AnalysisState::Failed:             StateStr = QStringLiteral("Failed"); break;
        }
        StdOut << "[" << Progress.Percentage << "%] " << StateStr;
        if (!Progress.StatusMessage.isEmpty()) {
            StdOut << " - " << Progress.StatusMessage;
        }
        StdOut << "\n" << Qt::flush;
    });

    QObject::connect(Engine, &Fidra::AnalysisEngine::LogMessage, [&StdOut](const QString& Message) {
        StdOut << "[log] " << Message << "\n" << Qt::flush;
    });

    QObject::connect(Engine, &Fidra::AnalysisEngine::AnalysisFinished, [&](bool Success) {
        qint64 ElapsedMs = ElapsedTimer.elapsed();
        double ElapsedSec = ElapsedMs / 1000.0;

        if (!Success) {
            StdErr << "Analysis failed after " << QString::number(ElapsedSec, 'f', 2) << "s\n" << Qt::flush;
            ExitCode = 1;
            QCoreApplication::exit(1);
            return;
        }

        Fidra::AnalysisDatabase* Db = Engine->Database();
        Fidra::BinaryInfo Info = Db->GetBinaryInfo();

        StdOut << "\nAnalysis complete in " << QString::number(ElapsedSec, 'f', 2) << "s\n";
        StdOut << "  Architecture:   " << (Info.Is64Bit ? "x86_64" : "x86") << "\n";
        StdOut << "  Image Base:     0x" << QString::number(Info.ImageBase, 16) << "\n";
        StdOut << "  Entry Point:    0x" << QString::number(Info.EntryPoint, 16) << "\n";
        StdOut << "  Functions:      " << Db->FunctionCount() << "\n";
        StdOut << "  Instructions:   " << Db->InstructionCount() << "\n";
        StdOut << "  Strings:        " << Db->StringCount() << "\n";
        StdOut << "  Cross-refs:     " << Db->XrefCount() << "\n";
        StdOut << "  Imports:        " << Info.Imports.size() << "\n";
        StdOut << "  Exports:        " << Info.Exports.size() << "\n";
        StdOut << "  Segments:       " << Info.Segments.size() << "\n";
        StdOut << Qt::flush;

        bool OutputOk = true;

        if (!OutputJsonPath.isEmpty()) {
            StdOut << "Writing JSON database to " << OutputJsonPath << "... " << Qt::flush;
            if (WriteOutputJson(Db, OutputJsonPath)) {
                StdOut << "done\n" << Qt::flush;
            } else {
                StdErr << "FAILED to write " << OutputJsonPath << "\n" << Qt::flush;
                OutputOk = false;
            }
        }

        if (!OutputFunctionsPath.isEmpty()) {
            StdOut << "Writing function list to " << OutputFunctionsPath << "... " << Qt::flush;
            if (WriteOutputFunctions(Db, OutputFunctionsPath)) {
                StdOut << "done (" << Db->FunctionCount() << " functions)\n" << Qt::flush;
            } else {
                StdErr << "FAILED to write " << OutputFunctionsPath << "\n" << Qt::flush;
                OutputOk = false;
            }
        }

        if (!OutputStringsPath.isEmpty()) {
            StdOut << "Writing strings to " << OutputStringsPath << "... " << Qt::flush;
            if (WriteOutputStrings(Db, OutputStringsPath)) {
                StdOut << "done (" << Db->StringCount() << " strings)\n" << Qt::flush;
            } else {
                StdErr << "FAILED to write " << OutputStringsPath << "\n" << Qt::flush;
                OutputOk = false;
            }
        }

        if (!OutputXrefsPath.isEmpty()) {
            StdOut << "Writing cross-references to " << OutputXrefsPath << "... " << Qt::flush;
            if (WriteOutputXrefs(Db, OutputXrefsPath)) {
                StdOut << "done\n" << Qt::flush;
            } else {
                StdErr << "FAILED to write " << OutputXrefsPath << "\n" << Qt::flush;
                OutputOk = false;
            }
        }

        if (!OutputImportsPath.isEmpty()) {
            StdOut << "Writing imports to " << OutputImportsPath << "... " << Qt::flush;
            if (WriteOutputImports(Db, OutputImportsPath)) {
                StdOut << "done (" << Info.Imports.size() << " imports)\n" << Qt::flush;
            } else {
                StdErr << "FAILED to write " << OutputImportsPath << "\n" << Qt::flush;
                OutputOk = false;
            }
        }

        if (!ScriptPath.isEmpty()) {
            StdOut << "Script: " << ScriptPath << " (script execution not yet implemented)\n" << Qt::flush;
        }

        ExitCode = OutputOk ? 0 : 1;
        QCoreApplication::exit(ExitCode);
    });

    QTimer* TimeoutTimer = new QTimer(&App);
    TimeoutTimer->setSingleShot(true);
    QObject::connect(TimeoutTimer, &QTimer::timeout, [&]() {
        StdErr << "\nAnalysis timed out after " << TimeoutSeconds << "s\n" << Qt::flush;
        Engine->CancelAnalysis();
        ExitCode = 1;
        QCoreApplication::exit(1);
    });

    StdOut << "Starting analysis...\n" << Qt::flush;

    if (!Engine->LoadFile(BinaryFile.absoluteFilePath())) {
        StdErr << "Error: failed to load file: " << BinaryFile.absoluteFilePath() << "\n" << Qt::flush;
        return 1;
    }

    TimeoutTimer->start(TimeoutSeconds * 1000);

    return App.exec();
}

static bool HasArgRaw(int Argc, char* Argv[], const char* Flag) {
    for (int I = 1; I < Argc; ++I) {
        if (strcmp(Argv[I], Flag) == 0) return true;
    }
    return false;
}

int main(int Argc, char* Argv[]) {
    if (HasArgRaw(Argc, Argv, "--help") || HasArgRaw(Argc, Argv, "-h")) {
        PrintUsage();
        fflush(stdout);
        _exit(0);
    }

    if (HasArgRaw(Argc, Argv, "--version") || HasArgRaw(Argc, Argv, "-v")) {
        PrintVersion();
        fflush(stdout);
        _exit(0);
    }

    if (HasArgRaw(Argc, Argv, "--headless")) {
        return RunHeadless(Argc, Argv);
    }

    QApplication App(Argc, Argv);
    App.setApplicationName("Fidra");
    App.setApplicationVersion("1.0.0");
    App.setOrganizationName("Fidra");

    Fidra::Application MainWindow;

    MainWindow.RegisterModule(new Fidra::DisasmModule());
    MainWindow.RegisterModule(new Fidra::DebuggerModule());
    MainWindow.RegisterModule(new Fidra::ScannerModule());
    MainWindow.RegisterModule(new Fidra::UnpackerModule());
    MainWindow.RegisterModule(new Fidra::NetworkModule());
    MainWindow.RegisterModule(new Fidra::WebSecModule());
    MainWindow.RegisterModule(new Fidra::McpModule());
    MainWindow.RegisterModule(new Fidra::DumperModule());
    MainWindow.RegisterModule(new Fidra::StructEditorModule());
    MainWindow.RegisterModule(new Fidra::DiffModule());
    MainWindow.RegisterModule(new Fidra::DecompilerModule());
    MainWindow.RegisterModule(new Fidra::CallGraphModule());
    MainWindow.RegisterModule(new Fidra::PluginModule());
    MainWindow.RegisterModule(new Fidra::BinDiffModule());
    MainWindow.RegisterModule(new Fidra::ProjectModule());
    MainWindow.RegisterModule(new Fidra::SymbolModule());
    MainWindow.RegisterModule(new Fidra::ScriptModule());

#ifdef FIDRA_HAS_WEBENGINE
    MainWindow.RegisterModule(new Fidra::BrowserModule());
#endif

    MainWindow.InitializeModules();
    MainWindow.show();
    MainWindow.raise();
    MainWindow.activateWindow();

    MainWindow.Log("Fidra v1.0.0 initialized", Fidra::LogLevel::Info);

    QString BinaryPath = FindBinaryPath(Argc, Argv);
    if (!BinaryPath.isEmpty()) {
        QFileInfo BinaryFile(BinaryPath);
        if (BinaryFile.exists() && BinaryFile.isFile()) {
            QTimer::singleShot(100, &MainWindow, [&MainWindow, BinaryPath]() {
                MainWindow.OpenBinaryFile(BinaryPath);
            });
        }
    }

    return App.exec();
}
