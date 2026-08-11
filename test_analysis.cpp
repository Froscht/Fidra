#include "src/analysis/AnalysisEngine.h"
#include "src/analysis/AnalysisDatabase.h"
#include "src/analysis/AnalysisTypes.h"
#include <QCoreApplication>
#include <QTimer>
#include <QElapsedTimer>
#include <cstdio>

using namespace Fidra;

int main(int Argc, char* Argv[]) {
    QCoreApplication App(Argc, Argv);

    if (Argc < 2) {
        printf("Usage: %s <binary>\n", Argv[0]);
        return 1;
    }

    QString FilePath = QString::fromUtf8(Argv[1]);
    printf("Loading: %s\n", FilePath.toUtf8().constData());

    AnalysisEngine Engine;
    QElapsedTimer Timer;
    Timer.start();

    QObject::connect(&Engine, &AnalysisEngine::ProgressChanged, [](AnalysisProgress P) {
        printf("\r[%3d%%] %s", P.Percentage, P.StatusMessage.toUtf8().constData());
        fflush(stdout);
    });

    QObject::connect(&Engine, &AnalysisEngine::LogMessage, [](const QString& Msg) {
        printf("\n  LOG: %s", Msg.toUtf8().constData());
        fflush(stdout);
    });

    QObject::connect(&Engine, &AnalysisEngine::AnalysisFinished, [&](bool Success) {
        printf("\n\n=== Analysis %s in %.2f seconds ===\n",
            Success ? "COMPLETE" : "FAILED",
            Timer.elapsed() / 1000.0);

        if (Success) {
            AnalysisDatabase* Db = Engine.Database();
            BinaryInfo Info = Db->GetBinaryInfo();

            printf("File:         %s\n", Info.FileName.toUtf8().constData());
            printf("Architecture: %s\n", Info.Is64Bit ? "x86_64" : "x86");
            printf("Image Base:   0x%lx\n", Info.ImageBase);
            printf("Entry Point:  0x%lx\n", Info.EntryPoint);
            printf("Image Size:   %zu bytes\n", Info.ImageSize);
            printf("DLL:          %s\n", Info.IsDll ? "yes" : "no");
            printf("Driver:       %s\n", Info.IsDriver ? "yes" : "no");
            printf("Segments:     %d\n", Info.Segments.size());
            printf("Imports:      %d\n", Info.Imports.size());
            printf("Exports:      %d\n", Info.Exports.size());
            printf("\n--- Analysis Results ---\n");
            printf("Functions:    %d\n", Db->FunctionCount());
            printf("Instructions: %d\n", Db->InstructionCount());
            printf("Strings:      %d\n", Db->StringCount());
            printf("Xrefs:        %d\n", Db->XrefCount());

            printf("\n--- Segments ---\n");
            for (const auto& Seg : Info.Segments) {
                printf("  %-10s VA=0x%lx Size=0x%zx Raw=0x%zx %s%s%s %s\n",
                    Seg.Name.toUtf8().constData(),
                    Seg.VirtualAddress, Seg.VirtualSize, Seg.RawSize,
                    Seg.IsReadable ? "R" : "-",
                    Seg.IsWritable ? "W" : "-",
                    Seg.IsExecutable ? "X" : "-",
                    Seg.Type == SegmentType::Code ? "CODE" :
                    Seg.Type == SegmentType::Data ? "DATA" :
                    Seg.Type == SegmentType::Bss ? "BSS" :
                    Seg.Type == SegmentType::Resource ? "RSRC" :
                    Seg.Type == SegmentType::Reloc ? "RELOC" : "?");
            }

            printf("\n--- First 20 Imports ---\n");
            int Count = 0;
            for (const auto& Imp : Info.Imports) {
                if (Count++ >= 20) break;
                printf("  %s!%s @ 0x%lx\n",
                    Imp.DllName.toUtf8().constData(),
                    Imp.FuncName.toUtf8().constData(),
                    Imp.IatAddress);
            }

            printf("\n--- First 20 Functions ---\n");
            QList<AnalyzedFunction> Funcs = Db->GetAllFunctions();
            Count = 0;
            for (const auto& F : Funcs) {
                if (Count++ >= 20) break;
                printf("  %-40s 0x%lx - 0x%lx  size=%zu  insns=%d  args=%d%s%s\n",
                    F.Name.toUtf8().constData(),
                    F.Start, F.End, F.Size,
                    F.InstructionCount, F.ArgCount,
                    F.IsThunk ? " [thunk]" : "",
                    F.IsExported ? " [export]" : "");
            }

            printf("\n--- First 20 Strings ---\n");
            QList<AnalyzedString> Strings = Db->GetAllStrings();
            Count = 0;
            for (const auto& S : Strings) {
                if (Count++ >= 20) break;
                printf("  0x%lx: %s\"%s\"\n",
                    S.Addr,
                    S.IsWide ? "L" : "",
                    S.Value.left(80).toUtf8().constData());
            }

            printf("\n--- Disassembly at Entry Point (first 30 insns) ---\n");
            QList<AnalyzedInstruction> EntryInsns = Db->GetInstructions(Info.EntryPoint, Info.EntryPoint + 0x200);
            Count = 0;
            for (const auto& I : EntryInsns) {
                if (Count++ >= 30) break;
                QByteArray ByteHex;
                for (int B = 0; B < I.Size; ++B) {
                    ByteHex += QString("%1 ").arg(I.Bytes[B], 2, 16, QChar('0')).toUtf8();
                }
                printf("  0x%lx: %-24s %-8s %s",
                    I.Addr,
                    ByteHex.constData(),
                    I.Mnemonic.toUtf8().constData(),
                    I.Operands.toUtf8().constData());
                if (!I.Comment.isEmpty()) {
                    printf("  ; %s", I.Comment.toUtf8().constData());
                }
                printf("\n");
            }
        }

        QCoreApplication::quit();
    });

    Engine.LoadFile(FilePath);
    return App.exec();
}
