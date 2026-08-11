#include "DiffEngine.h"
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"

#include <QMap>
#include <QSet>
#include <algorithm>
#include <cstring>

namespace Fidra {

DiffEngine::DiffEngine(QObject* Parent)
    : QObject(Parent)
{
}

double DiffEngine::CalculateSimilarity(const QByteArray& A, const QByteArray& B) {
    if (A.isEmpty() && B.isEmpty()) return 1.0;
    if (A.isEmpty() || B.isEmpty()) return 0.0;

    int MinLen = std::min(A.size(), B.size());
    int MaxLen = std::max(A.size(), B.size());
    if (MaxLen == 0) return 1.0;

    int MatchCount = 0;
    for (int I = 0; I < MinLen; ++I) {
        if (A[I] == B[I])
            ++MatchCount;
    }

    return static_cast<double>(MatchCount) / static_cast<double>(MaxLen);
}

QVector<ByteDiff> DiffEngine::DiffBytes(const QByteArray& Old, const QByteArray& New, int BlockSize) {
    QVector<ByteDiff> Diffs;

    int64_t OldLen = Old.size();
    int64_t NewLen = New.size();
    int64_t CommonLen = std::min(OldLen, NewLen);
    int64_t MaxLen = std::max(OldLen, NewLen);

    int64_t Pos = 0;
    while (Pos < CommonLen) {
        int64_t BlockEnd = std::min(Pos + BlockSize, CommonLen);
        int ActualBlock = static_cast<int>(BlockEnd - Pos);

        bool Same = (memcmp(Old.constData() + Pos, New.constData() + Pos, ActualBlock) == 0);

        if (!Same) {
            int64_t RunStart = Pos;
            while (Pos < CommonLen) {
                BlockEnd = std::min(Pos + BlockSize, CommonLen);
                ActualBlock = static_cast<int>(BlockEnd - Pos);
                if (memcmp(Old.constData() + Pos, New.constData() + Pos, ActualBlock) == 0)
                    break;
                Pos = BlockEnd;
            }

            int RunLen = static_cast<int>(Pos - RunStart);
            ByteDiff Diff;
            Diff.Offset = RunStart;
            Diff.Length = RunLen;
            Diff.Type = DiffType::Modified;
            Diff.OldData = Old.mid(static_cast<int>(RunStart), RunLen);
            Diff.NewData = New.mid(static_cast<int>(RunStart), RunLen);
            Diffs.append(Diff);
        } else {
            Pos = BlockEnd;
        }
    }

    if (NewLen > OldLen) {
        ByteDiff Diff;
        Diff.Offset = OldLen;
        Diff.Length = static_cast<int>(NewLen - OldLen);
        Diff.Type = DiffType::Added;
        Diff.NewData = New.mid(static_cast<int>(OldLen));
        Diffs.append(Diff);
    } else if (OldLen > NewLen) {
        ByteDiff Diff;
        Diff.Offset = NewLen;
        Diff.Length = static_cast<int>(OldLen - NewLen);
        Diff.Type = DiffType::Removed;
        Diff.OldData = Old.mid(static_cast<int>(NewLen));
        Diffs.append(Diff);
    }

    return Diffs;
}

DiffResult DiffEngine::CompareBinaries(const QByteArray& OldData, const QByteArray& NewData) {
    DiffResult Result;
    Result.OldSize = OldData.size();
    Result.NewSize = NewData.size();
    Result.TotalChanged = 0;
    Result.TotalAdded = 0;
    Result.TotalRemoved = 0;

    emit ProgressChanged(5);

    Result.ByteDiffs = DiffBytes(OldData, NewData, 16);

    emit ProgressChanged(70);

    for (const auto& Diff : Result.ByteDiffs) {
        switch (Diff.Type) {
        case DiffType::Modified:
            Result.TotalChanged += Diff.Length;
            break;
        case DiffType::Added:
            Result.TotalAdded += Diff.Length;
            break;
        case DiffType::Removed:
            Result.TotalRemoved += Diff.Length;
            break;
        default:
            break;
        }
    }

    Result.OverallSimilarity = CalculateSimilarity(OldData, NewData);

    emit ProgressChanged(100);

    return Result;
}

DiffResult DiffEngine::CompareFunctions(AnalysisDatabase* OldDb, AnalysisDatabase* NewDb) {
    DiffResult Result;

    if (!OldDb || !NewDb) return Result;

    BinaryInfo OldInfo = OldDb->GetBinaryInfo();
    BinaryInfo NewInfo = NewDb->GetBinaryInfo();
    Result.OldFileName = OldInfo.FileName;
    Result.NewFileName = NewInfo.FileName;
    Result.OldSize = OldInfo.ImageSize;
    Result.NewSize = NewInfo.ImageSize;
    Result.TotalChanged = 0;
    Result.TotalAdded = 0;
    Result.TotalRemoved = 0;

    QList<AnalyzedFunction> OldFuncs = OldDb->GetAllFunctions();
    QList<AnalyzedFunction> NewFuncs = NewDb->GetAllFunctions();

    QMap<QString, AnalyzedFunction> OldByName;
    QMap<QString, AnalyzedFunction> NewByName;
    QMap<Address, AnalyzedFunction> OldByAddr;
    QMap<Address, AnalyzedFunction> NewByAddr;

    for (const auto& Func : OldFuncs) {
        if (!Func.Name.isEmpty() && !Func.Name.startsWith("sub_"))
            OldByName[Func.Name] = Func;
        OldByAddr[Func.Start] = Func;
    }

    for (const auto& Func : NewFuncs) {
        if (!Func.Name.isEmpty() && !Func.Name.startsWith("sub_"))
            NewByName[Func.Name] = Func;
        NewByAddr[Func.Start] = Func;
    }

    int TotalWork = OldFuncs.size() + NewFuncs.size();
    int Done = 0;

    QSet<Address> MatchedNewAddrs;

    for (const auto& OldFunc : OldFuncs) {
        FunctionDiff FDiff;
        FDiff.OldAddr = OldFunc.Start;
        FDiff.Name = OldFunc.Name;

        bool Found = false;

        if (!OldFunc.Name.isEmpty() && !OldFunc.Name.startsWith("sub_") && NewByName.contains(OldFunc.Name)) {
            const auto& NewFunc = NewByName[OldFunc.Name];
            FDiff.NewAddr = NewFunc.Start;
            MatchedNewAddrs.insert(NewFunc.Start);
            Found = true;

            QByteArray OldBytes = OldDb->ReadBytes(OldFunc.Start, OldFunc.Size);
            QByteArray NewBytes = NewDb->ReadBytes(NewFunc.Start, NewFunc.Size);

            FDiff.Similarity = CalculateSimilarity(OldBytes, NewBytes);

            if (FDiff.Similarity >= 0.9999) {
                FDiff.Type = DiffType::Unchanged;
            } else {
                FDiff.Type = DiffType::Modified;
                FDiff.InstructionDiffs = DiffBytes(OldBytes, NewBytes, 1);
                ++Result.TotalChanged;
            }
        }

        if (!Found) {
            QByteArray OldBytes = OldDb->ReadBytes(OldFunc.Start, std::min(OldFunc.Size, static_cast<size_t>(256)));
            double BestSim = 0.0;
            Address BestAddr = 0;

            for (const auto& NewFunc : NewFuncs) {
                if (MatchedNewAddrs.contains(NewFunc.Start)) continue;
                if (NewFunc.Size == 0) continue;

                size_t CmpSize = std::min({OldFunc.Size, NewFunc.Size, static_cast<size_t>(256)});
                QByteArray NewBytes = NewDb->ReadBytes(NewFunc.Start, CmpSize);
                double Sim = CalculateSimilarity(OldBytes.left(static_cast<int>(CmpSize)), NewBytes);

                if (Sim > BestSim && Sim > 0.6) {
                    BestSim = Sim;
                    BestAddr = NewFunc.Start;
                }
            }

            if (BestAddr != 0) {
                FDiff.NewAddr = BestAddr;
                FDiff.Similarity = BestSim;
                MatchedNewAddrs.insert(BestAddr);

                QByteArray OldFullBytes = OldDb->ReadBytes(OldFunc.Start, OldFunc.Size);
                const auto& MatchedFunc = NewByAddr[BestAddr];
                QByteArray NewFullBytes = NewDb->ReadBytes(MatchedFunc.Start, MatchedFunc.Size);

                if (BestSim >= 0.9999) {
                    FDiff.Type = DiffType::Unchanged;
                } else {
                    FDiff.Type = DiffType::Modified;
                    FDiff.InstructionDiffs = DiffBytes(OldFullBytes, NewFullBytes, 1);
                    ++Result.TotalChanged;
                }

                if (FDiff.Name.isEmpty() || FDiff.Name.startsWith("sub_")) {
                    FDiff.Name = MatchedFunc.Name;
                }
            } else {
                FDiff.NewAddr = 0;
                FDiff.Similarity = 0.0;
                FDiff.Type = DiffType::Removed;
                ++Result.TotalRemoved;
            }
        }

        Result.FunctionDiffs.append(FDiff);

        ++Done;
        if (TotalWork > 0)
            emit ProgressChanged(Done * 90 / TotalWork);
    }

    for (const auto& NewFunc : NewFuncs) {
        if (MatchedNewAddrs.contains(NewFunc.Start)) continue;

        FunctionDiff FDiff;
        FDiff.Name = NewFunc.Name;
        FDiff.OldAddr = 0;
        FDiff.NewAddr = NewFunc.Start;
        FDiff.Type = DiffType::Added;
        FDiff.Similarity = 0.0;
        ++Result.TotalAdded;
        Result.FunctionDiffs.append(FDiff);

        ++Done;
        if (TotalWork > 0)
            emit ProgressChanged(Done * 90 / TotalWork);
    }

    int TotalMatched = 0;
    double SimSum = 0.0;
    for (const auto& FD : Result.FunctionDiffs) {
        if (FD.Type == DiffType::Unchanged || FD.Type == DiffType::Modified) {
            ++TotalMatched;
            SimSum += FD.Similarity;
        }
    }
    Result.OverallSimilarity = TotalMatched > 0 ? SimSum / TotalMatched : 0.0;

    std::sort(Result.FunctionDiffs.begin(), Result.FunctionDiffs.end(),
              [](const FunctionDiff& A, const FunctionDiff& B) {
                  if (A.Type != B.Type) {
                      int OrderA = (A.Type == DiffType::Modified) ? 0 : (A.Type == DiffType::Added) ? 1 : (A.Type == DiffType::Removed) ? 2 : 3;
                      int OrderB = (B.Type == DiffType::Modified) ? 0 : (B.Type == DiffType::Added) ? 1 : (B.Type == DiffType::Removed) ? 2 : 3;
                      return OrderA < OrderB;
                  }
                  return A.Similarity < B.Similarity;
              });

    emit ProgressChanged(100);
    return Result;
}

}
