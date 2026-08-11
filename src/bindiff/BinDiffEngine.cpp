#include "BinDiffEngine.h"

#include <QFile>
#include <QCryptographicHash>
#include <algorithm>

namespace Fidra {

BinDiffEngine::BinDiffEngine(QObject* Parent)
    : QObject(Parent) {
}

BinDiffEngine::~BinDiffEngine() {
}

QByteArray BinDiffEngine::LoadFile(const QString& Path) {
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly))
        return QByteArray();
    return File.readAll();
}

DiffResult BinDiffEngine::CompareBytes(const QString& Path1, const QString& Path2) {
    emit ComparisonStarted();

    QByteArray Data1 = LoadFile(Path1);
    QByteArray Data2 = LoadFile(Path2);

    DiffResult Result;
    Result.File1Size = static_cast<uint64_t>(Data1.size());
    Result.File2Size = static_cast<uint64_t>(Data2.size());
    Result.MatchingBytes = 0;
    Result.DifferingBytes = 0;
    Result.OnlyInFile1 = 0;
    Result.OnlyInFile2 = 0;

    uint64_t CommonLen = qMin(Result.File1Size, Result.File2Size);

    if (CommonLen == 0) {
        if (Data1.size() > 0) {
            DiffRegion Region;
            Region.Offset = 0;
            Region.Size = Result.File1Size;
            Region.Type = DiffRegionType::Removed;
            Result.Regions.append(Region);
            Result.OnlyInFile1 = Result.File1Size;
        }
        if (Data2.size() > 0) {
            DiffRegion Region;
            Region.Offset = 0;
            Region.Size = Result.File2Size;
            Region.Type = DiffRegionType::Added;
            Result.Regions.append(Region);
            Result.OnlyInFile2 = Result.File2Size;
        }
        Result.MatchPercent = 0;
        emit ComparisonFinished(Result);
        return Result;
    }

    const char* Ptr1 = Data1.constData();
    const char* Ptr2 = Data2.constData();

    uint64_t RegionStart = 0;
    bool PrevMatch = (Ptr1[0] == Ptr2[0]);

    for (uint64_t I = 0; I <= CommonLen; ++I) {
        bool CurMatch = (I < CommonLen) ? (Ptr1[I] == Ptr2[I]) : !PrevMatch;

        if (CurMatch != PrevMatch || I == CommonLen) {
            DiffRegion Region;
            Region.Offset = RegionStart;
            Region.Size = I - RegionStart;
            Region.Type = PrevMatch ? DiffRegionType::Match : DiffRegionType::Modified;
            Result.Regions.append(Region);

            if (PrevMatch)
                Result.MatchingBytes += Region.Size;
            else
                Result.DifferingBytes += Region.Size;

            RegionStart = I;
            PrevMatch = CurMatch;
        }

        if (I % 65536 == 0 && CommonLen > 0) {
            int Progress = static_cast<int>((I * 100) / CommonLen);
            emit ComparisonProgress(Progress);
        }
    }

    if (Result.File1Size > CommonLen) {
        DiffRegion Region;
        Region.Offset = CommonLen;
        Region.Size = Result.File1Size - CommonLen;
        Region.Type = DiffRegionType::Removed;
        Result.Regions.append(Region);
        Result.OnlyInFile1 = Region.Size;
    }

    if (Result.File2Size > CommonLen) {
        DiffRegion Region;
        Region.Offset = CommonLen;
        Region.Size = Result.File2Size - CommonLen;
        Region.Type = DiffRegionType::Added;
        Result.Regions.append(Region);
        Result.OnlyInFile2 = Region.Size;
    }

    uint64_t TotalBytes = qMax(Result.File1Size, Result.File2Size);
    Result.MatchPercent = TotalBytes > 0
        ? static_cast<int>((Result.MatchingBytes * 100) / TotalBytes)
        : 0;

    emit ComparisonProgress(100);
    emit ComparisonFinished(Result);
    return Result;
}

uint64_t BinDiffEngine::ComputeFunctionHash(const AnalyzedFunction& Func, AnalysisDatabase* Db) {
    QCryptographicHash Hasher(QCryptographicHash::Sha256);

    QList<AnalyzedInstruction> Instructions = Db->GetInstructions(Func.Start, Func.End);
    for (const auto& Inst : Instructions) {
        Hasher.addData(Inst.Mnemonic.toUtf8());
        Hasher.addData(",", 1);
    }

    QByteArray HashBytes = Hasher.result();
    uint64_t HashValue = 0;
    if (HashBytes.size() >= 8)
        memcpy(&HashValue, HashBytes.constData(), 8);

    return HashValue;
}

double BinDiffEngine::ComputeFunctionSimilarity(const AnalyzedFunction& Func1, AnalysisDatabase* Db1,
                                                 const AnalyzedFunction& Func2, AnalysisDatabase* Db2) {
    QList<AnalyzedInstruction> Insts1 = Db1->GetInstructions(Func1.Start, Func1.End);
    QList<AnalyzedInstruction> Insts2 = Db2->GetInstructions(Func2.Start, Func2.End);

    if (Insts1.isEmpty() && Insts2.isEmpty())
        return 1.0;
    if (Insts1.isEmpty() || Insts2.isEmpty())
        return 0.0;

    int N = Insts1.size();
    int M = Insts2.size();

    QVector<int> Prev(M + 1, 0);
    QVector<int> Curr(M + 1, 0);

    for (int I = 1; I <= N; ++I) {
        for (int J = 1; J <= M; ++J) {
            if (Insts1[I - 1].Mnemonic == Insts2[J - 1].Mnemonic)
                Curr[J] = Prev[J - 1] + 1;
            else
                Curr[J] = qMax(Prev[J], Curr[J - 1]);
        }
        std::swap(Prev, Curr);
        Curr.fill(0);
    }

    int LcsLen = Prev[M];
    return static_cast<double>(LcsLen) / static_cast<double>(qMax(N, M));
}

DiffResult BinDiffEngine::CompareFunctions(AnalysisDatabase* Db1, AnalysisDatabase* Db2) {
    emit ComparisonStarted();

    DiffResult Result;
    Result.File1Size = 0;
    Result.File2Size = 0;
    Result.MatchingBytes = 0;
    Result.DifferingBytes = 0;
    Result.OnlyInFile1 = 0;
    Result.OnlyInFile2 = 0;
    Result.MatchPercent = 0;

    if (!Db1 || !Db2) {
        emit ComparisonFinished(Result);
        return Result;
    }

    QList<AnalyzedFunction> Funcs1 = Db1->GetAllFunctions();
    QList<AnalyzedFunction> Funcs2 = Db2->GetAllFunctions();

    QSet<int> Matched1;
    QSet<int> Matched2;

    for (int I = 0; I < Funcs1.size(); ++I) {
        if (Matched1.contains(I))
            continue;
        for (int J = 0; J < Funcs2.size(); ++J) {
            if (Matched2.contains(J))
                continue;
            if (Funcs1[I].Name == Funcs2[J].Name && !Funcs1[I].Name.isEmpty()) {
                double Sim = ComputeFunctionSimilarity(Funcs1[I], Db1, Funcs2[J], Db2);
                FunctionMatch Match;
                Match.Name1 = Funcs1[I].Name;
                Match.Name2 = Funcs2[J].Name;
                Match.Addr1 = Funcs1[I].Start;
                Match.Addr2 = Funcs2[J].Start;
                Match.Similarity = Sim;
                Result.FunctionMatches.append(Match);
                Matched1.insert(I);
                Matched2.insert(J);
                break;
            }
        }
    }

    QMap<uint64_t, int> HashToFunc2;
    for (int J = 0; J < Funcs2.size(); ++J) {
        if (Matched2.contains(J))
            continue;
        uint64_t Hash = ComputeFunctionHash(Funcs2[J], Db2);
        HashToFunc2[Hash] = J;
    }

    for (int I = 0; I < Funcs1.size(); ++I) {
        if (Matched1.contains(I))
            continue;
        uint64_t Hash = ComputeFunctionHash(Funcs1[I], Db1);
        if (HashToFunc2.contains(Hash)) {
            int J = HashToFunc2[Hash];
            if (!Matched2.contains(J)) {
                double Sim = ComputeFunctionSimilarity(Funcs1[I], Db1, Funcs2[J], Db2);
                FunctionMatch Match;
                Match.Name1 = Funcs1[I].Name;
                Match.Name2 = Funcs2[J].Name;
                Match.Addr1 = Funcs1[I].Start;
                Match.Addr2 = Funcs2[J].Start;
                Match.Similarity = Sim;
                Result.FunctionMatches.append(Match);
                Matched1.insert(I);
                Matched2.insert(J);
            }
        }
    }

    for (int I = 0; I < Funcs1.size(); ++I) {
        if (Matched1.contains(I))
            continue;

        int BestJ = -1;
        double BestScore = 0.0;

        for (int J = 0; J < Funcs2.size(); ++J) {
            if (Matched2.contains(J))
                continue;

            double MaxSize = qMax(static_cast<double>(Funcs1[I].Size),
                                  static_cast<double>(Funcs2[J].Size));
            double SizeRatio = MaxSize > 0
                ? 1.0 - qAbs(static_cast<double>(Funcs1[I].Size) - static_cast<double>(Funcs2[J].Size)) / MaxSize
                : 1.0;

            int CallerMax = qMax(Funcs1[I].Callers.size(), Funcs2[J].Callers.size());
            double CallerRatio = CallerMax > 0
                ? 1.0 - static_cast<double>(qAbs(Funcs1[I].Callers.size() - Funcs2[J].Callers.size()))
                        / static_cast<double>(CallerMax)
                : 1.0;

            int CalleeMax = qMax(Funcs1[I].Callees.size(), Funcs2[J].Callees.size());
            double CalleeRatio = CalleeMax > 0
                ? 1.0 - static_cast<double>(qAbs(Funcs1[I].Callees.size() - Funcs2[J].Callees.size()))
                        / static_cast<double>(CalleeMax)
                : 1.0;

            double Score = (SizeRatio + CallerRatio + CalleeRatio) / 3.0;

            if (Score > BestScore && Score > 0.7) {
                BestScore = Score;
                BestJ = J;
            }
        }

        if (BestJ >= 0) {
            double Sim = ComputeFunctionSimilarity(Funcs1[I], Db1, Funcs2[BestJ], Db2);
            FunctionMatch Match;
            Match.Name1 = Funcs1[I].Name;
            Match.Name2 = Funcs2[BestJ].Name;
            Match.Addr1 = Funcs1[I].Start;
            Match.Addr2 = Funcs2[BestJ].Start;
            Match.Similarity = Sim;
            Result.FunctionMatches.append(Match);
            Matched1.insert(I);
            Matched2.insert(BestJ);
        }
    }

    int TotalFunctions = qMax(Funcs1.size(), Funcs2.size());
    if (TotalFunctions > 0)
        Result.MatchPercent = static_cast<int>((Result.FunctionMatches.size() * 100) / TotalFunctions);

    emit ComparisonProgress(100);
    emit ComparisonFinished(Result);
    return Result;
}

}
