#pragma once

#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <QObject>
#include <QString>
#include <QVector>
#include <QByteArray>

namespace Fidra {

enum class DiffRegionType {
    Match,
    Modified,
    Added,
    Removed
};

struct DiffRegion {
    uint64_t Offset;
    uint64_t Size;
    DiffRegionType Type;
};

struct FunctionMatch {
    QString Name1;
    QString Name2;
    Address Addr1;
    Address Addr2;
    double Similarity;
};

struct DiffResult {
    QVector<DiffRegion> Regions;
    int MatchPercent;
    QVector<FunctionMatch> FunctionMatches;
    uint64_t File1Size;
    uint64_t File2Size;
    uint64_t MatchingBytes;
    uint64_t DifferingBytes;
    uint64_t OnlyInFile1;
    uint64_t OnlyInFile2;
};

class BinDiffEngine : public QObject {
    Q_OBJECT

public:
    explicit BinDiffEngine(QObject* Parent = nullptr);
    ~BinDiffEngine() override;

    DiffResult CompareBytes(const QString& Path1, const QString& Path2);
    DiffResult CompareFunctions(AnalysisDatabase* Db1, AnalysisDatabase* Db2);

signals:
    void ComparisonStarted();
    void ComparisonProgress(int Percent);
    void ComparisonFinished(const DiffResult& Result);

private:
    QByteArray LoadFile(const QString& Path);
    uint64_t ComputeFunctionHash(const AnalyzedFunction& Func, AnalysisDatabase* Db);
    double ComputeFunctionSimilarity(const AnalyzedFunction& Func1, AnalysisDatabase* Db1,
                                     const AnalyzedFunction& Func2, AnalysisDatabase* Db2);
};

}
