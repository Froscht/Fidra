#pragma once

#include <fidra/Types.h>
#include <QObject>
#include <QByteArray>
#include <QVector>
#include <QString>

namespace Fidra {

class AnalysisDatabase;

enum class DiffType { Added, Removed, Modified, Unchanged };

struct ByteDiff {
    int64_t Offset;
    int Length;
    DiffType Type;
    QByteArray OldData;
    QByteArray NewData;
};

struct FunctionDiff {
    QString Name;
    Address OldAddr;
    Address NewAddr;
    DiffType Type;
    double Similarity;
    QVector<ByteDiff> InstructionDiffs;
};

struct DiffResult {
    QString OldFileName;
    QString NewFileName;
    int64_t OldSize;
    int64_t NewSize;
    QVector<ByteDiff> ByteDiffs;
    QVector<FunctionDiff> FunctionDiffs;
    int TotalChanged;
    int TotalAdded;
    int TotalRemoved;
    double OverallSimilarity;
};

class DiffEngine : public QObject {
    Q_OBJECT

public:
    explicit DiffEngine(QObject* Parent = nullptr);

    DiffResult CompareBinaries(const QByteArray& OldData, const QByteArray& NewData);
    DiffResult CompareFunctions(AnalysisDatabase* OldDb, AnalysisDatabase* NewDb);

    static QVector<ByteDiff> DiffBytes(const QByteArray& Old, const QByteArray& New, int BlockSize = 16);
    static double CalculateSimilarity(const QByteArray& A, const QByteArray& B);

signals:
    void ProgressChanged(int Percent);
};

}
