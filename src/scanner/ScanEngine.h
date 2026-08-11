#pragma once

#include <fidra/Types.h>
#include <fidra/ICore.h>
#include <QObject>
#include <QVector>
#include <QVariant>
#include <QByteArray>
#include <QMutex>
#include <QAtomicInt>
#include <QFutureWatcher>

namespace Fidra {

struct ScanResult {
    Address Addr;
    QByteArray Value;
    QByteArray PreviousValue;
};

class ScanEngine : public QObject {
    Q_OBJECT

public:
    explicit ScanEngine(QObject* Parent = nullptr);
    ~ScanEngine() override;

    void StartFirstScan(ICore* Core, ScanType Type, ValueType ValType, QVariant Value, QVariant ValueEnd = QVariant());
    void StartNextScan(ICore* Core, ScanType Type, QVariant Value, QVariant ValueEnd = QVariant());
    void Cancel();
    void Reset();

    const QVector<ScanResult>& GetResults() const;
    bool IsScanning() const;

    static int ValueTypeSize(ValueType Type, const QVariant& Value = QVariant());

signals:
    void ScanProgress(int Percent);
    void ScanComplete(int ResultCount);

private:
    struct ScanChunk {
        Address Base;
        size_t Size;
    };

    struct PatternByte {
        uint8_t Value;
        bool IsWildcard;
    };

    QVector<ScanResult> ScanFirstChunk(ICore* Core, const ScanChunk& Chunk, ScanType Type, ValueType ValType, const QByteArray& SearchValue, const QByteArray& SearchValueEnd);
    QVector<ScanResult> ScanNextBatch(ICore* Core, const QVector<ScanResult>& Batch, ScanType Type, ValueType ValType, const QByteArray& SearchValue, const QByteArray& SearchValueEnd);

    static QByteArray VariantToBytes(const QVariant& Value, ValueType Type);
    static bool CompareValue(const char* Data, const QByteArray& SearchValue, const QByteArray& SearchValueEnd, ScanType Type, ValueType ValType);
    static bool MatchPattern(const char* Data, size_t DataSize, const QVector<PatternByte>& Pattern);
    static QVector<PatternByte> ParsePattern(const QString& PatternStr);

    template<typename T>
    static bool CompareTyped(T Current, T Search, T SearchEnd, ScanType Type);

    QVector<ScanResult> Results;
    ValueType CurrentValueType;
    QAtomicInt Scanning;
    QAtomicInt Cancelled;
    QMutex ResultMutex;
    QFutureWatcher<void> Watcher;
};

}
