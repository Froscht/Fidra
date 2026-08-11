#include "ScanEngine.h"
#include <QtConcurrent>
#include <QThread>
#include <cstring>
#include <cmath>
#include <algorithm>

namespace Fidra {

ScanEngine::ScanEngine(QObject* Parent)
    : QObject(Parent)
    , CurrentValueType(ValueType::Int32)
{
    Scanning.storeRelaxed(0);
    Cancelled.storeRelaxed(0);
}

ScanEngine::~ScanEngine()
{
    Cancel();
    Watcher.waitForFinished();
}

int ScanEngine::ValueTypeSize(ValueType Type, const QVariant& Value)
{
    switch (Type) {
    case ValueType::Byte:     return 1;
    case ValueType::Int16:    return 2;
    case ValueType::Int32:    return 4;
    case ValueType::Int64:    return 8;
    case ValueType::Float:    return 4;
    case ValueType::Double:   return 8;
    case ValueType::Pointer:  return 8;
    case ValueType::String:
        if (Value.isValid())
            return Value.toString().toUtf8().size();
        return 0;
    case ValueType::ByteArray:
        if (Value.isValid()) {
            QString PatternStr = Value.toString();
            QStringList Parts = PatternStr.split(' ', Qt::SkipEmptyParts);
            return Parts.size();
        }
        return 0;
    }
    return 4;
}

QByteArray ScanEngine::VariantToBytes(const QVariant& Value, ValueType Type)
{
    QByteArray Bytes;

    switch (Type) {
    case ValueType::Byte: {
        uint8_t V = static_cast<uint8_t>(Value.toUInt());
        Bytes.append(reinterpret_cast<const char*>(&V), sizeof(V));
        break;
    }
    case ValueType::Int16: {
        int16_t V = static_cast<int16_t>(Value.toInt());
        Bytes.append(reinterpret_cast<const char*>(&V), sizeof(V));
        break;
    }
    case ValueType::Int32: {
        int32_t V = static_cast<int32_t>(Value.toInt());
        Bytes.append(reinterpret_cast<const char*>(&V), sizeof(V));
        break;
    }
    case ValueType::Int64: {
        int64_t V = Value.toLongLong();
        Bytes.append(reinterpret_cast<const char*>(&V), sizeof(V));
        break;
    }
    case ValueType::Float: {
        float V = Value.toFloat();
        Bytes.append(reinterpret_cast<const char*>(&V), sizeof(V));
        break;
    }
    case ValueType::Double: {
        double V = Value.toDouble();
        Bytes.append(reinterpret_cast<const char*>(&V), sizeof(V));
        break;
    }
    case ValueType::Pointer: {
        uint64_t V = Value.toULongLong();
        Bytes.append(reinterpret_cast<const char*>(&V), sizeof(V));
        break;
    }
    case ValueType::String: {
        Bytes = Value.toString().toUtf8();
        break;
    }
    case ValueType::ByteArray: {
        QString PatternStr = Value.toString();
        QStringList Parts = PatternStr.split(' ', Qt::SkipEmptyParts);
        for (const QString& Part : Parts) {
            if (Part == "??" || Part == "?") {
                Bytes.append('\x00');
            } else {
                bool Ok;
                uint8_t B = static_cast<uint8_t>(Part.toUInt(&Ok, 16));
                Bytes.append(static_cast<char>(B));
            }
        }
        break;
    }
    }

    return Bytes;
}

QVector<ScanEngine::PatternByte> ScanEngine::ParsePattern(const QString& PatternStr)
{
    QVector<PatternByte> Pattern;
    QStringList Parts = PatternStr.split(' ', Qt::SkipEmptyParts);

    for (const QString& Part : Parts) {
        PatternByte Pb;
        if (Part == "??" || Part == "?") {
            Pb.Value = 0;
            Pb.IsWildcard = true;
        } else {
            bool Ok;
            Pb.Value = static_cast<uint8_t>(Part.toUInt(&Ok, 16));
            Pb.IsWildcard = false;
        }
        Pattern.append(Pb);
    }

    return Pattern;
}

bool ScanEngine::MatchPattern(const char* Data, size_t DataSize, const QVector<PatternByte>& Pattern)
{
    if (static_cast<size_t>(Pattern.size()) > DataSize)
        return false;

    for (int I = 0; I < Pattern.size(); ++I) {
        if (Pattern[I].IsWildcard)
            continue;
        if (static_cast<uint8_t>(Data[I]) != Pattern[I].Value)
            return false;
    }

    return true;
}

template<typename T>
bool ScanEngine::CompareTyped(T Current, T Search, T SearchEnd, ScanType Type)
{
    switch (Type) {
    case ScanType::Exact:
        if constexpr (std::is_floating_point_v<T>) {
            return std::fabs(static_cast<double>(Current) - static_cast<double>(Search)) < 0.0001;
        } else {
            return Current == Search;
        }
    case ScanType::GreaterThan:
        return Current > Search;
    case ScanType::LessThan:
        return Current < Search;
    case ScanType::Between:
        return Current >= Search && Current <= SearchEnd;
    case ScanType::Unknown:
        return true;
    default:
        return false;
    }
}

bool ScanEngine::CompareValue(const char* Data, const QByteArray& SearchValue, const QByteArray& SearchValueEnd, ScanType Type, ValueType ValType)
{
    if (Type == ScanType::Unknown)
        return true;

    switch (ValType) {
    case ValueType::Byte: {
        uint8_t Current;
        std::memcpy(&Current, Data, sizeof(Current));
        uint8_t Search = 0;
        uint8_t SearchEnd2 = 0;
        if (!SearchValue.isEmpty()) std::memcpy(&Search, SearchValue.constData(), sizeof(Search));
        if (!SearchValueEnd.isEmpty()) std::memcpy(&SearchEnd2, SearchValueEnd.constData(), sizeof(SearchEnd2));
        return CompareTyped(Current, Search, SearchEnd2, Type);
    }
    case ValueType::Int16: {
        int16_t Current;
        std::memcpy(&Current, Data, sizeof(Current));
        int16_t Search = 0;
        int16_t SearchEnd2 = 0;
        if (!SearchValue.isEmpty()) std::memcpy(&Search, SearchValue.constData(), sizeof(Search));
        if (!SearchValueEnd.isEmpty()) std::memcpy(&SearchEnd2, SearchValueEnd.constData(), sizeof(SearchEnd2));
        return CompareTyped(Current, Search, SearchEnd2, Type);
    }
    case ValueType::Int32: {
        int32_t Current;
        std::memcpy(&Current, Data, sizeof(Current));
        int32_t Search = 0;
        int32_t SearchEnd2 = 0;
        if (!SearchValue.isEmpty()) std::memcpy(&Search, SearchValue.constData(), sizeof(Search));
        if (!SearchValueEnd.isEmpty()) std::memcpy(&SearchEnd2, SearchValueEnd.constData(), sizeof(SearchEnd2));
        return CompareTyped(Current, Search, SearchEnd2, Type);
    }
    case ValueType::Int64: {
        int64_t Current;
        std::memcpy(&Current, Data, sizeof(Current));
        int64_t Search = 0;
        int64_t SearchEnd2 = 0;
        if (!SearchValue.isEmpty()) std::memcpy(&Search, SearchValue.constData(), sizeof(Search));
        if (!SearchValueEnd.isEmpty()) std::memcpy(&SearchEnd2, SearchValueEnd.constData(), sizeof(SearchEnd2));
        return CompareTyped(Current, Search, SearchEnd2, Type);
    }
    case ValueType::Float: {
        float Current;
        std::memcpy(&Current, Data, sizeof(Current));
        float Search = 0;
        float SearchEnd2 = 0;
        if (!SearchValue.isEmpty()) std::memcpy(&Search, SearchValue.constData(), sizeof(Search));
        if (!SearchValueEnd.isEmpty()) std::memcpy(&SearchEnd2, SearchValueEnd.constData(), sizeof(SearchEnd2));
        return CompareTyped(Current, Search, SearchEnd2, Type);
    }
    case ValueType::Double: {
        double Current;
        std::memcpy(&Current, Data, sizeof(Current));
        double Search = 0;
        double SearchEnd2 = 0;
        if (!SearchValue.isEmpty()) std::memcpy(&Search, SearchValue.constData(), sizeof(Search));
        if (!SearchValueEnd.isEmpty()) std::memcpy(&SearchEnd2, SearchValueEnd.constData(), sizeof(SearchEnd2));
        return CompareTyped(Current, Search, SearchEnd2, Type);
    }
    case ValueType::Pointer: {
        uint64_t Current;
        std::memcpy(&Current, Data, sizeof(Current));
        uint64_t Search = 0;
        uint64_t SearchEnd2 = 0;
        if (!SearchValue.isEmpty()) std::memcpy(&Search, SearchValue.constData(), sizeof(Search));
        if (!SearchValueEnd.isEmpty()) std::memcpy(&SearchEnd2, SearchValueEnd.constData(), sizeof(SearchEnd2));
        return CompareTyped(Current, Search, SearchEnd2, Type);
    }
    case ValueType::String: {
        if (Type != ScanType::Exact)
            return false;
        return std::memcmp(Data, SearchValue.constData(), SearchValue.size()) == 0;
    }
    case ValueType::ByteArray: {
        return false;
    }
    }

    return false;
}

bool ScanEngine::IsScanning() const
{
    return Scanning.loadRelaxed() != 0;
}

const QVector<ScanResult>& ScanEngine::GetResults() const
{
    return Results;
}

void ScanEngine::Cancel()
{
    Cancelled.storeRelaxed(1);
}

void ScanEngine::Reset()
{
    Cancel();
    Watcher.waitForFinished();
    Scanning.storeRelaxed(0);
    Cancelled.storeRelaxed(0);
    QMutexLocker Lock(&ResultMutex);
    Results.clear();
}

QVector<ScanResult> ScanEngine::ScanFirstChunk(ICore* Core, const ScanChunk& Chunk, ScanType Type, ValueType ValType, const QByteArray& SearchValue, const QByteArray& SearchValueEnd)
{
    QVector<ScanResult> LocalResults;

    QByteArray Buffer(static_cast<int>(Chunk.Size), '\0');
    if (!Core->ReadMemory(Chunk.Base, Buffer.data(), Chunk.Size))
        return LocalResults;

    if (ValType == ValueType::ByteArray) {
        QVector<PatternByte> Pattern = ParsePattern(QString::fromUtf8(SearchValue));
        if (Pattern.isEmpty())
            return LocalResults;

        size_t PatternSize = static_cast<size_t>(Pattern.size());
        for (size_t I = 0; I + PatternSize <= Chunk.Size; ++I) {
            if (Cancelled.loadRelaxed())
                break;

            if (MatchPattern(Buffer.constData() + I, Chunk.Size - I, Pattern)) {
                ScanResult Result;
                Result.Addr = Chunk.Base + I;
                Result.Value = Buffer.mid(static_cast<int>(I), static_cast<int>(PatternSize));
                Result.PreviousValue = Result.Value;
                LocalResults.append(Result);
            }
        }
        return LocalResults;
    }

    int ValSize = ValueTypeSize(ValType);
    if (ValType == ValueType::String)
        ValSize = SearchValue.size();

    if (ValSize <= 0)
        return LocalResults;

    int Alignment = 1;
    if (ValType != ValueType::String && ValType != ValueType::ByteArray)
        Alignment = ValSize;

    for (size_t I = 0; I + static_cast<size_t>(ValSize) <= Chunk.Size; I += Alignment) {
        if (Cancelled.loadRelaxed())
            break;

        if (CompareValue(Buffer.constData() + I, SearchValue, SearchValueEnd, Type, ValType)) {
            ScanResult Result;
            Result.Addr = Chunk.Base + I;
            Result.Value = Buffer.mid(static_cast<int>(I), ValSize);
            Result.PreviousValue = Result.Value;
            LocalResults.append(Result);
        }
    }

    return LocalResults;
}

QVector<ScanResult> ScanEngine::ScanNextBatch(ICore* Core, const QVector<ScanResult>& Batch, ScanType Type, ValueType ValType, const QByteArray& SearchValue, const QByteArray& SearchValueEnd)
{
    QVector<ScanResult> LocalResults;

    int ValSize = ValueTypeSize(ValType);
    if (ValType == ValueType::String)
        ValSize = SearchValue.size();
    if (ValType == ValueType::ByteArray)
        ValSize = Batch.isEmpty() ? 0 : Batch[0].Value.size();

    if (ValSize <= 0)
        return LocalResults;

    QByteArray ReadBuf(ValSize, '\0');

    for (const ScanResult& Prev : Batch) {
        if (Cancelled.loadRelaxed())
            break;

        if (!Core->ReadMemory(Prev.Addr, ReadBuf.data(), ValSize))
            continue;

        bool Match = false;

        if (Type == ScanType::Changed) {
            Match = (ReadBuf != Prev.Value);
        } else if (Type == ScanType::Unchanged) {
            Match = (ReadBuf == Prev.Value);
        } else if (ValType == ValueType::ByteArray) {
            QVector<PatternByte> Pattern = ParsePattern(QString::fromUtf8(SearchValue));
            Match = MatchPattern(ReadBuf.constData(), ValSize, Pattern);
        } else {
            Match = CompareValue(ReadBuf.constData(), SearchValue, SearchValueEnd, Type, ValType);
        }

        if (Match) {
            ScanResult Result;
            Result.Addr = Prev.Addr;
            Result.Value = ReadBuf;
            Result.PreviousValue = Prev.Value;
            LocalResults.append(Result);
        }
    }

    return LocalResults;
}

void ScanEngine::StartFirstScan(ICore* Core, ScanType Type, ValueType ValType, QVariant Value, QVariant ValueEnd)
{
    if (IsScanning())
        return;

    Scanning.storeRelaxed(1);
    Cancelled.storeRelaxed(0);
    Results.clear();
    CurrentValueType = ValType;

    QByteArray SearchValue;
    QByteArray SearchValueEnd;

    if (ValType == ValueType::ByteArray) {
        SearchValue = Value.toString().toUtf8();
    } else {
        if (Value.isValid() && Type != ScanType::Unknown)
            SearchValue = VariantToBytes(Value, ValType);
        if (ValueEnd.isValid())
            SearchValueEnd = VariantToBytes(ValueEnd, ValType);
    }

    QList<MemoryRegion> Regions = Core->GetMemoryRegions();

    QVector<ScanChunk> Chunks;
    constexpr size_t MaxChunkSize = 4 * 1024 * 1024;

    for (const MemoryRegion& Region : Regions) {
        size_t Remaining = Region.Size;
        Address CurrentBase = Region.Base;

        while (Remaining > 0) {
            ScanChunk Chunk;
            Chunk.Base = CurrentBase;
            Chunk.Size = std::min(Remaining, MaxChunkSize);
            Chunks.append(Chunk);
            CurrentBase += Chunk.Size;
            Remaining -= Chunk.Size;
        }
    }

    auto Future = QtConcurrent::run([this, Core, Chunks, Type, ValType, SearchValue, SearchValueEnd]() {
        QVector<QVector<ScanResult>> AllResults(Chunks.size());
        QAtomicInt CompletedChunks(0);
        int TotalChunks = Chunks.size();

        auto ProcessChunk = [&](int Index) {
            if (Cancelled.loadRelaxed())
                return;

            AllResults[Index] = ScanFirstChunk(Core, Chunks[Index], Type, ValType, SearchValue, SearchValueEnd);

            int Done = CompletedChunks.fetchAndAddRelaxed(1) + 1;
            int Percent = TotalChunks > 0 ? (Done * 100 / TotalChunks) : 100;
            QMetaObject::invokeMethod(this, [this, Percent]() {
                emit ScanProgress(Percent);
            }, Qt::QueuedConnection);
        };

        QVector<QFuture<void>> Futures;
        int ThreadCount = QThread::idealThreadCount();
        if (ThreadCount < 2) ThreadCount = 2;

        for (int I = 0; I < Chunks.size(); I += ThreadCount) {
            Futures.clear();
            int BatchEnd = std::min(I + ThreadCount, static_cast<int>(Chunks.size()));
            for (int J = I; J < BatchEnd; ++J) {
                int Idx = J;
                Futures.append(QtConcurrent::run([&ProcessChunk, Idx]() {
                    ProcessChunk(Idx);
                }));
            }
            for (auto& F : Futures) {
                F.waitForFinished();
            }
        }

        QVector<ScanResult> MergedResults;
        for (const auto& Partial : AllResults) {
            MergedResults.append(Partial);
        }

        QMutexLocker Lock(&ResultMutex);
        Results = std::move(MergedResults);
        Scanning.storeRelaxed(0);

        int Count = Results.size();
        QMetaObject::invokeMethod(this, [this, Count]() {
            emit ScanComplete(Count);
        }, Qt::QueuedConnection);
    });

    Watcher.setFuture(Future);
}

void ScanEngine::StartNextScan(ICore* Core, ScanType Type, QVariant Value, QVariant ValueEnd)
{
    if (IsScanning())
        return;

    if (Results.isEmpty())
        return;

    Scanning.storeRelaxed(1);
    Cancelled.storeRelaxed(0);

    ValueType ValType = CurrentValueType;

    QByteArray SearchValue;
    QByteArray SearchValueEnd;

    if (ValType == ValueType::ByteArray) {
        SearchValue = Value.toString().toUtf8();
    } else {
        if (Value.isValid() && Type != ScanType::Changed && Type != ScanType::Unchanged)
            SearchValue = VariantToBytes(Value, ValType);
        if (ValueEnd.isValid())
            SearchValueEnd = VariantToBytes(ValueEnd, ValType);
    }

    QVector<ScanResult> PreviousResults;
    {
        QMutexLocker Lock(&ResultMutex);
        PreviousResults = Results;
    }

    int ThreadCount = QThread::idealThreadCount();
    if (ThreadCount < 2) ThreadCount = 2;

    int BatchSize = std::max(1, static_cast<int>(PreviousResults.size()) / ThreadCount);

    QVector<QPair<int, int>> Batches;
    for (int I = 0; I < static_cast<int>(PreviousResults.size()); I += BatchSize) {
        int End = std::min(I + BatchSize, static_cast<int>(PreviousResults.size()));
        Batches.append({I, End});
    }

    auto Future = QtConcurrent::run([this, Core, PreviousResults, Batches, Type, ValType, SearchValue, SearchValueEnd]() {
        QVector<QVector<ScanResult>> AllResults(Batches.size());
        QAtomicInt CompletedBatches(0);
        int TotalBatches = Batches.size();

        QVector<QFuture<void>> Futures;

        for (int I = 0; I < Batches.size(); ++I) {
            int Idx = I;
            Futures.append(QtConcurrent::run([&, Idx]() {
                if (Cancelled.loadRelaxed())
                    return;

                int Start = Batches[Idx].first;
                int End = Batches[Idx].second;
                QVector<ScanResult> Batch(PreviousResults.begin() + Start, PreviousResults.begin() + End);

                AllResults[Idx] = ScanNextBatch(Core, Batch, Type, ValType, SearchValue, SearchValueEnd);

                int Done = CompletedBatches.fetchAndAddRelaxed(1) + 1;
                int Percent = TotalBatches > 0 ? (Done * 100 / TotalBatches) : 100;
                QMetaObject::invokeMethod(this, [this, Percent]() {
                    emit ScanProgress(Percent);
                }, Qt::QueuedConnection);
            }));
        }

        for (auto& F : Futures) {
            F.waitForFinished();
        }

        QVector<ScanResult> MergedResults;
        for (const auto& Partial : AllResults) {
            MergedResults.append(Partial);
        }

        QMutexLocker Lock(&ResultMutex);
        Results = std::move(MergedResults);
        Scanning.storeRelaxed(0);

        int Count = Results.size();
        QMetaObject::invokeMethod(this, [this, Count]() {
            emit ScanComplete(Count);
        }, Qt::QueuedConnection);
    });

    Watcher.setFuture(Future);
}

}
