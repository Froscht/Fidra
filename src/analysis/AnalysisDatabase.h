#pragma once

#include "AnalysisTypes.h"
#include <QObject>
#include <QMap>
#include <QMultiMap>
#include <QHash>
#include <QSet>
#include <QReadWriteLock>
#include <QJsonObject>
#include <QJsonArray>
#include <QAtomicInt>
#include <vector>
#include <atomic>
#include <functional>
#include <optional>

namespace Fidra {

class AnalysisDatabase : public QObject {
    Q_OBJECT

public:
    static constexpr int MaxInstructions = 20000000;

    explicit AnalysisDatabase(QObject* Parent = nullptr);
    ~AnalysisDatabase() override;

    void Clear();

    void SetBinaryInfo(const BinaryInfo& Info);
    BinaryInfo GetBinaryInfo() const;

    void AddInstruction(const AnalyzedInstruction& Inst);
    AnalyzedInstruction GetInstruction(Address Addr) const;
    bool HasInstruction(Address Addr) const;
    QList<AnalyzedInstruction> GetInstructions(Address Start, Address End) const;
    int InstructionCount() const;
    bool InstructionLimitReached() const;
    void ForEachInstruction(const std::function<void(const AnalyzedInstruction&)>& Callback) const;

    void AddFunction(const AnalyzedFunction& Func);
    void UpdateFunction(Address Start, const AnalyzedFunction& Func);
    AnalyzedFunction GetFunction(Address Addr) const;
    AnalyzedFunction GetFunctionContaining(Address Addr) const;
    bool HasFunction(Address Addr) const;
    QList<AnalyzedFunction> GetAllFunctions() const;
    void ForEachFunction(const std::function<void(const AnalyzedFunction&)>& Callback) const;
    int FunctionCount() const;

    void AddXref(const Xref& Ref);
    QList<Xref> GetXrefsTo(Address Addr) const;
    QList<Xref> GetXrefsFrom(Address Addr) const;
    int XrefCount() const;

    void AddString(const AnalyzedString& Str);
    AnalyzedString GetString(Address Addr) const;
    bool HasString(Address Addr) const;
    QList<AnalyzedString> GetAllStrings() const;
    void ForEachString(const std::function<void(const AnalyzedString&)>& Callback) const;
    int StringCount() const;

    void SetItemType(Address Addr, ItemType Type);
    ItemType GetItemType(Address Addr) const;

    void SetName(Address Addr, const QString& Name);
    QString GetName(Address Addr) const;
    bool HasName(Address Addr) const;
    QMap<Address, QString> GetAllNames() const;

    void SetComment(Address Addr, const QString& Comment);
    QString GetComment(Address Addr) const;
    QMap<Address, QString> GetAllComments() const;

    std::optional<Segment> GetSegmentAt(Address Addr) const;
    bool IsCodeAddress(Address Addr) const;
    bool IsDataAddress(Address Addr) const;
    bool IsAddressValid(Address Addr) const;
    void BuildSegmentCache();
    void BuildInstructionIndex();

    QByteArray ReadBytes(Address Addr, size_t Size) const;

    QJsonObject ExportToJson() const;
    void ImportFromJson(const QJsonObject& Root);

signals:
    void FunctionAdded(Address Addr, const QString& Name);
    void StringFound(Address Addr, const QString& Value);
    void AnalysisUpdated();

private:
    const Segment* FindSegmentUnlocked(Address Addr) const;

    mutable QReadWriteLock Lock{QReadWriteLock::Recursive};
    mutable QReadWriteLock InsnLock{QReadWriteLock::Recursive};
    bool LimitWarned = false;
    BinaryInfo Binary;
    QHash<Address, AnalyzedInstruction> Instructions;
    QMap<Address, AnalyzedFunction> Functions;
    QMultiMap<Address, Xref> XrefsTo;
    QMultiMap<Address, Xref> XrefsFrom;
    QMap<Address, AnalyzedString> Strings;
    QHash<Address, ItemType> ItemTypes;
    QMap<Address, QString> Names;
    QMap<Address, QString> Comments;

    struct SegmentRange {
        Address Start;
        Address End;
        int Index;
    };
    std::vector<SegmentRange> SortedSegments;

    std::vector<Address> SortedInsnAddrs;
    bool InsnIndexBuilt = false;
};

}
