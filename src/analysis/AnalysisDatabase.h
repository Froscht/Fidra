#pragma once

#include "AnalysisTypes.h"
#include <QObject>
#include <QMap>
#include <QMultiMap>
#include <QSet>
#include <QReadWriteLock>
#include <QJsonObject>
#include <QJsonArray>

namespace Fidra {

class AnalysisDatabase : public QObject {
    Q_OBJECT

public:
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

    void AddFunction(const AnalyzedFunction& Func);
    void UpdateFunction(Address Start, const AnalyzedFunction& Func);
    AnalyzedFunction GetFunction(Address Addr) const;
    AnalyzedFunction GetFunctionContaining(Address Addr) const;
    bool HasFunction(Address Addr) const;
    QList<AnalyzedFunction> GetAllFunctions() const;
    int FunctionCount() const;

    void AddXref(const Xref& Ref);
    QList<Xref> GetXrefsTo(Address Addr) const;
    QList<Xref> GetXrefsFrom(Address Addr) const;
    int XrefCount() const;

    void AddString(const AnalyzedString& Str);
    AnalyzedString GetString(Address Addr) const;
    bool HasString(Address Addr) const;
    QList<AnalyzedString> GetAllStrings() const;
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

    const Segment* GetSegmentAt(Address Addr) const;
    bool IsCodeAddress(Address Addr) const;
    bool IsDataAddress(Address Addr) const;
    bool IsAddressValid(Address Addr) const;

    QByteArray ReadBytes(Address Addr, size_t Size) const;

    QJsonObject ExportToJson() const;
    void ImportFromJson(const QJsonObject& Root);

signals:
    void FunctionAdded(Address Addr, const QString& Name);
    void StringFound(Address Addr, const QString& Value);
    void AnalysisUpdated();

private:
    mutable QReadWriteLock Lock;
    BinaryInfo Binary;
    QMap<Address, AnalyzedInstruction> Instructions;
    QMap<Address, AnalyzedFunction> Functions;
    QMultiMap<Address, Xref> XrefsTo;
    QMultiMap<Address, Xref> XrefsFrom;
    QMap<Address, AnalyzedString> Strings;
    QMap<Address, ItemType> ItemTypes;
    QMap<Address, QString> Names;
    QMap<Address, QString> Comments;
};

}
