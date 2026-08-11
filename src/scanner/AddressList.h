#pragma once

#include <fidra/Types.h>
#include <fidra/ICore.h>
#include <QAbstractTableModel>
#include <QVector>
#include <QByteArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>

namespace Fidra {

struct AddressEntry {
    QString Label;
    Address Addr;
    ValueType Type;
    QByteArray CurrentValue;
    bool Frozen;
    QByteArray FrozenValue;
};

class AddressList : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        ColFrozen = 0,
        ColLabel,
        ColAddress,
        ColType,
        ColValue,
        ColCount
    };

    explicit AddressList(QObject* Parent = nullptr);
    ~AddressList() override;

    int rowCount(const QModelIndex& Parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& Parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& Index, int Role = Qt::DisplayRole) const override;
    QVariant headerData(int Section, Qt::Orientation Orientation, int Role = Qt::DisplayRole) const override;
    Qt::ItemFlags flags(const QModelIndex& Index) const override;
    bool setData(const QModelIndex& Index, const QVariant& Value, int Role = Qt::EditRole) override;

    void AddEntry(const AddressEntry& Entry);
    void RemoveEntry(int Row);
    void Clear();
    void UpdateValues(ICore* Core);
    void WriteFrozenValues(ICore* Core);
    void SaveToJson(const QString& FilePath);
    void LoadFromJson(const QString& FilePath, ICore* Core);
    AddressEntry& GetEntry(int Row);
    int EntryCount() const;

    static QString FormatValue(const QByteArray& Data, ValueType Type);
    static int ValueTypeSize(ValueType Type);
    static QString ValueTypeName(ValueType Type);

private:
    QVector<AddressEntry> Entries;
};

}
