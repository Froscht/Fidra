#include "AddressList.h"

namespace Fidra {

AddressList::AddressList(QObject* Parent)
    : QAbstractTableModel(Parent)
{
}

AddressList::~AddressList() = default;

int AddressList::rowCount(const QModelIndex& Parent) const
{
    if (Parent.isValid())
        return 0;
    return Entries.size();
}

int AddressList::columnCount(const QModelIndex& Parent) const
{
    if (Parent.isValid())
        return 0;
    return ColCount;
}

QVariant AddressList::data(const QModelIndex& Index, int Role) const
{
    if (!Index.isValid() || Index.row() >= Entries.size())
        return {};

    const AddressEntry& Entry = Entries[Index.row()];

    if (Index.column() == ColFrozen) {
        if (Role == Qt::CheckStateRole)
            return Entry.Frozen ? Qt::Checked : Qt::Unchecked;
        return {};
    }

    if (Role == Qt::DisplayRole || Role == Qt::EditRole) {
        switch (Index.column()) {
        case ColLabel:
            return Entry.Label;
        case ColAddress:
            return QString("0x%1").arg(Entry.Addr, 16, 16, QChar('0')).toUpper();
        case ColType:
            return ValueTypeName(Entry.Type);
        case ColValue:
            return FormatValue(Entry.CurrentValue, Entry.Type);
        default:
            return {};
        }
    }

    return {};
}

QVariant AddressList::headerData(int Section, Qt::Orientation Orientation, int Role) const
{
    if (Orientation != Qt::Horizontal || Role != Qt::DisplayRole)
        return {};

    switch (Section) {
    case ColFrozen:
        return QStringLiteral("Frozen");
    case ColLabel:
        return QStringLiteral("Name");
    case ColAddress:
        return QStringLiteral("Address");
    case ColType:
        return QStringLiteral("Type");
    case ColValue:
        return QStringLiteral("Value");
    default:
        return {};
    }
}

Qt::ItemFlags AddressList::flags(const QModelIndex& Index) const
{
    if (!Index.isValid())
        return Qt::NoItemFlags;

    Qt::ItemFlags BaseFlags = Qt::ItemIsEnabled | Qt::ItemIsSelectable;

    if (Index.column() == ColFrozen)
        BaseFlags |= Qt::ItemIsUserCheckable;

    if (Index.column() == ColLabel)
        BaseFlags |= Qt::ItemIsEditable;

    return BaseFlags;
}

bool AddressList::setData(const QModelIndex& Index, const QVariant& Value, int Role)
{
    if (!Index.isValid() || Index.row() >= Entries.size())
        return false;

    AddressEntry& Entry = Entries[Index.row()];

    if (Index.column() == ColFrozen && Role == Qt::CheckStateRole) {
        Entry.Frozen = (Value.toInt() == Qt::Checked);
        if (Entry.Frozen)
            Entry.FrozenValue = Entry.CurrentValue;
        emit dataChanged(Index, Index, {Role});
        return true;
    }

    if (Index.column() == ColLabel && Role == Qt::EditRole) {
        Entry.Label = Value.toString();
        emit dataChanged(Index, Index, {Role});
        return true;
    }

    return false;
}

void AddressList::AddEntry(const AddressEntry& Entry)
{
    int Row = Entries.size();
    beginInsertRows(QModelIndex(), Row, Row);
    Entries.append(Entry);
    endInsertRows();
}

void AddressList::RemoveEntry(int Row)
{
    if (Row < 0 || Row >= Entries.size())
        return;
    beginRemoveRows(QModelIndex(), Row, Row);
    Entries.remove(Row);
    endRemoveRows();
}

void AddressList::Clear()
{
    if (Entries.isEmpty())
        return;
    beginResetModel();
    Entries.clear();
    endResetModel();
}

void AddressList::UpdateValues(ICore* Core)
{
    if (!Core || !Core->IsAttached() || Entries.isEmpty())
        return;

    for (int I = 0; I < Entries.size(); ++I) {
        AddressEntry& Entry = Entries[I];
        int Size = ValueTypeSize(Entry.Type);
        if (Size <= 0) {
            if (Entry.Type == ValueType::String) {
                QByteArray Buffer(256, '\0');
                if (Core->ReadMemory(Entry.Addr, Buffer.data(), Buffer.size()))
                    Entry.CurrentValue = Buffer.left(Buffer.indexOf('\0'));
                else
                    Entry.CurrentValue.clear();
            } else if (Entry.Type == ValueType::ByteArray) {
                if (!Entry.CurrentValue.isEmpty()) {
                    QByteArray Buffer(Entry.CurrentValue.size(), '\0');
                    if (Core->ReadMemory(Entry.Addr, Buffer.data(), Buffer.size()))
                        Entry.CurrentValue = Buffer;
                }
            }
        } else {
            QByteArray Buffer(Size, '\0');
            if (Core->ReadMemory(Entry.Addr, Buffer.data(), Size))
                Entry.CurrentValue = Buffer;
        }
    }

    emit dataChanged(index(0, ColValue), index(Entries.size() - 1, ColValue), {Qt::DisplayRole});
}

void AddressList::WriteFrozenValues(ICore* Core)
{
    if (!Core || !Core->IsAttached())
        return;

    for (const AddressEntry& Entry : Entries) {
        if (Entry.Frozen && !Entry.FrozenValue.isEmpty())
            Core->WriteMemory(Entry.Addr, Entry.FrozenValue.constData(), Entry.FrozenValue.size());
    }
}

void AddressList::SaveToJson(const QString& FilePath)
{
    QJsonArray Array;

    for (const AddressEntry& Entry : Entries) {
        QJsonObject Obj;
        Obj["Label"] = Entry.Label;
        Obj["Address"] = QString("0x%1").arg(Entry.Addr, 16, 16, QChar('0')).toUpper();
        Obj["Type"] = static_cast<int>(Entry.Type);
        Obj["Frozen"] = Entry.Frozen;
        Obj["FrozenValue"] = QString::fromLatin1(Entry.FrozenValue.toBase64());
        Array.append(Obj);
    }

    QJsonDocument Doc(Array);
    QFile File(FilePath);
    if (File.open(QIODevice::WriteOnly))
        File.write(Doc.toJson(QJsonDocument::Indented));
}

void AddressList::LoadFromJson(const QString& FilePath, ICore* Core)
{
    QFile File(FilePath);
    if (!File.open(QIODevice::ReadOnly))
        return;

    QJsonDocument Doc = QJsonDocument::fromJson(File.readAll());
    if (!Doc.isArray())
        return;

    beginResetModel();
    Entries.clear();

    QJsonArray Array = Doc.array();
    for (const QJsonValue& Val : Array) {
        QJsonObject Obj = Val.toObject();
        AddressEntry Entry;
        Entry.Label = Obj["Label"].toString();
        QString AddrStr = Obj["Address"].toString();
        Entry.Addr = AddrStr.toULongLong(nullptr, 16);
        Entry.Type = static_cast<ValueType>(Obj["Type"].toInt());
        Entry.Frozen = Obj["Frozen"].toBool();
        Entry.FrozenValue = QByteArray::fromBase64(Obj["FrozenValue"].toString().toLatin1());
        Entry.CurrentValue = QByteArray(qMax(ValueTypeSize(Entry.Type), 1), '\0');
        Entries.append(Entry);
    }

    endResetModel();

    if (Core && Core->IsAttached())
        UpdateValues(Core);
}

AddressEntry& AddressList::GetEntry(int Row)
{
    return Entries[Row];
}

int AddressList::EntryCount() const
{
    return Entries.size();
}

QString AddressList::FormatValue(const QByteArray& Data, ValueType Type)
{
    if (Data.isEmpty())
        return QStringLiteral("??");

    switch (Type) {
    case ValueType::Byte:
        if (Data.size() >= 1)
            return QString::number(static_cast<uint8_t>(Data[0]));
        break;

    case ValueType::Int16:
        if (Data.size() >= 2) {
            int16_t Val;
            memcpy(&Val, Data.constData(), sizeof(Val));
            return QString::number(Val);
        }
        break;

    case ValueType::Int32:
        if (Data.size() >= 4) {
            int32_t Val;
            memcpy(&Val, Data.constData(), sizeof(Val));
            return QString::number(Val);
        }
        break;

    case ValueType::Int64:
        if (Data.size() >= 8) {
            int64_t Val;
            memcpy(&Val, Data.constData(), sizeof(Val));
            return QString::number(Val);
        }
        break;

    case ValueType::Float:
        if (Data.size() >= 4) {
            float Val;
            memcpy(&Val, Data.constData(), sizeof(Val));
            return QString::number(static_cast<double>(Val), 'f', 4);
        }
        break;

    case ValueType::Double:
        if (Data.size() >= 8) {
            double Val;
            memcpy(&Val, Data.constData(), sizeof(Val));
            return QString::number(Val, 'f', 6);
        }
        break;

    case ValueType::String:
        return QString::fromUtf8(Data);

    case ValueType::ByteArray: {
        QString Hex;
        Hex.reserve(Data.size() * 3);
        for (int I = 0; I < Data.size(); ++I) {
            if (I > 0)
                Hex += ' ';
            Hex += QString("%1").arg(static_cast<uint8_t>(Data[I]), 2, 16, QChar('0')).toUpper();
        }
        return Hex;
    }

    case ValueType::Pointer:
        if (Data.size() >= 8) {
            uint64_t Val;
            memcpy(&Val, Data.constData(), sizeof(Val));
            return QString("0x%1").arg(Val, 16, 16, QChar('0')).toUpper();
        }
        break;
    }

    return QStringLiteral("??");
}

int AddressList::ValueTypeSize(ValueType Type)
{
    switch (Type) {
    case ValueType::Byte:      return 1;
    case ValueType::Int16:     return 2;
    case ValueType::Int32:     return 4;
    case ValueType::Int64:     return 8;
    case ValueType::Float:     return 4;
    case ValueType::Double:    return 8;
    case ValueType::Pointer:   return 8;
    case ValueType::String:    return -1;
    case ValueType::ByteArray: return -1;
    }
    return -1;
}

QString AddressList::ValueTypeName(ValueType Type)
{
    switch (Type) {
    case ValueType::Byte:      return QStringLiteral("Byte");
    case ValueType::Int16:     return QStringLiteral("Int16");
    case ValueType::Int32:     return QStringLiteral("Int32");
    case ValueType::Int64:     return QStringLiteral("Int64");
    case ValueType::Float:     return QStringLiteral("Float");
    case ValueType::Double:    return QStringLiteral("Double");
    case ValueType::String:    return QStringLiteral("String");
    case ValueType::ByteArray: return QStringLiteral("ByteArray");
    case ValueType::Pointer:   return QStringLiteral("Pointer");
    }
    return QStringLiteral("Unknown");
}

}
