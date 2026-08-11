#pragma once

#include <fidra/Types.h>
#include <QString>
#include <QVector>
#include <QMap>
#include <QUuid>
#include <QJsonObject>
#include <QJsonArray>

namespace Fidra {

enum class StructFieldType {
    Int8, UInt8, Int16, UInt16, Int32, UInt32, Int64, UInt64,
    Float, Double, Bool,
    Pointer, Pointer32, Pointer64,
    CharArray, WCharArray,
    Padding, Unknown,
    Struct, Enum, Bitfield, Array, VTable, FunctionPtr
};

struct StructField {
    QString Name;
    StructFieldType Type;
    int Offset;
    int Size;
    int ArrayCount;
    QString ReferencedType;
    QString Comment;
    QUuid Id;
    int BitOffset;
    int BitSize;

    StructField()
        : Type(StructFieldType::Unknown)
        , Offset(0)
        , Size(0)
        , ArrayCount(1)
        , BitOffset(0)
        , BitSize(0)
    {
        Id = QUuid::createUuid();
    }

    int TotalSize() const { return Size * ArrayCount; }
    QJsonObject ToJson() const;
    static StructField FromJson(const QJsonObject& Obj);
};

struct StructDefinition {
    QString Name;
    int Size;
    QVector<StructField> Fields;
    QUuid Id;
    QString ParentStruct;

    StructDefinition() : Size(0) { Id = QUuid::createUuid(); }

    void RecalculateSize();
    void InsertField(int Offset, StructField Field);
    void RemoveField(const QUuid& FieldId);
    StructField* GetFieldAt(int Offset);
    QJsonObject ToJson() const;
    static StructDefinition FromJson(const QJsonObject& Obj);
};

struct EnumDefinition {
    QString Name;
    QString UnderlyingType;
    QMap<int64_t, QString> Values;
    QUuid Id;

    EnumDefinition() { Id = QUuid::createUuid(); }
    QJsonObject ToJson() const;
    static EnumDefinition FromJson(const QJsonObject& Obj);
};

class TypeDatabase {
public:
    TypeDatabase();

    void AddStruct(const StructDefinition& Def);
    void UpdateStruct(const QUuid& Id, const StructDefinition& Def);
    void RemoveStruct(const QUuid& Id);
    StructDefinition* GetStruct(const QString& Name);
    StructDefinition* GetStructById(const QUuid& Id);
    QVector<StructDefinition> GetAllStructs() const;

    void AddEnum(const EnumDefinition& Def);
    void RemoveEnum(const QUuid& Id);
    EnumDefinition* GetEnum(const QString& Name);
    QVector<EnumDefinition> GetAllEnums() const;

    QJsonObject ExportToJson() const;
    void ImportFromJson(const QJsonObject& Obj);

    static int FieldTypeSize(StructFieldType Type);
    static QString FieldTypeToString(StructFieldType Type);
    static StructFieldType StringToFieldType(const QString& Str);

private:
    QMap<QUuid, StructDefinition> Structs;
    QMap<QUuid, EnumDefinition> Enums;
};

}
