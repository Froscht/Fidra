#include "StructTypes.h"
#include <algorithm>

namespace Fidra {

QJsonObject StructField::ToJson() const
{
    QJsonObject Obj;
    Obj["name"] = Name;
    Obj["type"] = TypeDatabase::FieldTypeToString(Type);
    Obj["offset"] = Offset;
    Obj["size"] = Size;
    Obj["arrayCount"] = ArrayCount;
    Obj["referencedType"] = ReferencedType;
    Obj["comment"] = Comment;
    Obj["id"] = Id.toString();
    Obj["bitOffset"] = BitOffset;
    Obj["bitSize"] = BitSize;
    return Obj;
}

StructField StructField::FromJson(const QJsonObject& Obj)
{
    StructField F;
    F.Name = Obj["name"].toString();
    F.Type = TypeDatabase::StringToFieldType(Obj["type"].toString());
    F.Offset = Obj["offset"].toInt();
    F.Size = Obj["size"].toInt();
    F.ArrayCount = Obj["arrayCount"].toInt(1);
    F.ReferencedType = Obj["referencedType"].toString();
    F.Comment = Obj["comment"].toString();
    QString IdStr = Obj["id"].toString();
    if (!IdStr.isEmpty()) {
        F.Id = QUuid::fromString(IdStr);
    }
    F.BitOffset = Obj["bitOffset"].toInt();
    F.BitSize = Obj["bitSize"].toInt();
    return F;
}

void StructDefinition::RecalculateSize()
{
    int MaxEnd = 0;
    for (const auto& Field : Fields) {
        int End = Field.Offset + Field.TotalSize();
        if (End > MaxEnd) {
            MaxEnd = End;
        }
    }
    Size = MaxEnd;
}

void StructDefinition::InsertField(int Offset, StructField Field)
{
    Field.Offset = Offset;

    int InsertIdx = 0;
    for (int I = 0; I < Fields.size(); ++I) {
        if (Fields[I].Offset <= Offset) {
            InsertIdx = I + 1;
        }
    }
    Fields.insert(InsertIdx, Field);
    RecalculateSize();
}

void StructDefinition::RemoveField(const QUuid& FieldId)
{
    for (int I = 0; I < Fields.size(); ++I) {
        if (Fields[I].Id == FieldId) {
            Fields.removeAt(I);
            RecalculateSize();
            return;
        }
    }
}

StructField* StructDefinition::GetFieldAt(int Offset)
{
    for (auto& Field : Fields) {
        if (Field.Offset == Offset) {
            return &Field;
        }
    }
    return nullptr;
}

QJsonObject StructDefinition::ToJson() const
{
    QJsonObject Obj;
    Obj["name"] = Name;
    Obj["size"] = Size;
    Obj["id"] = Id.toString();
    Obj["parentStruct"] = ParentStruct;

    QJsonArray FieldArray;
    for (const auto& Field : Fields) {
        FieldArray.append(Field.ToJson());
    }
    Obj["fields"] = FieldArray;
    return Obj;
}

StructDefinition StructDefinition::FromJson(const QJsonObject& Obj)
{
    StructDefinition Def;
    Def.Name = Obj["name"].toString();
    Def.Size = Obj["size"].toInt();
    QString IdStr = Obj["id"].toString();
    if (!IdStr.isEmpty()) {
        Def.Id = QUuid::fromString(IdStr);
    }
    Def.ParentStruct = Obj["parentStruct"].toString();

    QJsonArray FieldArray = Obj["fields"].toArray();
    for (const auto& FieldVal : FieldArray) {
        Def.Fields.append(StructField::FromJson(FieldVal.toObject()));
    }
    return Def;
}

QJsonObject EnumDefinition::ToJson() const
{
    QJsonObject Obj;
    Obj["name"] = Name;
    Obj["underlyingType"] = UnderlyingType;
    Obj["id"] = Id.toString();

    QJsonArray ValArray;
    for (auto It = Values.constBegin(); It != Values.constEnd(); ++It) {
        QJsonObject Entry;
        Entry["value"] = static_cast<double>(It.key());
        Entry["name"] = It.value();
        ValArray.append(Entry);
    }
    Obj["values"] = ValArray;
    return Obj;
}

EnumDefinition EnumDefinition::FromJson(const QJsonObject& Obj)
{
    EnumDefinition Def;
    Def.Name = Obj["name"].toString();
    Def.UnderlyingType = Obj["underlyingType"].toString();
    QString IdStr = Obj["id"].toString();
    if (!IdStr.isEmpty()) {
        Def.Id = QUuid::fromString(IdStr);
    }

    QJsonArray ValArray = Obj["values"].toArray();
    for (const auto& Val : ValArray) {
        QJsonObject Entry = Val.toObject();
        int64_t Key = static_cast<int64_t>(Entry["value"].toDouble());
        QString Name = Entry["name"].toString();
        Def.Values[Key] = Name;
    }
    return Def;
}

TypeDatabase::TypeDatabase()
{
}

void TypeDatabase::AddStruct(const StructDefinition& Def)
{
    Structs[Def.Id] = Def;
}

void TypeDatabase::UpdateStruct(const QUuid& Id, const StructDefinition& Def)
{
    if (Structs.contains(Id)) {
        Structs[Id] = Def;
        Structs[Id].Id = Id;
    }
}

void TypeDatabase::RemoveStruct(const QUuid& Id)
{
    Structs.remove(Id);
}

StructDefinition* TypeDatabase::GetStruct(const QString& Name)
{
    for (auto& Def : Structs) {
        if (Def.Name == Name) {
            return &Def;
        }
    }
    return nullptr;
}

StructDefinition* TypeDatabase::GetStructById(const QUuid& Id)
{
    auto It = Structs.find(Id);
    if (It != Structs.end()) {
        return &It.value();
    }
    return nullptr;
}

QVector<StructDefinition> TypeDatabase::GetAllStructs() const
{
    QVector<StructDefinition> Result;
    Result.reserve(Structs.size());
    for (const auto& Def : Structs) {
        Result.append(Def);
    }
    return Result;
}

void TypeDatabase::AddEnum(const EnumDefinition& Def)
{
    Enums[Def.Id] = Def;
}

void TypeDatabase::RemoveEnum(const QUuid& Id)
{
    Enums.remove(Id);
}

EnumDefinition* TypeDatabase::GetEnum(const QString& Name)
{
    for (auto& Def : Enums) {
        if (Def.Name == Name) {
            return &Def;
        }
    }
    return nullptr;
}

QVector<EnumDefinition> TypeDatabase::GetAllEnums() const
{
    QVector<EnumDefinition> Result;
    Result.reserve(Enums.size());
    for (const auto& Def : Enums) {
        Result.append(Def);
    }
    return Result;
}

QJsonObject TypeDatabase::ExportToJson() const
{
    QJsonObject Root;

    QJsonArray StructArray;
    for (const auto& Def : Structs) {
        StructArray.append(Def.ToJson());
    }
    Root["structs"] = StructArray;

    QJsonArray EnumArray;
    for (const auto& Def : Enums) {
        EnumArray.append(Def.ToJson());
    }
    Root["enums"] = EnumArray;

    return Root;
}

void TypeDatabase::ImportFromJson(const QJsonObject& Obj)
{
    Structs.clear();
    Enums.clear();

    QJsonArray StructArray = Obj["structs"].toArray();
    for (const auto& Val : StructArray) {
        StructDefinition Def = StructDefinition::FromJson(Val.toObject());
        Structs[Def.Id] = Def;
    }

    QJsonArray EnumArray = Obj["enums"].toArray();
    for (const auto& Val : EnumArray) {
        EnumDefinition Def = EnumDefinition::FromJson(Val.toObject());
        Enums[Def.Id] = Def;
    }
}

int TypeDatabase::FieldTypeSize(StructFieldType Type)
{
    switch (Type) {
        case StructFieldType::Int8:
        case StructFieldType::UInt8:
        case StructFieldType::Bool:
            return 1;
        case StructFieldType::Int16:
        case StructFieldType::UInt16:
            return 2;
        case StructFieldType::Int32:
        case StructFieldType::UInt32:
        case StructFieldType::Float:
        case StructFieldType::Pointer32:
            return 4;
        case StructFieldType::Int64:
        case StructFieldType::UInt64:
        case StructFieldType::Double:
        case StructFieldType::Pointer:
        case StructFieldType::Pointer64:
        case StructFieldType::VTable:
        case StructFieldType::FunctionPtr:
            return 8;
        case StructFieldType::CharArray:
        case StructFieldType::WCharArray:
        case StructFieldType::Padding:
        case StructFieldType::Unknown:
        case StructFieldType::Struct:
        case StructFieldType::Enum:
        case StructFieldType::Bitfield:
        case StructFieldType::Array:
            return 0;
    }
    return 0;
}

QString TypeDatabase::FieldTypeToString(StructFieldType Type)
{
    switch (Type) {
        case StructFieldType::Int8: return "int8_t";
        case StructFieldType::UInt8: return "uint8_t";
        case StructFieldType::Int16: return "int16_t";
        case StructFieldType::UInt16: return "uint16_t";
        case StructFieldType::Int32: return "int32_t";
        case StructFieldType::UInt32: return "uint32_t";
        case StructFieldType::Int64: return "int64_t";
        case StructFieldType::UInt64: return "uint64_t";
        case StructFieldType::Float: return "float";
        case StructFieldType::Double: return "double";
        case StructFieldType::Bool: return "bool";
        case StructFieldType::Pointer: return "void*";
        case StructFieldType::Pointer32: return "uint32_t*";
        case StructFieldType::Pointer64: return "uint64_t*";
        case StructFieldType::CharArray: return "char[]";
        case StructFieldType::WCharArray: return "wchar_t[]";
        case StructFieldType::Padding: return "padding";
        case StructFieldType::Unknown: return "unknown";
        case StructFieldType::Struct: return "struct";
        case StructFieldType::Enum: return "enum";
        case StructFieldType::Bitfield: return "bitfield";
        case StructFieldType::Array: return "array";
        case StructFieldType::VTable: return "vtable*";
        case StructFieldType::FunctionPtr: return "func*";
    }
    return "unknown";
}

StructFieldType TypeDatabase::StringToFieldType(const QString& Str)
{
    if (Str == "int8_t") return StructFieldType::Int8;
    if (Str == "uint8_t") return StructFieldType::UInt8;
    if (Str == "int16_t") return StructFieldType::Int16;
    if (Str == "uint16_t") return StructFieldType::UInt16;
    if (Str == "int32_t") return StructFieldType::Int32;
    if (Str == "uint32_t") return StructFieldType::UInt32;
    if (Str == "int64_t") return StructFieldType::Int64;
    if (Str == "uint64_t") return StructFieldType::UInt64;
    if (Str == "float") return StructFieldType::Float;
    if (Str == "double") return StructFieldType::Double;
    if (Str == "bool") return StructFieldType::Bool;
    if (Str == "void*") return StructFieldType::Pointer;
    if (Str == "uint32_t*") return StructFieldType::Pointer32;
    if (Str == "uint64_t*") return StructFieldType::Pointer64;
    if (Str == "char[]") return StructFieldType::CharArray;
    if (Str == "wchar_t[]") return StructFieldType::WCharArray;
    if (Str == "padding") return StructFieldType::Padding;
    if (Str == "unknown") return StructFieldType::Unknown;
    if (Str == "struct") return StructFieldType::Struct;
    if (Str == "enum") return StructFieldType::Enum;
    if (Str == "bitfield") return StructFieldType::Bitfield;
    if (Str == "array") return StructFieldType::Array;
    if (Str == "vtable*") return StructFieldType::VTable;
    if (Str == "func*") return StructFieldType::FunctionPtr;
    return StructFieldType::Unknown;
}

}
