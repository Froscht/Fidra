#include "TypeSystem.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QTextStream>
#include <algorithm>

namespace Fidra {

TypeSystem::TypeSystem(QObject* Parent) : QObject(Parent) {}

void TypeSystem::AddStruct(const StructDef& Def) {
    Structs[Def.Name] = Def;
    emit StructAdded(Def.Name);
}

void TypeSystem::RemoveStruct(const QString& Name) {
    Structs.remove(Name);
    emit StructRemoved(Name);
}

StructDef* TypeSystem::GetStruct(const QString& Name) {
    auto It = Structs.find(Name);
    return It != Structs.end() ? &It.value() : nullptr;
}

const StructDef* TypeSystem::GetStruct(const QString& Name) const {
    auto It = Structs.find(Name);
    return It != Structs.end() ? &It.value() : nullptr;
}

QStringList TypeSystem::GetStructNames() const {
    return Structs.keys();
}

void TypeSystem::AddField(const QString& StructName, const StructField& Field) {
    auto* Def = GetStruct(StructName);
    if (!Def) return;
    Def->Fields.append(Field);
    std::sort(Def->Fields.begin(), Def->Fields.end(),
        [](const StructField& A, const StructField& B) { return A.Offset < B.Offset; });
    int End = 0;
    for (const auto& F : Def->Fields) End = qMax(End, F.Offset + F.Size);
    Def->TotalSize = End;
    emit StructChanged(StructName);
}

void TypeSystem::RemoveField(const QString& StructName, int Offset) {
    auto* Def = GetStruct(StructName);
    if (!Def) return;
    for (int I = 0; I < Def->Fields.size(); ++I) {
        if (Def->Fields[I].Offset == Offset) {
            Def->Fields.removeAt(I);
            break;
        }
    }
    emit StructChanged(StructName);
}

void TypeSystem::ModifyField(const QString& StructName, int Offset, const StructField& NewField) {
    auto* Def = GetStruct(StructName);
    if (!Def) return;
    for (auto& F : Def->Fields) {
        if (F.Offset == Offset) {
            F = NewField;
            break;
        }
    }
    emit StructChanged(StructName);
}

void TypeSystem::InsertPadding(const QString& StructName, int Offset, int Size) {
    StructField Pad;
    Pad.Name = QString("pad_%1").arg(Offset, 4, 16, QChar('0'));
    Pad.Type = FieldType::Padding;
    Pad.Offset = Offset;
    Pad.Size = Size;
    Pad.ArrayCount = 1;
    Pad.BitFieldWidth = 0;
    Pad.IsCollapsed = false;
    AddField(StructName, Pad);
}

void TypeSystem::AutoFillPadding(const QString& StructName) {
    auto* Def = GetStruct(StructName);
    if (!Def || Def->Fields.isEmpty()) return;

    QVector<StructField> NewFields;
    int CurrentOffset = 0;

    std::sort(Def->Fields.begin(), Def->Fields.end(),
        [](const StructField& A, const StructField& B) { return A.Offset < B.Offset; });

    for (const auto& F : Def->Fields) {
        if (F.Type == FieldType::Padding) continue;
        if (F.Offset > CurrentOffset) {
            StructField Pad;
            Pad.Name = QString("pad_%1").arg(CurrentOffset, 4, 16, QChar('0'));
            Pad.Type = FieldType::Padding;
            Pad.Offset = CurrentOffset;
            Pad.Size = F.Offset - CurrentOffset;
            Pad.ArrayCount = 1;
            Pad.BitFieldWidth = 0;
            Pad.IsCollapsed = false;
            NewFields.append(Pad);
        }
        NewFields.append(F);
        CurrentOffset = F.Offset + F.Size;
    }

    if (CurrentOffset < Def->TotalSize) {
        StructField Pad;
        Pad.Name = QString("pad_%1").arg(CurrentOffset, 4, 16, QChar('0'));
        Pad.Type = FieldType::Padding;
        Pad.Offset = CurrentOffset;
        Pad.Size = Def->TotalSize - CurrentOffset;
        Pad.ArrayCount = 1;
        Pad.BitFieldWidth = 0;
        Pad.IsCollapsed = false;
        NewFields.append(Pad);
    }

    Def->Fields = NewFields;
    emit StructChanged(StructName);
}

int TypeSystem::FieldTypeSize(FieldType Type) {
    switch (Type) {
        case FieldType::Int8: case FieldType::UInt8: case FieldType::Bool: case FieldType::Char: case FieldType::Hex8: return 1;
        case FieldType::Int16: case FieldType::UInt16: case FieldType::WChar: case FieldType::Hex16: return 2;
        case FieldType::Int32: case FieldType::UInt32: case FieldType::Float: case FieldType::Hex32: return 4;
        case FieldType::Int64: case FieldType::UInt64: case FieldType::Double: case FieldType::Hex64: case FieldType::Pointer: case FieldType::FunctionPtr: case FieldType::VTable: return 8;
        case FieldType::Padding: return 1;
        case FieldType::CString: case FieldType::WString: return 8;
        default: return 4;
    }
}

QString TypeSystem::FieldTypeToString(FieldType Type) {
    switch (Type) {
        case FieldType::Int8: return "int8"; case FieldType::UInt8: return "uint8";
        case FieldType::Int16: return "int16"; case FieldType::UInt16: return "uint16";
        case FieldType::Int32: return "int32"; case FieldType::UInt32: return "uint32";
        case FieldType::Int64: return "int64"; case FieldType::UInt64: return "uint64";
        case FieldType::Float: return "float"; case FieldType::Double: return "double";
        case FieldType::Bool: return "bool"; case FieldType::Char: return "char"; case FieldType::WChar: return "wchar";
        case FieldType::Pointer: return "pointer"; case FieldType::Array: return "array";
        case FieldType::CString: return "cstring"; case FieldType::WString: return "wstring";
        case FieldType::Struct: return "struct"; case FieldType::Padding: return "padding";
        case FieldType::Hex8: return "hex8"; case FieldType::Hex16: return "hex16";
        case FieldType::Hex32: return "hex32"; case FieldType::Hex64: return "hex64";
        case FieldType::VTable: return "vtable"; case FieldType::FunctionPtr: return "funcptr";
        case FieldType::BitField: return "bitfield";
    }
    return "uint32";
}

FieldType TypeSystem::StringToFieldType(const QString& Str) {
    static const QMap<QString, FieldType> Map = {
        {"int8", FieldType::Int8}, {"uint8", FieldType::UInt8}, {"int16", FieldType::Int16},
        {"uint16", FieldType::UInt16}, {"int32", FieldType::Int32}, {"uint32", FieldType::UInt32},
        {"int64", FieldType::Int64}, {"uint64", FieldType::UInt64}, {"float", FieldType::Float},
        {"double", FieldType::Double}, {"bool", FieldType::Bool}, {"char", FieldType::Char},
        {"wchar", FieldType::WChar}, {"pointer", FieldType::Pointer}, {"array", FieldType::Array},
        {"cstring", FieldType::CString}, {"wstring", FieldType::WString}, {"struct", FieldType::Struct},
        {"padding", FieldType::Padding}, {"hex8", FieldType::Hex8}, {"hex16", FieldType::Hex16},
        {"hex32", FieldType::Hex32}, {"hex64", FieldType::Hex64}, {"vtable", FieldType::VTable},
        {"funcptr", FieldType::FunctionPtr}, {"bitfield", FieldType::BitField}
    };
    return Map.value(Str.toLower(), FieldType::UInt32);
}

QStringList TypeSystem::AllFieldTypeStrings() {
    return {"int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64",
            "float", "double", "bool", "char", "wchar", "pointer", "array",
            "cstring", "wstring", "struct", "padding", "hex8", "hex16", "hex32", "hex64",
            "vtable", "funcptr", "bitfield"};
}

bool TypeSystem::SaveToFile(const QString& Path) {
    QJsonObject Root;
    QJsonArray StructArr;
    for (auto It = Structs.begin(); It != Structs.end(); ++It) {
        QJsonObject Obj;
        Obj["name"] = It->Name;
        Obj["totalSize"] = It->TotalSize;
        Obj["baseClass"] = It->BaseClass;
        Obj["sampleAddress"] = static_cast<qint64>(It->SampleAddress);
        QJsonArray Fields;
        for (const auto& F : It->Fields) {
            QJsonObject FObj;
            FObj["name"] = F.Name;
            FObj["type"] = FieldTypeToString(F.Type);
            FObj["offset"] = F.Offset;
            FObj["size"] = F.Size;
            FObj["arrayCount"] = F.ArrayCount;
            FObj["bitFieldWidth"] = F.BitFieldWidth;
            FObj["pointedType"] = F.PointedType;
            Fields.append(FObj);
        }
        Obj["fields"] = Fields;
        StructArr.append(Obj);
    }
    Root["structs"] = StructArr;

    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly)) return false;
    File.write(QJsonDocument(Root).toJson());
    File.close();
    return true;
}

bool TypeSystem::LoadFromFile(const QString& Path) {
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly)) return false;
    QJsonDocument Doc = QJsonDocument::fromJson(File.readAll());
    File.close();
    if (!Doc.isObject()) return false;

    Structs.clear();
    QJsonArray StructArr = Doc.object()["structs"].toArray();
    for (const auto& Val : StructArr) {
        QJsonObject Obj = Val.toObject();
        StructDef Def;
        Def.Name = Obj["name"].toString();
        Def.TotalSize = Obj["totalSize"].toInt();
        Def.BaseClass = Obj["baseClass"].toString();
        Def.SampleAddress = static_cast<Address>(Obj["sampleAddress"].toInteger());
        QJsonArray Fields = Obj["fields"].toArray();
        for (const auto& FVal : Fields) {
            QJsonObject FObj = FVal.toObject();
            StructField Field;
            Field.Name = FObj["name"].toString();
            Field.Type = StringToFieldType(FObj["type"].toString());
            Field.Offset = FObj["offset"].toInt();
            Field.Size = FObj["size"].toInt();
            Field.ArrayCount = FObj["arrayCount"].toInt(1);
            Field.BitFieldWidth = FObj["bitFieldWidth"].toInt();
            Field.PointedType = FObj["pointedType"].toString();
            Field.IsCollapsed = false;
            Def.Fields.append(Field);
        }
        Structs[Def.Name] = Def;
    }
    return true;
}

bool TypeSystem::ExportAsHeader(const QString& Path) {
    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly | QIODevice::Text)) return false;
    QTextStream Out(&File);

    Out << "#pragma once\n\n#include <stdint.h>\n\n";

    for (auto It = Structs.begin(); It != Structs.end(); ++It) {
        const auto& Def = It.value();
        Out << "struct " << Def.Name << " {\n";

        for (const auto& F : Def.Fields) {
            Out << "    ";
            switch (F.Type) {
                case FieldType::Int8: Out << "int8_t"; break;
                case FieldType::UInt8: case FieldType::Hex8: Out << "uint8_t"; break;
                case FieldType::Int16: Out << "int16_t"; break;
                case FieldType::UInt16: case FieldType::Hex16: Out << "uint16_t"; break;
                case FieldType::Int32: Out << "int32_t"; break;
                case FieldType::UInt32: case FieldType::Hex32: Out << "uint32_t"; break;
                case FieldType::Int64: Out << "int64_t"; break;
                case FieldType::UInt64: case FieldType::Hex64: Out << "uint64_t"; break;
                case FieldType::Float: Out << "float"; break;
                case FieldType::Double: Out << "double"; break;
                case FieldType::Bool: Out << "bool"; break;
                case FieldType::Char: Out << "char"; break;
                case FieldType::WChar: Out << "wchar_t"; break;
                case FieldType::Pointer: case FieldType::VTable: case FieldType::FunctionPtr:
                    Out << "void*"; break;
                case FieldType::CString: Out << "char*"; break;
                case FieldType::WString: Out << "wchar_t*"; break;
                case FieldType::Padding: Out << "uint8_t"; break;
                default: Out << "uint8_t"; break;
            }
            Out << " " << F.Name;
            if (F.Type == FieldType::Padding && F.Size > 1)
                Out << "[" << F.Size << "]";
            else if (F.ArrayCount > 1)
                Out << "[" << F.ArrayCount << "]";
            Out << ";\n";
        }
        Out << "};\n\n";
    }

    File.close();
    return true;
}

}
