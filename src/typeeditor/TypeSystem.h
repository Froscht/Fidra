#pragma once

#include <fidra/Types.h>
#include <QObject>
#include <QString>
#include <QVector>
#include <QMap>
#include <QStringList>

namespace Fidra {

enum class FieldType {
    Int8, UInt8, Int16, UInt16, Int32, UInt32, Int64, UInt64,
    Float, Double, Bool, Char, WChar,
    Pointer, Array, CString, WString,
    Struct, Padding, Hex8, Hex16, Hex32, Hex64,
    VTable, FunctionPtr, BitField
};

struct StructField {
    QString Name;
    FieldType Type;
    int Offset;
    int Size;
    int ArrayCount;
    int BitFieldWidth;
    QString PointedType;
    QString Comment;
    bool IsCollapsed;
};

struct StructDef {
    QString Name;
    int TotalSize;
    QVector<StructField> Fields;
    QString BaseClass;
    Address SampleAddress;
};

class TypeSystem : public QObject {
    Q_OBJECT

public:
    explicit TypeSystem(QObject* Parent = nullptr);

    void AddStruct(const StructDef& Def);
    void RemoveStruct(const QString& Name);
    StructDef* GetStruct(const QString& Name);
    const StructDef* GetStruct(const QString& Name) const;
    QStringList GetStructNames() const;

    void AddField(const QString& StructName, const StructField& Field);
    void RemoveField(const QString& StructName, int Offset);
    void ModifyField(const QString& StructName, int Offset, const StructField& NewField);

    void InsertPadding(const QString& StructName, int Offset, int Size);
    void AutoFillPadding(const QString& StructName);

    static int FieldTypeSize(FieldType Type);
    static QString FieldTypeToString(FieldType Type);
    static FieldType StringToFieldType(const QString& Str);
    static QStringList AllFieldTypeStrings();

    bool SaveToFile(const QString& Path);
    bool LoadFromFile(const QString& Path);

    bool ExportAsHeader(const QString& Path);

signals:
    void StructChanged(const QString& Name);
    void StructAdded(const QString& Name);
    void StructRemoved(const QString& Name);

private:
    QMap<QString, StructDef> Structs;
};

}
