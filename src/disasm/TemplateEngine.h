#pragma once

#include <fidra/Types.h>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVector>
#include <QMap>
#include <QPair>
#include <QVariant>
#include <QColor>

namespace Fidra {

class AnalysisDatabase;

enum class TemplateFieldType {
    U8, U16, U32, U64, I8, I16, I32, I64,
    Float, Double, Bool,
    Char, WChar, String, WString,
    Padding, Array, Struct, Enum, Bitfield,
    Pointer, Color
};

struct TemplateField {
    QString Name;
    TemplateFieldType Type;
    int ArraySize = 0;
    int BitSize = 0;
    bool IsLittleEndian = true;
    QString EnumTypeName;
    QString StructTypeName;
    QString Condition;
    QString SizeExpression;
    QString Comment;
    QVector<TemplateField> Children;
    QColor DisplayColor;
};

struct TemplateDefinition {
    QString Name;
    QString Description;
    QVector<TemplateField> Fields;
    QMap<QString, QVector<QPair<QString, int64_t>>> Enums;
    QMap<QString, QVector<TemplateField>> Structs;
};

struct TemplateResult {
    QString FieldName;
    TemplateFieldType Type;
    Address Offset;
    int Size;
    QVariant Value;
    QString DisplayValue;
    QColor Color;
    QVector<TemplateResult> Children;
};

class TemplateEngine : public QObject {
    Q_OBJECT

public:
    explicit TemplateEngine(QObject* Parent = nullptr);

    bool Parse(const QString& TemplateSource, QString& Error);
    bool LoadFromFile(const QString& Path, QString& Error);

    QVector<TemplateResult> Apply(AnalysisDatabase* Db, Address BaseAddr);

    TemplateDefinition GetDefinition() const;

    static QString GetBuiltinTemplate(const QString& Name);
    static QStringList GetBuiltinTemplateNames();

private:
    enum class TokenType {
        Keyword, Identifier, Number, String,
        LBrace, RBrace, LBracket, RBracket,
        Semicolon, Colon, Comma, Equals,
        LParen, RParen, At, Eof, Unknown
    };

    struct Token {
        TokenType Type;
        QString Text;
        int64_t NumValue;
        int Line;
    };

    bool Tokenize(const QString& Source, QVector<Token>& Tokens, QString& Error);
    bool ParseDefinition(const QVector<Token>& Tokens, int& Pos, QString& Error);
    bool ParseStruct(const QVector<Token>& Tokens, int& Pos, QString& Error);
    bool ParseEnum(const QVector<Token>& Tokens, int& Pos, QString& Error);
    bool ParseField(const QVector<Token>& Tokens, int& Pos, TemplateField& OutField, QString& Error);

    TemplateFieldType TypeFromKeyword(const QString& Kw) const;
    bool IsTypeKeyword(const QString& Kw) const;
    int FieldSize(TemplateFieldType Type) const;
    QVariant ReadFieldValue(const QByteArray& Data, TemplateFieldType Type, bool LittleEndian) const;
    QString FormatValue(const QVariant& Value, TemplateFieldType Type) const;
    TemplateResult ApplyField(AnalysisDatabase* Db, Address& CurrentOffset, const TemplateField& Field, QMap<QString, QVariant>& Context);
    TemplateFieldType ResolveEnumBaseType(const QString& EnumName) const;

    TemplateDefinition Definition;
    QMap<QString, TemplateFieldType> EnumBaseTypes;
    bool FirstStructSeen;
};

}
