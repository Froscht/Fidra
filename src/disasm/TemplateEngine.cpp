#include "TemplateEngine.h"
#include "../analysis/AnalysisDatabase.h"
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QtEndian>
#include <cstring>
#include <cmath>

namespace Fidra {

static const QStringList Keywords = {
    QStringLiteral("struct"), QStringLiteral("enum"), QStringLiteral("if"),
    QStringLiteral("padding"), QStringLiteral("array"), QStringLiteral("be"),
    QStringLiteral("u8"), QStringLiteral("u16"), QStringLiteral("u32"), QStringLiteral("u64"),
    QStringLiteral("i8"), QStringLiteral("i16"), QStringLiteral("i32"), QStringLiteral("i64"),
    QStringLiteral("float"), QStringLiteral("double"), QStringLiteral("bool"),
    QStringLiteral("char"), QStringLiteral("wchar"), QStringLiteral("string"), QStringLiteral("wstring"),
    QStringLiteral("pointer"), QStringLiteral("color"), QStringLiteral("bitfield")
};

TemplateEngine::TemplateEngine(QObject* Parent)
    : QObject(Parent)
    , FirstStructSeen(false)
{
}

bool TemplateEngine::Tokenize(const QString& Source, QVector<Token>& Tokens, QString& Error) {
    int Pos = 0;
    int Line = 1;
    int Len = Source.length();

    while (Pos < Len) {
        QChar Ch = Source[Pos];

        if (Ch == '\n') {
            ++Line;
            ++Pos;
            continue;
        }

        if (Ch.isSpace()) {
            ++Pos;
            continue;
        }

        if (Pos + 1 < Len && Ch == '/' && Source[Pos + 1] == '/') {
            while (Pos < Len && Source[Pos] != '\n')
                ++Pos;
            continue;
        }

        if (Pos + 1 < Len && Ch == '/' && Source[Pos + 1] == '*') {
            Pos += 2;
            while (Pos + 1 < Len) {
                if (Source[Pos] == '\n') ++Line;
                if (Source[Pos] == '*' && Source[Pos + 1] == '/') {
                    Pos += 2;
                    break;
                }
                ++Pos;
            }
            continue;
        }

        if (Ch == '{') { Tokens.append({TokenType::LBrace, QStringLiteral("{"), 0, Line}); ++Pos; continue; }
        if (Ch == '}') { Tokens.append({TokenType::RBrace, QStringLiteral("}"), 0, Line}); ++Pos; continue; }
        if (Ch == '[') { Tokens.append({TokenType::LBracket, QStringLiteral("["), 0, Line}); ++Pos; continue; }
        if (Ch == ']') { Tokens.append({TokenType::RBracket, QStringLiteral("]"), 0, Line}); ++Pos; continue; }
        if (Ch == '(') { Tokens.append({TokenType::LParen, QStringLiteral("("), 0, Line}); ++Pos; continue; }
        if (Ch == ')') { Tokens.append({TokenType::RParen, QStringLiteral(")"), 0, Line}); ++Pos; continue; }
        if (Ch == ';') { Tokens.append({TokenType::Semicolon, QStringLiteral(";"), 0, Line}); ++Pos; continue; }
        if (Ch == ':') { Tokens.append({TokenType::Colon, QStringLiteral(":"), 0, Line}); ++Pos; continue; }
        if (Ch == ',') { Tokens.append({TokenType::Comma, QStringLiteral(","), 0, Line}); ++Pos; continue; }
        if (Ch == '=') { Tokens.append({TokenType::Equals, QStringLiteral("="), 0, Line}); ++Pos; continue; }
        if (Ch == '@') { Tokens.append({TokenType::At, QStringLiteral("@"), 0, Line}); ++Pos; continue; }

        if (Ch == '"') {
            ++Pos;
            QString Str;
            while (Pos < Len && Source[Pos] != '"') {
                if (Source[Pos] == '\\' && Pos + 1 < Len) {
                    ++Pos;
                    if (Source[Pos] == 'n') Str += '\n';
                    else if (Source[Pos] == 't') Str += '\t';
                    else if (Source[Pos] == '\\') Str += '\\';
                    else if (Source[Pos] == '"') Str += '"';
                    else Str += Source[Pos];
                } else {
                    Str += Source[Pos];
                }
                ++Pos;
            }
            if (Pos >= Len) {
                Error = QStringLiteral("Unterminated string literal at line %1").arg(Line);
                return false;
            }
            ++Pos;
            Tokens.append({TokenType::String, Str, 0, Line});
            continue;
        }

        if (Ch.isDigit() || (Ch == '-' && Pos + 1 < Len && Source[Pos + 1].isDigit())) {
            bool Negative = (Ch == '-');
            if (Negative) ++Pos;

            int64_t NumVal = 0;
            QString NumText;

            if (Pos + 1 < Len && Source[Pos] == '0' && (Source[Pos + 1] == 'x' || Source[Pos + 1] == 'X')) {
                NumText = QStringLiteral("0x");
                Pos += 2;
                while (Pos < Len && (Source[Pos].isDigit() || (Source[Pos] >= 'a' && Source[Pos] <= 'f') || (Source[Pos] >= 'A' && Source[Pos] <= 'F'))) {
                    NumText += Source[Pos];
                    ++Pos;
                }
                bool Ok = false;
                NumVal = NumText.toLongLong(&Ok, 16);
            } else if (Pos + 1 < Len && Source[Pos] == '0' && (Source[Pos + 1] == 'b' || Source[Pos + 1] == 'B')) {
                NumText = QStringLiteral("0b");
                Pos += 2;
                while (Pos < Len && (Source[Pos] == '0' || Source[Pos] == '1')) {
                    NumText += Source[Pos];
                    ++Pos;
                }
                bool Ok = false;
                NumVal = NumText.mid(2).toLongLong(&Ok, 2);
            } else {
                while (Pos < Len && Source[Pos].isDigit()) {
                    NumText += Source[Pos];
                    ++Pos;
                }
                NumVal = NumText.toLongLong();
            }

            if (Negative) {
                NumVal = -NumVal;
                NumText = QStringLiteral("-") + NumText;
            }

            Tokens.append({TokenType::Number, NumText, NumVal, Line});
            continue;
        }

        if (Ch.isLetter() || Ch == '_') {
            QString Ident;
            while (Pos < Len && (Source[Pos].isLetterOrNumber() || Source[Pos] == '_')) {
                Ident += Source[Pos];
                ++Pos;
            }

            if (Keywords.contains(Ident)) {
                Tokens.append({TokenType::Keyword, Ident, 0, Line});
            } else {
                Tokens.append({TokenType::Identifier, Ident, 0, Line});
            }
            continue;
        }

        Error = QStringLiteral("Unexpected character '%1' at line %2").arg(Ch).arg(Line);
        return false;
    }

    Tokens.append({TokenType::Eof, QString(), 0, Line});
    return true;
}

bool TemplateEngine::Parse(const QString& TemplateSource, QString& Error) {
    Definition = TemplateDefinition();
    EnumBaseTypes.clear();
    FirstStructSeen = false;

    QVector<Token> Tokens;
    if (!Tokenize(TemplateSource, Tokens, Error))
        return false;

    int Pos = 0;
    while (Pos < Tokens.size() && Tokens[Pos].Type != TokenType::Eof) {
        if (!ParseDefinition(Tokens, Pos, Error))
            return false;
    }

    if (!FirstStructSeen) {
        Error = QStringLiteral("No struct definitions found");
        return false;
    }

    return true;
}

bool TemplateEngine::ParseDefinition(const QVector<Token>& Tokens, int& Pos, QString& Error) {
    if (Pos >= Tokens.size() || Tokens[Pos].Type == TokenType::Eof)
        return true;

    if (Tokens[Pos].Type == TokenType::Keyword && Tokens[Pos].Text == QStringLiteral("struct")) {
        return ParseStruct(Tokens, Pos, Error);
    }

    if (Tokens[Pos].Type == TokenType::Keyword && Tokens[Pos].Text == QStringLiteral("enum")) {
        return ParseEnum(Tokens, Pos, Error);
    }

    Error = QStringLiteral("Expected 'struct' or 'enum' at line %1, got '%2'").arg(Tokens[Pos].Line).arg(Tokens[Pos].Text);
    return false;
}

bool TemplateEngine::ParseStruct(const QVector<Token>& Tokens, int& Pos, QString& Error) {
    ++Pos;

    if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::Identifier) {
        Error = QStringLiteral("Expected struct name at line %1").arg(Tokens[Pos].Line);
        return false;
    }

    QString StructName = Tokens[Pos].Text;
    ++Pos;

    if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::LBrace) {
        Error = QStringLiteral("Expected '{' after struct name at line %1").arg(Tokens[Pos].Line);
        return false;
    }
    ++Pos;

    QVector<TemplateField> Fields;

    while (Pos < Tokens.size() && Tokens[Pos].Type != TokenType::RBrace) {
        TemplateField Field;
        if (!ParseField(Tokens, Pos, Field, Error))
            return false;
        Fields.append(Field);
    }

    if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::RBrace) {
        Error = QStringLiteral("Expected '}' to close struct at line %1").arg(Tokens[Pos].Line);
        return false;
    }
    ++Pos;

    if (Pos < Tokens.size() && Tokens[Pos].Type == TokenType::Semicolon)
        ++Pos;

    Definition.Structs[StructName] = Fields;

    if (!FirstStructSeen) {
        FirstStructSeen = true;
        Definition.Name = StructName;
        Definition.Fields = Fields;
    }

    return true;
}

bool TemplateEngine::ParseEnum(const QVector<Token>& Tokens, int& Pos, QString& Error) {
    ++Pos;

    if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::Identifier) {
        Error = QStringLiteral("Expected enum name at line %1").arg(Tokens[Pos].Line);
        return false;
    }

    QString EnumName = Tokens[Pos].Text;
    ++Pos;

    TemplateFieldType BaseType = TemplateFieldType::U32;

    if (Pos < Tokens.size() && Tokens[Pos].Type == TokenType::Colon) {
        ++Pos;
        if (Pos >= Tokens.size() || !IsTypeKeyword(Tokens[Pos].Text)) {
            Error = QStringLiteral("Expected type after ':' in enum at line %1").arg(Tokens[Pos].Line);
            return false;
        }
        BaseType = TypeFromKeyword(Tokens[Pos].Text);
        ++Pos;
    }

    EnumBaseTypes[EnumName] = BaseType;

    if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::LBrace) {
        Error = QStringLiteral("Expected '{' after enum declaration at line %1").arg(Tokens[Pos].Line);
        return false;
    }
    ++Pos;

    QVector<QPair<QString, int64_t>> Entries;
    int64_t NextValue = 0;

    while (Pos < Tokens.size() && Tokens[Pos].Type != TokenType::RBrace) {
        if (Tokens[Pos].Type != TokenType::Identifier) {
            Error = QStringLiteral("Expected enum entry name at line %1").arg(Tokens[Pos].Line);
            return false;
        }

        QString EntryName = Tokens[Pos].Text;
        ++Pos;

        if (Pos < Tokens.size() && Tokens[Pos].Type == TokenType::Equals) {
            ++Pos;
            if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::Number) {
                Error = QStringLiteral("Expected number after '=' in enum at line %1").arg(Tokens[Pos].Line);
                return false;
            }
            NextValue = Tokens[Pos].NumValue;
            ++Pos;
        }

        Entries.append({EntryName, NextValue});
        ++NextValue;

        if (Pos < Tokens.size() && Tokens[Pos].Type == TokenType::Comma)
            ++Pos;
    }

    if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::RBrace) {
        Error = QStringLiteral("Expected '}' to close enum at line %1").arg(Tokens[Pos].Line);
        return false;
    }
    ++Pos;

    if (Pos < Tokens.size() && Tokens[Pos].Type == TokenType::Semicolon)
        ++Pos;

    Definition.Enums[EnumName] = Entries;
    return true;
}

bool TemplateEngine::ParseField(const QVector<Token>& Tokens, int& Pos, TemplateField& OutField, QString& Error) {
    if (Pos >= Tokens.size()) {
        Error = QStringLiteral("Unexpected end of input while parsing field");
        return false;
    }

    if (Tokens[Pos].Type == TokenType::At) {
        ++Pos;
        if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::Number) {
            Error = QStringLiteral("Expected offset value after '@' at line %1").arg(Tokens[Pos].Line);
            return false;
        }
        OutField.Type = TemplateFieldType::Padding;
        OutField.Name = QStringLiteral("@seek");
        OutField.SizeExpression = QString::number(Tokens[Pos].NumValue);
        ++Pos;
        if (Pos < Tokens.size() && Tokens[Pos].Type == TokenType::Semicolon)
            ++Pos;
        return true;
    }

    if (Tokens[Pos].Type == TokenType::Keyword && Tokens[Pos].Text == QStringLiteral("if")) {
        ++Pos;
        if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::LParen) {
            Error = QStringLiteral("Expected '(' after 'if' at line %1").arg(Tokens[Pos].Line);
            return false;
        }
        ++Pos;

        QString Condition;
        int Depth = 1;
        while (Pos < Tokens.size() && Depth > 0) {
            if (Tokens[Pos].Type == TokenType::LParen) ++Depth;
            else if (Tokens[Pos].Type == TokenType::RParen) {
                --Depth;
                if (Depth == 0) break;
            }
            Condition += Tokens[Pos].Text + QStringLiteral(" ");
            ++Pos;
        }

        if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::RParen) {
            Error = QStringLiteral("Expected ')' after condition at line %1").arg(Tokens[Pos].Line);
            return false;
        }
        ++Pos;

        OutField.Type = TemplateFieldType::Struct;
        OutField.Name = QStringLiteral("if");
        OutField.Condition = Condition.trimmed();

        if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::LBrace) {
            Error = QStringLiteral("Expected '{' after if condition at line %1").arg(Tokens[Pos].Line);
            return false;
        }
        ++Pos;

        while (Pos < Tokens.size() && Tokens[Pos].Type != TokenType::RBrace) {
            TemplateField ChildField;
            if (!ParseField(Tokens, Pos, ChildField, Error))
                return false;
            OutField.Children.append(ChildField);
        }

        if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::RBrace) {
            Error = QStringLiteral("Expected '}' to close if block at line %1").arg(Tokens[Pos].Line);
            return false;
        }
        ++Pos;

        return true;
    }

    if (Tokens[Pos].Type == TokenType::Keyword && Tokens[Pos].Text == QStringLiteral("padding")) {
        OutField.Type = TemplateFieldType::Padding;
        OutField.Name = QStringLiteral("padding");
        ++Pos;

        if (Pos < Tokens.size() && Tokens[Pos].Type == TokenType::LBracket) {
            ++Pos;
            if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::Number) {
                Error = QStringLiteral("Expected number in padding[] at line %1").arg(Tokens[Pos].Line);
                return false;
            }
            OutField.ArraySize = static_cast<int>(Tokens[Pos].NumValue);
            ++Pos;
            if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::RBracket) {
                Error = QStringLiteral("Expected ']' after padding size at line %1").arg(Tokens[Pos].Line);
                return false;
            }
            ++Pos;
        }

        if (Pos < Tokens.size() && Tokens[Pos].Type == TokenType::Semicolon)
            ++Pos;
        return true;
    }

    bool BigEndian = false;
    if (Tokens[Pos].Type == TokenType::Keyword && Tokens[Pos].Text == QStringLiteral("be")) {
        BigEndian = true;
        ++Pos;
    }

    if (Pos >= Tokens.size()) {
        Error = QStringLiteral("Unexpected end of input while parsing field type");
        return false;
    }

    bool IsBuiltinType = false;
    TemplateFieldType FieldType = TemplateFieldType::U8;
    QString TypeName;

    if (Tokens[Pos].Type == TokenType::Keyword && IsTypeKeyword(Tokens[Pos].Text)) {
        FieldType = TypeFromKeyword(Tokens[Pos].Text);
        TypeName = Tokens[Pos].Text;
        IsBuiltinType = true;
        ++Pos;
    } else if (Tokens[Pos].Type == TokenType::Identifier) {
        TypeName = Tokens[Pos].Text;
        ++Pos;

        if (Definition.Enums.contains(TypeName)) {
            FieldType = TemplateFieldType::Enum;
        } else if (Definition.Structs.contains(TypeName)) {
            FieldType = TemplateFieldType::Struct;
        } else {
            FieldType = TemplateFieldType::Struct;
        }
    } else {
        Error = QStringLiteral("Expected type name at line %1, got '%2'").arg(Tokens[Pos].Line).arg(Tokens[Pos].Text);
        return false;
    }

    if (Pos >= Tokens.size() || (Tokens[Pos].Type != TokenType::Identifier && Tokens[Pos].Type != TokenType::Semicolon)) {
        if (Tokens[Pos].Type == TokenType::LBracket && !IsBuiltinType) {
            OutField.Type = FieldType;
            OutField.Name = TypeName;
            OutField.IsLittleEndian = !BigEndian;
            if (FieldType == TemplateFieldType::Enum) {
                OutField.EnumTypeName = TypeName;
            } else if (FieldType == TemplateFieldType::Struct) {
                OutField.StructTypeName = TypeName;
            }
        } else {
            Error = QStringLiteral("Expected field name at line %1, got '%2'").arg(Tokens[Pos].Line).arg(Tokens[Pos].Text);
            return false;
        }
    }

    QString FieldName;
    if (Pos < Tokens.size() && Tokens[Pos].Type == TokenType::Identifier) {
        FieldName = Tokens[Pos].Text;
        ++Pos;
    }

    OutField.Name = FieldName;
    OutField.IsLittleEndian = !BigEndian;

    if (FieldType == TemplateFieldType::Enum) {
        OutField.Type = TemplateFieldType::Enum;
        OutField.EnumTypeName = TypeName;
    } else if (FieldType == TemplateFieldType::Struct && !IsBuiltinType) {
        OutField.Type = TemplateFieldType::Struct;
        OutField.StructTypeName = TypeName;
    } else {
        OutField.Type = FieldType;
    }

    if (Pos < Tokens.size() && Tokens[Pos].Type == TokenType::LBracket) {
        ++Pos;
        if (Pos >= Tokens.size()) {
            Error = QStringLiteral("Unexpected end of input in array size");
            return false;
        }

        if (Tokens[Pos].Type == TokenType::Number) {
            OutField.ArraySize = static_cast<int>(Tokens[Pos].NumValue);
            ++Pos;
        } else if (Tokens[Pos].Type == TokenType::Identifier) {
            OutField.SizeExpression = Tokens[Pos].Text;
            OutField.ArraySize = -1;
            ++Pos;
        } else {
            Error = QStringLiteral("Expected number or identifier in array brackets at line %1").arg(Tokens[Pos].Line);
            return false;
        }

        if (Pos >= Tokens.size() || Tokens[Pos].Type != TokenType::RBracket) {
            Error = QStringLiteral("Expected ']' at line %1").arg(Tokens[Pos].Line);
            return false;
        }
        ++Pos;
    }

    if (Pos < Tokens.size() && Tokens[Pos].Type == TokenType::Semicolon)
        ++Pos;

    return true;
}

bool TemplateEngine::LoadFromFile(const QString& Path, QString& Error) {
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly | QIODevice::Text)) {
        Error = QStringLiteral("Failed to open file: %1").arg(Path);
        return false;
    }

    QTextStream Stream(&File);
    QString Source = Stream.readAll();
    File.close();

    return Parse(Source, Error);
}

bool TemplateEngine::IsTypeKeyword(const QString& Kw) const {
    return Kw == QStringLiteral("u8") || Kw == QStringLiteral("u16") ||
           Kw == QStringLiteral("u32") || Kw == QStringLiteral("u64") ||
           Kw == QStringLiteral("i8") || Kw == QStringLiteral("i16") ||
           Kw == QStringLiteral("i32") || Kw == QStringLiteral("i64") ||
           Kw == QStringLiteral("float") || Kw == QStringLiteral("double") ||
           Kw == QStringLiteral("bool") || Kw == QStringLiteral("char") ||
           Kw == QStringLiteral("wchar") || Kw == QStringLiteral("string") ||
           Kw == QStringLiteral("wstring") || Kw == QStringLiteral("pointer") ||
           Kw == QStringLiteral("color") || Kw == QStringLiteral("bitfield");
}

TemplateFieldType TemplateEngine::TypeFromKeyword(const QString& Kw) const {
    if (Kw == QStringLiteral("u8")) return TemplateFieldType::U8;
    if (Kw == QStringLiteral("u16")) return TemplateFieldType::U16;
    if (Kw == QStringLiteral("u32")) return TemplateFieldType::U32;
    if (Kw == QStringLiteral("u64")) return TemplateFieldType::U64;
    if (Kw == QStringLiteral("i8")) return TemplateFieldType::I8;
    if (Kw == QStringLiteral("i16")) return TemplateFieldType::I16;
    if (Kw == QStringLiteral("i32")) return TemplateFieldType::I32;
    if (Kw == QStringLiteral("i64")) return TemplateFieldType::I64;
    if (Kw == QStringLiteral("float")) return TemplateFieldType::Float;
    if (Kw == QStringLiteral("double")) return TemplateFieldType::Double;
    if (Kw == QStringLiteral("bool")) return TemplateFieldType::Bool;
    if (Kw == QStringLiteral("char")) return TemplateFieldType::Char;
    if (Kw == QStringLiteral("wchar")) return TemplateFieldType::WChar;
    if (Kw == QStringLiteral("string")) return TemplateFieldType::String;
    if (Kw == QStringLiteral("wstring")) return TemplateFieldType::WString;
    if (Kw == QStringLiteral("pointer")) return TemplateFieldType::Pointer;
    if (Kw == QStringLiteral("color")) return TemplateFieldType::Color;
    if (Kw == QStringLiteral("bitfield")) return TemplateFieldType::Bitfield;
    return TemplateFieldType::U8;
}

int TemplateEngine::FieldSize(TemplateFieldType Type) const {
    switch (Type) {
    case TemplateFieldType::U8:
    case TemplateFieldType::I8:
    case TemplateFieldType::Bool:
    case TemplateFieldType::Char:
        return 1;
    case TemplateFieldType::U16:
    case TemplateFieldType::I16:
    case TemplateFieldType::WChar:
        return 2;
    case TemplateFieldType::U32:
    case TemplateFieldType::I32:
    case TemplateFieldType::Float:
    case TemplateFieldType::Color:
        return 4;
    case TemplateFieldType::U64:
    case TemplateFieldType::I64:
    case TemplateFieldType::Double:
    case TemplateFieldType::Pointer:
        return 8;
    case TemplateFieldType::Padding:
    case TemplateFieldType::Array:
    case TemplateFieldType::Struct:
    case TemplateFieldType::Enum:
    case TemplateFieldType::Bitfield:
    case TemplateFieldType::String:
    case TemplateFieldType::WString:
        return 0;
    }
    return 0;
}

TemplateFieldType TemplateEngine::ResolveEnumBaseType(const QString& EnumName) const {
    if (EnumBaseTypes.contains(EnumName))
        return EnumBaseTypes[EnumName];
    return TemplateFieldType::U32;
}

QVariant TemplateEngine::ReadFieldValue(const QByteArray& Data, TemplateFieldType Type, bool LittleEndian) const {
    const uint8_t* Raw = reinterpret_cast<const uint8_t*>(Data.constData());
    int Available = Data.size();

    switch (Type) {
    case TemplateFieldType::U8:
    case TemplateFieldType::Char:
        if (Available >= 1) return QVariant(static_cast<quint64>(Raw[0]));
        break;
    case TemplateFieldType::I8:
        if (Available >= 1) return QVariant(static_cast<qint64>(static_cast<int8_t>(Raw[0])));
        break;
    case TemplateFieldType::Bool:
        if (Available >= 1) return QVariant(Raw[0] != 0);
        break;
    case TemplateFieldType::U16:
    case TemplateFieldType::WChar: {
        if (Available >= 2) {
            uint16_t Val;
            std::memcpy(&Val, Raw, 2);
            if (!LittleEndian) Val = qFromBigEndian(Val);
            else Val = qFromLittleEndian(Val);
            return QVariant(static_cast<quint64>(Val));
        }
        break;
    }
    case TemplateFieldType::I16: {
        if (Available >= 2) {
            uint16_t Val;
            std::memcpy(&Val, Raw, 2);
            if (!LittleEndian) Val = qFromBigEndian(Val);
            else Val = qFromLittleEndian(Val);
            return QVariant(static_cast<qint64>(static_cast<int16_t>(Val)));
        }
        break;
    }
    case TemplateFieldType::U32:
    case TemplateFieldType::Color: {
        if (Available >= 4) {
            uint32_t Val;
            std::memcpy(&Val, Raw, 4);
            if (!LittleEndian) Val = qFromBigEndian(Val);
            else Val = qFromLittleEndian(Val);
            return QVariant(static_cast<quint64>(Val));
        }
        break;
    }
    case TemplateFieldType::I32: {
        if (Available >= 4) {
            uint32_t Val;
            std::memcpy(&Val, Raw, 4);
            if (!LittleEndian) Val = qFromBigEndian(Val);
            else Val = qFromLittleEndian(Val);
            return QVariant(static_cast<qint64>(static_cast<int32_t>(Val)));
        }
        break;
    }
    case TemplateFieldType::Float: {
        if (Available >= 4) {
            uint32_t Val;
            std::memcpy(&Val, Raw, 4);
            if (!LittleEndian) Val = qFromBigEndian(Val);
            else Val = qFromLittleEndian(Val);
            float Fval;
            std::memcpy(&Fval, &Val, 4);
            return QVariant(static_cast<double>(Fval));
        }
        break;
    }
    case TemplateFieldType::U64:
    case TemplateFieldType::Pointer: {
        if (Available >= 8) {
            uint64_t Val;
            std::memcpy(&Val, Raw, 8);
            if (!LittleEndian) Val = qFromBigEndian(Val);
            else Val = qFromLittleEndian(Val);
            return QVariant(static_cast<quint64>(Val));
        }
        break;
    }
    case TemplateFieldType::I64: {
        if (Available >= 8) {
            uint64_t Val;
            std::memcpy(&Val, Raw, 8);
            if (!LittleEndian) Val = qFromBigEndian(Val);
            else Val = qFromLittleEndian(Val);
            return QVariant(static_cast<qint64>(static_cast<int64_t>(Val)));
        }
        break;
    }
    case TemplateFieldType::Double: {
        if (Available >= 8) {
            uint64_t Val;
            std::memcpy(&Val, Raw, 8);
            if (!LittleEndian) Val = qFromBigEndian(Val);
            else Val = qFromLittleEndian(Val);
            double Dval;
            std::memcpy(&Dval, &Val, 8);
            return QVariant(Dval);
        }
        break;
    }
    default:
        break;
    }

    return QVariant();
}

QString TemplateEngine::FormatValue(const QVariant& Value, TemplateFieldType Type) const {
    if (!Value.isValid())
        return QStringLiteral("??");

    switch (Type) {
    case TemplateFieldType::U8:
        return QStringLiteral("0x%1 (%2)").arg(Value.toULongLong(), 2, 16, QChar('0')).arg(Value.toULongLong());
    case TemplateFieldType::I8:
        return QString::number(Value.toLongLong());
    case TemplateFieldType::U16:
        return QStringLiteral("0x%1 (%2)").arg(Value.toULongLong(), 4, 16, QChar('0')).arg(Value.toULongLong());
    case TemplateFieldType::I16:
        return QString::number(Value.toLongLong());
    case TemplateFieldType::U32:
        return QStringLiteral("0x%1 (%2)").arg(Value.toULongLong(), 8, 16, QChar('0')).arg(Value.toULongLong());
    case TemplateFieldType::I32:
        return QString::number(Value.toLongLong());
    case TemplateFieldType::U64:
        return QStringLiteral("0x%1").arg(Value.toULongLong(), 16, 16, QChar('0'));
    case TemplateFieldType::I64:
        return QString::number(Value.toLongLong());
    case TemplateFieldType::Float:
    case TemplateFieldType::Double:
        return QString::number(Value.toDouble(), 'g', 10);
    case TemplateFieldType::Bool:
        return Value.toBool() ? QStringLiteral("true") : QStringLiteral("false");
    case TemplateFieldType::Char: {
        uint8_t Ch = static_cast<uint8_t>(Value.toULongLong());
        if (Ch >= 0x20 && Ch <= 0x7E)
            return QStringLiteral("'%1' (0x%2)").arg(QChar(Ch)).arg(Ch, 2, 16, QChar('0'));
        return QStringLiteral("0x%1").arg(Ch, 2, 16, QChar('0'));
    }
    case TemplateFieldType::WChar: {
        uint16_t Ch = static_cast<uint16_t>(Value.toULongLong());
        return QStringLiteral("'%1' (0x%2)").arg(QChar(Ch)).arg(Ch, 4, 16, QChar('0'));
    }
    case TemplateFieldType::Pointer:
        return QStringLiteral("0x%1").arg(Value.toULongLong(), 16, 16, QChar('0'));
    case TemplateFieldType::Color: {
        uint32_t Rgba = static_cast<uint32_t>(Value.toULongLong());
        return QStringLiteral("#%1").arg(Rgba, 8, 16, QChar('0'));
    }
    case TemplateFieldType::Enum:
        return QStringLiteral("0x%1 (%2)").arg(Value.toULongLong(), 0, 16).arg(Value.toULongLong());
    default:
        return Value.toString();
    }
}

TemplateResult TemplateEngine::ApplyField(AnalysisDatabase* Db, Address& CurrentOffset, const TemplateField& Field, QMap<QString, QVariant>& Context) {
    TemplateResult Result;
    Result.FieldName = Field.Name;
    Result.Type = Field.Type;
    Result.Offset = CurrentOffset;
    Result.Color = Field.DisplayColor;

    if (Field.Name == QStringLiteral("@seek") && Field.Type == TemplateFieldType::Padding) {
        bool Ok = false;
        Address SeekAddr = Field.SizeExpression.toULongLong(&Ok, 0);
        if (Ok) CurrentOffset = SeekAddr;
        Result.Offset = CurrentOffset;
        Result.Size = 0;
        Result.DisplayValue = QStringLiteral("@0x%1").arg(CurrentOffset, 0, 16);
        return Result;
    }

    if (Field.Type == TemplateFieldType::Padding) {
        Result.Size = Field.ArraySize;
        Result.DisplayValue = QStringLiteral("padding[%1]").arg(Field.ArraySize);
        CurrentOffset += static_cast<Address>(Field.ArraySize);
        return Result;
    }

    if (!Field.Condition.isEmpty()) {
        QString Cond = Field.Condition;

        bool ConditionMet = false;
        int EqIdx = Cond.indexOf(QStringLiteral("=="));
        int NeqIdx = Cond.indexOf(QStringLiteral("!="));

        if (EqIdx >= 0 && NeqIdx < 0) {
            QString LhsName = Cond.left(EqIdx).trimmed();
            QString RhsStr = Cond.mid(EqIdx + 2).trimmed();
            if (Context.contains(LhsName)) {
                bool Ok = false;
                int64_t RhsVal = RhsStr.toLongLong(&Ok, 0);
                if (Ok) {
                    ConditionMet = (Context[LhsName].toLongLong() == RhsVal);
                }
            }
        } else if (NeqIdx >= 0) {
            QString LhsName = Cond.left(NeqIdx).trimmed();
            QString RhsStr = Cond.mid(NeqIdx + 2).trimmed();
            if (Context.contains(LhsName)) {
                bool Ok = false;
                int64_t RhsVal = RhsStr.toLongLong(&Ok, 0);
                if (Ok) {
                    ConditionMet = (Context[LhsName].toLongLong() != RhsVal);
                }
            }
        } else {
            if (Context.contains(Cond)) {
                ConditionMet = (Context[Cond].toLongLong() != 0);
            }
        }

        if (!ConditionMet) {
            Result.Size = 0;
            Result.DisplayValue = QStringLiteral("(skipped)");
            return Result;
        }

        Address ChildOffset = CurrentOffset;
        for (const TemplateField& ChildField : Field.Children) {
            TemplateResult ChildResult = ApplyField(Db, ChildOffset, ChildField, Context);
            Result.Children.append(ChildResult);
        }
        Result.Size = static_cast<int>(ChildOffset - CurrentOffset);
        CurrentOffset = ChildOffset;
        Result.DisplayValue = QStringLiteral("if (%1)").arg(Field.Condition);
        return Result;
    }

    if (Field.Type == TemplateFieldType::Struct) {
        QVector<TemplateField> StructFields;
        if (Definition.Structs.contains(Field.StructTypeName)) {
            StructFields = Definition.Structs[Field.StructTypeName];
        }

        int ArrayCount = 1;
        if (Field.ArraySize > 0) {
            ArrayCount = Field.ArraySize;
        } else if (Field.ArraySize == -1 && !Field.SizeExpression.isEmpty()) {
            if (Context.contains(Field.SizeExpression)) {
                ArrayCount = static_cast<int>(Context[Field.SizeExpression].toLongLong());
            }
        }

        if (ArrayCount > 1 || Field.ArraySize != 0) {
            Address ArrayStartOffset = CurrentOffset;
            for (int Idx = 0; Idx < ArrayCount; ++Idx) {
                TemplateResult ElementResult;
                ElementResult.FieldName = QStringLiteral("%1[%2]").arg(Field.Name).arg(Idx);
                ElementResult.Type = TemplateFieldType::Struct;
                ElementResult.Offset = CurrentOffset;

                Address ElementStart = CurrentOffset;
                for (const TemplateField& StructField : StructFields) {
                    TemplateResult ChildResult = ApplyField(Db, CurrentOffset, StructField, Context);
                    ElementResult.Children.append(ChildResult);
                }
                ElementResult.Size = static_cast<int>(CurrentOffset - ElementStart);
                ElementResult.DisplayValue = QStringLiteral("%1[%2]").arg(Field.StructTypeName).arg(Idx);
                Result.Children.append(ElementResult);
            }
            Result.Size = static_cast<int>(CurrentOffset - ArrayStartOffset);
            Result.DisplayValue = QStringLiteral("%1[%2]").arg(Field.StructTypeName).arg(ArrayCount);
        } else {
            Address StructStart = CurrentOffset;
            for (const TemplateField& StructField : StructFields) {
                TemplateResult ChildResult = ApplyField(Db, CurrentOffset, StructField, Context);
                Result.Children.append(ChildResult);
            }
            Result.Size = static_cast<int>(CurrentOffset - StructStart);
            Result.DisplayValue = Field.StructTypeName;
        }
        return Result;
    }

    if (Field.Type == TemplateFieldType::Enum) {
        TemplateFieldType BaseType = ResolveEnumBaseType(Field.EnumTypeName);
        int Size = FieldSize(BaseType);
        QByteArray Data = Db->ReadBytes(CurrentOffset, static_cast<size_t>(Size));
        QVariant Value = ReadFieldValue(Data, BaseType, Field.IsLittleEndian);

        Result.Size = Size;
        Result.Value = Value;

        int64_t IntVal = Value.toLongLong();
        QString EnumDisplayName;
        if (Definition.Enums.contains(Field.EnumTypeName)) {
            for (const auto& Entry : Definition.Enums[Field.EnumTypeName]) {
                if (Entry.second == IntVal) {
                    EnumDisplayName = Entry.first;
                    break;
                }
            }
        }

        if (!EnumDisplayName.isEmpty()) {
            Result.DisplayValue = QStringLiteral("%1 (0x%2)").arg(EnumDisplayName).arg(static_cast<quint64>(IntVal), 0, 16);
        } else {
            Result.DisplayValue = QStringLiteral("0x%1 (%2)").arg(static_cast<quint64>(IntVal), 0, 16).arg(IntVal);
        }

        Context[Field.Name] = Value;
        CurrentOffset += static_cast<Address>(Size);
        return Result;
    }

    int PrimitiveSize = FieldSize(Field.Type);

    if (Field.ArraySize > 0 && PrimitiveSize > 0) {
        int TotalSize = Field.ArraySize * PrimitiveSize;
        QByteArray AllData = Db->ReadBytes(CurrentOffset, static_cast<size_t>(TotalSize));

        if (Field.Type == TemplateFieldType::Char || Field.Type == TemplateFieldType::U8) {
            Result.Size = TotalSize;
            Result.Value = AllData;

            QString AsciiStr;
            for (int I = 0; I < AllData.size(); ++I) {
                uint8_t Ch = static_cast<uint8_t>(AllData[I]);
                if (Ch >= 0x20 && Ch <= 0x7E)
                    AsciiStr += QChar(Ch);
                else if (Ch == 0)
                    break;
                else
                    AsciiStr += '.';
            }
            Result.DisplayValue = QStringLiteral("\"%1\"").arg(AsciiStr);

            for (int I = 0; I < Field.ArraySize; ++I) {
                TemplateResult ElemResult;
                ElemResult.FieldName = QStringLiteral("%1[%2]").arg(Field.Name).arg(I);
                ElemResult.Type = Field.Type;
                ElemResult.Offset = CurrentOffset + static_cast<Address>(I * PrimitiveSize);
                ElemResult.Size = PrimitiveSize;
                QByteArray ElemData = AllData.mid(I * PrimitiveSize, PrimitiveSize);
                ElemResult.Value = ReadFieldValue(ElemData, Field.Type, Field.IsLittleEndian);
                ElemResult.DisplayValue = FormatValue(ElemResult.Value, Field.Type);
                Result.Children.append(ElemResult);
            }
        } else {
            Result.Size = TotalSize;
            for (int I = 0; I < Field.ArraySize; ++I) {
                TemplateResult ElemResult;
                ElemResult.FieldName = QStringLiteral("%1[%2]").arg(Field.Name).arg(I);
                ElemResult.Type = Field.Type;
                ElemResult.Offset = CurrentOffset + static_cast<Address>(I * PrimitiveSize);
                ElemResult.Size = PrimitiveSize;
                QByteArray ElemData = AllData.mid(I * PrimitiveSize, PrimitiveSize);
                ElemResult.Value = ReadFieldValue(ElemData, Field.Type, Field.IsLittleEndian);
                ElemResult.DisplayValue = FormatValue(ElemResult.Value, Field.Type);
                Result.Children.append(ElemResult);
            }
            Result.DisplayValue = QStringLiteral("%1[%2]").arg(Field.Name).arg(Field.ArraySize);
        }

        CurrentOffset += static_cast<Address>(TotalSize);
        return Result;
    }

    if (Field.ArraySize == -1 && !Field.SizeExpression.isEmpty() && PrimitiveSize > 0) {
        int DynCount = 0;
        if (Context.contains(Field.SizeExpression)) {
            DynCount = static_cast<int>(Context[Field.SizeExpression].toLongLong());
        }
        if (DynCount < 0) DynCount = 0;
        if (DynCount > 65536) DynCount = 65536;

        int TotalSize = DynCount * PrimitiveSize;
        QByteArray AllData = Db->ReadBytes(CurrentOffset, static_cast<size_t>(TotalSize));
        Result.Size = TotalSize;
        Result.DisplayValue = QStringLiteral("%1[%2]").arg(Field.Name).arg(DynCount);

        for (int I = 0; I < DynCount; ++I) {
            TemplateResult ElemResult;
            ElemResult.FieldName = QStringLiteral("%1[%2]").arg(Field.Name).arg(I);
            ElemResult.Type = Field.Type;
            ElemResult.Offset = CurrentOffset + static_cast<Address>(I * PrimitiveSize);
            ElemResult.Size = PrimitiveSize;
            QByteArray ElemData = AllData.mid(I * PrimitiveSize, PrimitiveSize);
            ElemResult.Value = ReadFieldValue(ElemData, Field.Type, Field.IsLittleEndian);
            ElemResult.DisplayValue = FormatValue(ElemResult.Value, Field.Type);
            Result.Children.append(ElemResult);
        }

        CurrentOffset += static_cast<Address>(TotalSize);
        return Result;
    }

    if (PrimitiveSize > 0) {
        QByteArray Data = Db->ReadBytes(CurrentOffset, static_cast<size_t>(PrimitiveSize));
        QVariant Value = ReadFieldValue(Data, Field.Type, Field.IsLittleEndian);
        Result.Size = PrimitiveSize;
        Result.Value = Value;
        Result.DisplayValue = FormatValue(Value, Field.Type);

        if (Field.Type == TemplateFieldType::Color) {
            uint32_t Rgba = static_cast<uint32_t>(Value.toULongLong());
            Result.Color = QColor(
                static_cast<int>((Rgba >> 16) & 0xFF),
                static_cast<int>((Rgba >> 8) & 0xFF),
                static_cast<int>(Rgba & 0xFF),
                static_cast<int>((Rgba >> 24) & 0xFF)
            );
        }

        Context[Field.Name] = Value;
        CurrentOffset += static_cast<Address>(PrimitiveSize);
        return Result;
    }

    Result.Size = 0;
    Result.DisplayValue = QStringLiteral("(unsupported)");
    return Result;
}

QVector<TemplateResult> TemplateEngine::Apply(AnalysisDatabase* Db, Address BaseAddr) {
    QVector<TemplateResult> Results;
    if (!Db || Definition.Fields.isEmpty())
        return Results;

    Address CurrentOffset = BaseAddr;
    QMap<QString, QVariant> Context;

    for (const TemplateField& Field : Definition.Fields) {
        TemplateResult Result = ApplyField(Db, CurrentOffset, Field, Context);
        Results.append(Result);
    }

    return Results;
}

TemplateDefinition TemplateEngine::GetDefinition() const {
    return Definition;
}

QStringList TemplateEngine::GetBuiltinTemplateNames() {
    return {
        QStringLiteral("PE"),
        QStringLiteral("ELF"),
        QStringLiteral("ZIP"),
        QStringLiteral("PNG")
    };
}

QString TemplateEngine::GetBuiltinTemplate(const QString& Name) {
    if (Name == QStringLiteral("PE")) {
        return QStringLiteral(
            "struct PE_DOS_HEADER {\n"
            "    u16 e_magic;\n"
            "    u16 e_cblp;\n"
            "    u16 e_cp;\n"
            "    u16 e_crlc;\n"
            "    u16 e_cparhdr;\n"
            "    u16 e_minalloc;\n"
            "    u16 e_maxalloc;\n"
            "    u16 e_ss;\n"
            "    u16 e_sp;\n"
            "    u16 e_csum;\n"
            "    u16 e_ip;\n"
            "    u16 e_cs;\n"
            "    u16 e_lfarlc;\n"
            "    u16 e_ovno;\n"
            "    padding[8];\n"
            "    u16 e_oemid;\n"
            "    u16 e_oeminfo;\n"
            "    padding[20];\n"
            "    u32 e_lfanew;\n"
            "};\n"
            "\n"
            "enum MACHINE : u16 {\n"
            "    IMAGE_FILE_MACHINE_UNKNOWN = 0x0,\n"
            "    IMAGE_FILE_MACHINE_I386 = 0x14C,\n"
            "    IMAGE_FILE_MACHINE_AMD64 = 0x8664,\n"
            "    IMAGE_FILE_MACHINE_ARM64 = 0xAA64\n"
            "};\n"
            "\n"
            "struct PE_FILE_HEADER {\n"
            "    MACHINE Machine;\n"
            "    u16 NumberOfSections;\n"
            "    u32 TimeDateStamp;\n"
            "    u32 PointerToSymbolTable;\n"
            "    u32 NumberOfSymbols;\n"
            "    u16 SizeOfOptionalHeader;\n"
            "    u16 Characteristics;\n"
            "};\n"
            "\n"
            "struct PE_OPTIONAL_HEADER_64 {\n"
            "    u16 Magic;\n"
            "    u8 MajorLinkerVersion;\n"
            "    u8 MinorLinkerVersion;\n"
            "    u32 SizeOfCode;\n"
            "    u32 SizeOfInitializedData;\n"
            "    u32 SizeOfUninitializedData;\n"
            "    u32 AddressOfEntryPoint;\n"
            "    u32 BaseOfCode;\n"
            "    u64 ImageBase;\n"
            "    u32 SectionAlignment;\n"
            "    u32 FileAlignment;\n"
            "    u16 MajorOperatingSystemVersion;\n"
            "    u16 MinorOperatingSystemVersion;\n"
            "    u16 MajorImageVersion;\n"
            "    u16 MinorImageVersion;\n"
            "    u16 MajorSubsystemVersion;\n"
            "    u16 MinorSubsystemVersion;\n"
            "    u32 Win32VersionValue;\n"
            "    u32 SizeOfImage;\n"
            "    u32 SizeOfHeaders;\n"
            "    u32 CheckSum;\n"
            "    u16 Subsystem;\n"
            "    u16 DllCharacteristics;\n"
            "    u64 SizeOfStackReserve;\n"
            "    u64 SizeOfStackCommit;\n"
            "    u64 SizeOfHeapReserve;\n"
            "    u64 SizeOfHeapCommit;\n"
            "    u32 LoaderFlags;\n"
            "    u32 NumberOfRvaAndSizes;\n"
            "};\n"
            "\n"
            "struct PE_SECTION_HEADER {\n"
            "    u8 Name[8];\n"
            "    u32 VirtualSize;\n"
            "    u32 VirtualAddress;\n"
            "    u32 SizeOfRawData;\n"
            "    u32 PointerToRawData;\n"
            "    u32 PointerToRelocations;\n"
            "    u32 PointerToLinenumbers;\n"
            "    u16 NumberOfRelocations;\n"
            "    u16 NumberOfLinenumbers;\n"
            "    u32 Characteristics;\n"
            "};\n"
        );
    }

    if (Name == QStringLiteral("ELF")) {
        return QStringLiteral(
            "struct ELF_HEADER {\n"
            "    u8 e_ident[16];\n"
            "    u16 e_type;\n"
            "    u16 e_machine;\n"
            "    u32 e_version;\n"
            "    u64 e_entry;\n"
            "    u64 e_phoff;\n"
            "    u64 e_shoff;\n"
            "    u32 e_flags;\n"
            "    u16 e_ehsize;\n"
            "    u16 e_phentsize;\n"
            "    u16 e_phnum;\n"
            "    u16 e_shentsize;\n"
            "    u16 e_shnum;\n"
            "    u16 e_shstrndx;\n"
            "};\n"
            "\n"
            "struct ELF_PROGRAM_HEADER {\n"
            "    u32 p_type;\n"
            "    u32 p_flags;\n"
            "    u64 p_offset;\n"
            "    u64 p_vaddr;\n"
            "    u64 p_paddr;\n"
            "    u64 p_filesz;\n"
            "    u64 p_memsz;\n"
            "    u64 p_align;\n"
            "};\n"
            "\n"
            "struct ELF_SECTION_HEADER {\n"
            "    u32 sh_name;\n"
            "    u32 sh_type;\n"
            "    u64 sh_flags;\n"
            "    u64 sh_addr;\n"
            "    u64 sh_offset;\n"
            "    u64 sh_size;\n"
            "    u32 sh_link;\n"
            "    u32 sh_info;\n"
            "    u64 sh_addralign;\n"
            "    u64 sh_entsize;\n"
            "};\n"
        );
    }

    if (Name == QStringLiteral("ZIP")) {
        return QStringLiteral(
            "struct ZIP_LOCAL_FILE_HEADER {\n"
            "    u32 Signature;\n"
            "    u16 VersionNeeded;\n"
            "    u16 Flags;\n"
            "    u16 Compression;\n"
            "    u16 ModTime;\n"
            "    u16 ModDate;\n"
            "    u32 Crc32;\n"
            "    u32 CompressedSize;\n"
            "    u32 UncompressedSize;\n"
            "    u16 FileNameLength;\n"
            "    u16 ExtraFieldLength;\n"
            "};\n"
            "\n"
            "struct ZIP_CENTRAL_DIR_HEADER {\n"
            "    u32 Signature;\n"
            "    u16 VersionMadeBy;\n"
            "    u16 VersionNeeded;\n"
            "    u16 Flags;\n"
            "    u16 Compression;\n"
            "    u16 ModTime;\n"
            "    u16 ModDate;\n"
            "    u32 Crc32;\n"
            "    u32 CompressedSize;\n"
            "    u32 UncompressedSize;\n"
            "    u16 FileNameLength;\n"
            "    u16 ExtraFieldLength;\n"
            "    u16 CommentLength;\n"
            "    u16 DiskNumberStart;\n"
            "    u16 InternalAttrs;\n"
            "    u32 ExternalAttrs;\n"
            "    u32 LocalHeaderOffset;\n"
            "};\n"
            "\n"
            "struct ZIP_END_CENTRAL_DIR {\n"
            "    u32 Signature;\n"
            "    u16 DiskNumber;\n"
            "    u16 StartDisk;\n"
            "    u16 EntriesOnDisk;\n"
            "    u16 TotalEntries;\n"
            "    u32 CentralDirSize;\n"
            "    u32 CentralDirOffset;\n"
            "    u16 CommentLength;\n"
            "};\n"
        );
    }

    if (Name == QStringLiteral("PNG")) {
        return QStringLiteral(
            "struct PNG_SIGNATURE {\n"
            "    u8 Signature[8];\n"
            "};\n"
            "\n"
            "struct PNG_CHUNK_HEADER {\n"
            "    be u32 Length;\n"
            "    u8 Type[4];\n"
            "};\n"
            "\n"
            "struct PNG_IHDR {\n"
            "    be u32 Width;\n"
            "    be u32 Height;\n"
            "    u8 BitDepth;\n"
            "    u8 ColorType;\n"
            "    u8 CompressionMethod;\n"
            "    u8 FilterMethod;\n"
            "    u8 InterlaceMethod;\n"
            "};\n"
        );
    }

    return QString();
}

}
