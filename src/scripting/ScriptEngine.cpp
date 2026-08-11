#include "ScriptEngine.h"
#include <fidra/ICore.h>
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <QFile>
#include <QTextStream>
#include <cstring>
#include <algorithm>
#include <random>
#include <chrono>

namespace Fidra {

AstPtr MakeNode(NodeType Type, int Line) {
    auto Node = std::make_shared<AstNode>();
    Node->Type = Type;
    Node->Line = Line;
    Node->NumVal = 0;
    Node->BoolVal = false;
    return Node;
}

Lexer::Lexer(const QString& Source)
    : Src(Source), Pos(0), Line(1), Col(1) {}

QChar Lexer::Current() const {
    if (Pos >= Src.length()) return QChar(0);
    return Src[Pos];
}

QChar Lexer::Advance() {
    QChar Ch = Current();
    if (Ch == '\n') { ++Line; Col = 1; } else { ++Col; }
    ++Pos;
    return Ch;
}

bool Lexer::AtEnd() const { return Pos >= Src.length(); }

Token Lexer::MakeToken(TokenType Type, const QString& Value) {
    return {Type, Value, Line, Col};
}

void Lexer::SkipWhitespace() {
    while (!AtEnd()) {
        QChar Ch = Current();
        if (Ch == ' ' || Ch == '\t' || Ch == '\r' || Ch == '\n') {
            Advance();
        } else if (Ch == '-' && Pos + 1 < Src.length() && Src[Pos + 1] == '-') {
            SkipComment();
        } else {
            break;
        }
    }
}

void Lexer::SkipComment() {
    Advance(); Advance();
    if (!AtEnd() && Current() == '[' && Pos + 1 < Src.length() && Src[Pos + 1] == '[') {
        Advance(); Advance();
        while (!AtEnd()) {
            if (Current() == ']' && Pos + 1 < Src.length() && Src[Pos + 1] == ']') {
                Advance(); Advance();
                return;
            }
            Advance();
        }
    } else {
        while (!AtEnd() && Current() != '\n') Advance();
    }
}

Token Lexer::ReadNumber() {
    int Start = Pos;
    if (Current() == '0' && Pos + 1 < Src.length() && (Src[Pos + 1] == 'x' || Src[Pos + 1] == 'X')) {
        Advance(); Advance();
        while (!AtEnd() && (Current().isDigit() || (Current() >= 'a' && Current() <= 'f') || (Current() >= 'A' && Current() <= 'F')))
            Advance();
        return MakeToken(TokenType::Number, Src.mid(Start, Pos - Start));
    }
    while (!AtEnd() && Current().isDigit()) Advance();
    if (!AtEnd() && Current() == '.' && Pos + 1 < Src.length() && Src[Pos + 1].isDigit()) {
        Advance();
        while (!AtEnd() && Current().isDigit()) Advance();
    }
    if (!AtEnd() && (Current() == 'e' || Current() == 'E')) {
        Advance();
        if (!AtEnd() && (Current() == '+' || Current() == '-')) Advance();
        while (!AtEnd() && Current().isDigit()) Advance();
    }
    return MakeToken(TokenType::Number, Src.mid(Start, Pos - Start));
}

Token Lexer::ReadString(QChar Quote) {
    Advance();
    QString Result;
    while (!AtEnd() && Current() != Quote) {
        if (Current() == '\\') {
            Advance();
            if (AtEnd()) break;
            QChar Esc = Current();
            if (Esc == 'n') Result += '\n';
            else if (Esc == 't') Result += '\t';
            else if (Esc == 'r') Result += '\r';
            else if (Esc == '\\') Result += '\\';
            else if (Esc == '\'') Result += '\'';
            else if (Esc == '"') Result += '"';
            else if (Esc == '0') Result += '\0';
            else if (Esc == 'a') Result += '\a';
            else if (Esc == 'b') Result += '\b';
            else if (Esc == 'f') Result += '\f';
            else if (Esc == 'v') Result += '\v';
            else if (Esc == 'x') {
                Advance();
                QString Hex;
                for (int I = 0; I < 2 && !AtEnd() && Current().isLetterOrNumber(); ++I) {
                    Hex += Current(); Advance();
                }
                bool Ok;
                int Code = Hex.toInt(&Ok, 16);
                if (Ok) Result += QChar(Code);
                continue;
            } else {
                Result += Esc;
            }
            Advance();
        } else {
            Result += Current();
            Advance();
        }
    }
    if (!AtEnd()) Advance();
    return MakeToken(TokenType::String, Result);
}

Token Lexer::ReadLongString() {
    Advance(); Advance();
    if (!AtEnd() && Current() == '\n') Advance();
    QString Result;
    while (!AtEnd()) {
        if (Current() == ']' && Pos + 1 < Src.length() && Src[Pos + 1] == ']') {
            Advance(); Advance();
            return MakeToken(TokenType::String, Result);
        }
        Result += Current();
        Advance();
    }
    return MakeToken(TokenType::String, Result);
}

Token Lexer::ReadIdentifier() {
    int Start = Pos;
    while (!AtEnd() && (Current().isLetterOrNumber() || Current() == '_')) Advance();
    QString Word = Src.mid(Start, Pos - Start);

    if (Word == "function") return MakeToken(TokenType::KwFunction, Word);
    if (Word == "end") return MakeToken(TokenType::KwEnd, Word);
    if (Word == "if") return MakeToken(TokenType::KwIf, Word);
    if (Word == "then") return MakeToken(TokenType::KwThen, Word);
    if (Word == "else") return MakeToken(TokenType::KwElse, Word);
    if (Word == "elseif") return MakeToken(TokenType::KwElseIf, Word);
    if (Word == "while") return MakeToken(TokenType::KwWhile, Word);
    if (Word == "do") return MakeToken(TokenType::KwDo, Word);
    if (Word == "for") return MakeToken(TokenType::KwFor, Word);
    if (Word == "in") return MakeToken(TokenType::KwIn, Word);
    if (Word == "return") return MakeToken(TokenType::KwReturn, Word);
    if (Word == "local") return MakeToken(TokenType::KwLocal, Word);
    if (Word == "nil") return MakeToken(TokenType::KwNil, Word);
    if (Word == "true") return MakeToken(TokenType::KwTrue, Word);
    if (Word == "false") return MakeToken(TokenType::KwFalse, Word);
    if (Word == "and") return MakeToken(TokenType::KwAnd, Word);
    if (Word == "or") return MakeToken(TokenType::KwOr, Word);
    if (Word == "not") return MakeToken(TokenType::KwNot, Word);
    if (Word == "break") return MakeToken(TokenType::KwBreak, Word);
    if (Word == "repeat") return MakeToken(TokenType::KwRepeat, Word);
    if (Word == "until") return MakeToken(TokenType::KwUntil, Word);
    if (Word == "print") return MakeToken(TokenType::KwPrint, Word);

    return MakeToken(TokenType::Identifier, Word);
}

Token Lexer::Peek() {
    if (Buffered.has_value()) return Buffered.value();
    Buffered = Next();
    return Buffered.value();
}

Token Lexer::Next() {
    if (Buffered.has_value()) {
        Token T = Buffered.value();
        Buffered.reset();
        return T;
    }
    SkipWhitespace();
    if (AtEnd()) return MakeToken(TokenType::Eof, "");

    QChar Ch = Current();

    if (Ch.isDigit()) return ReadNumber();
    if (Ch == '"' || Ch == '\'') return ReadString(Ch);
    if (Ch == '[' && Pos + 1 < Src.length() && Src[Pos + 1] == '[') return ReadLongString();
    if (Ch.isLetter() || Ch == '_') return ReadIdentifier();

    Advance();
    switch (Ch.unicode()) {
    case '+': return MakeToken(TokenType::Plus, "+");
    case '*': return MakeToken(TokenType::Star, "*");
    case '/': return MakeToken(TokenType::Slash, "/");
    case '%': return MakeToken(TokenType::Percent, "%");
    case '^': return MakeToken(TokenType::Caret, "^");
    case '#': return MakeToken(TokenType::Hash, "#");
    case '(': return MakeToken(TokenType::LParen, "(");
    case ')': return MakeToken(TokenType::RParen, ")");
    case '[': return MakeToken(TokenType::LBracket, "[");
    case ']': return MakeToken(TokenType::RBracket, "]");
    case '{': return MakeToken(TokenType::LBrace, "{");
    case '}': return MakeToken(TokenType::RBrace, "}");
    case ',': return MakeToken(TokenType::Comma, ",");
    case ';': return MakeToken(TokenType::Semicolon, ";");
    case ':': return MakeToken(TokenType::Colon, ":");
    case '-': return MakeToken(TokenType::Minus, "-");
    case '.':
        if (!AtEnd() && Current() == '.') {
            Advance();
            return MakeToken(TokenType::DotDot, "..");
        }
        return MakeToken(TokenType::Dot, ".");
    case '=':
        if (!AtEnd() && Current() == '=') { Advance(); return MakeToken(TokenType::EqEq, "=="); }
        return MakeToken(TokenType::Eq, "=");
    case '~':
        if (!AtEnd() && Current() == '=') { Advance(); return MakeToken(TokenType::TildeEq, "~="); }
        return MakeToken(TokenType::Error, "~");
    case '<':
        if (!AtEnd() && Current() == '=') { Advance(); return MakeToken(TokenType::LtEq, "<="); }
        return MakeToken(TokenType::Lt, "<");
    case '>':
        if (!AtEnd() && Current() == '=') { Advance(); return MakeToken(TokenType::GtEq, ">="); }
        return MakeToken(TokenType::Gt, ">");
    }
    return MakeToken(TokenType::Error, QString(Ch));
}

Parser::Parser(Lexer& Lex) : Lex(Lex), HadError(false) {
    Cur = Lex.Next();
}

Token Parser::Expect(TokenType Type, const QString& What) {
    if (Cur.Type == Type) {
        Token T = Cur;
        Cur = Lex.Next();
        return T;
    }
    Error("Expected " + What + " got '" + Cur.Value + "'");
    return Cur;
}

bool Parser::Check(TokenType Type) const { return Cur.Type == Type; }

Token Parser::Consume() {
    Token T = Cur;
    Cur = Lex.Next();
    return T;
}

void Parser::Error(const QString& Msg) {
    if (!HadError) {
        HadError = true;
        ErrorMsg = QString("Line %1: %2").arg(Cur.Line).arg(Msg);
    }
}

AstPtr Parser::ParseBlock() {
    auto Block = MakeNode(NodeType::Block, Cur.Line);
    while (Cur.Type != TokenType::Eof && Cur.Type != TokenType::KwEnd &&
           Cur.Type != TokenType::KwElse && Cur.Type != TokenType::KwElseIf &&
           Cur.Type != TokenType::KwUntil && !HadError) {
        auto Stmt = ParseStatement();
        if (Stmt) Block->Children.append(Stmt);
        if (Check(TokenType::Semicolon)) Consume();
    }
    return Block;
}

AstPtr Parser::ParseStatement() {
    if (HadError) return nullptr;
    switch (Cur.Type) {
    case TokenType::KwIf: return ParseIfStatement();
    case TokenType::KwWhile: return ParseWhileLoop();
    case TokenType::KwFor: return ParseForLoop();
    case TokenType::KwRepeat: return ParseRepeatUntil();
    case TokenType::KwReturn: return ParseReturn();
    case TokenType::KwLocal: return ParseLocalDecl();
    case TokenType::KwBreak: { Consume(); return MakeNode(NodeType::Break, Cur.Line); }
    case TokenType::KwFunction: return ParseFunctionDef(false);
    default: return ParseExpressionStatement();
    }
}

AstPtr Parser::ParseIfStatement() {
    int L = Cur.Line;
    Expect(TokenType::KwIf, "if");
    auto Node = MakeNode(NodeType::IfStatement, L);
    Node->Condition = ParseExpression();
    Expect(TokenType::KwThen, "then");
    Node->Body = ParseBlock();
    if (Check(TokenType::KwElseIf)) {
        Node->ElseBranch = ParseIfStatement();
    } else if (Check(TokenType::KwElse)) {
        Consume();
        Node->ElseBranch = ParseBlock();
        Expect(TokenType::KwEnd, "end");
    } else {
        Expect(TokenType::KwEnd, "end");
    }
    return Node;
}

AstPtr Parser::ParseWhileLoop() {
    int L = Cur.Line;
    Expect(TokenType::KwWhile, "while");
    auto Node = MakeNode(NodeType::WhileLoop, L);
    Node->Condition = ParseExpression();
    Expect(TokenType::KwDo, "do");
    Node->Body = ParseBlock();
    Expect(TokenType::KwEnd, "end");
    return Node;
}

AstPtr Parser::ParseForLoop() {
    int L = Cur.Line;
    Expect(TokenType::KwFor, "for");
    QString FirstName = Expect(TokenType::Identifier, "identifier").Value;

    if (Check(TokenType::Eq)) {
        Consume();
        auto Node = MakeNode(NodeType::NumericFor, L);
        Node->Name = FirstName;
        Node->Left = ParseExpression();
        Expect(TokenType::Comma, ",");
        Node->Right = ParseExpression();
        if (Check(TokenType::Comma)) {
            Consume();
            Node->Step = ParseExpression();
        }
        Expect(TokenType::KwDo, "do");
        Node->Body = ParseBlock();
        Expect(TokenType::KwEnd, "end");
        return Node;
    }

    auto Node = MakeNode(NodeType::GenericFor, L);
    Node->Params.append(FirstName);
    while (Check(TokenType::Comma)) {
        Consume();
        Node->Params.append(Expect(TokenType::Identifier, "identifier").Value);
    }
    Expect(TokenType::KwIn, "in");
    Node->Left = ParseExpression();
    if (Check(TokenType::Comma)) {
        Consume();
        Node->Right = ParseExpression();
        if (Check(TokenType::Comma)) {
            Consume();
            Node->Step = ParseExpression();
        }
    }
    Expect(TokenType::KwDo, "do");
    Node->Body = ParseBlock();
    Expect(TokenType::KwEnd, "end");
    return Node;
}

AstPtr Parser::ParseRepeatUntil() {
    int L = Cur.Line;
    Expect(TokenType::KwRepeat, "repeat");
    auto Node = MakeNode(NodeType::RepeatUntil, L);
    Node->Body = ParseBlock();
    Expect(TokenType::KwUntil, "until");
    Node->Condition = ParseExpression();
    return Node;
}

AstPtr Parser::ParseFunctionDef(bool IsLocal) {
    int L = Cur.Line;
    if (!IsLocal) Consume();
    auto Node = MakeNode(NodeType::FunctionDef, L);
    if (Check(TokenType::Identifier)) {
        Node->Name = Consume().Value;
        while (Check(TokenType::Dot)) {
            Consume();
            Node->Name += "." + Expect(TokenType::Identifier, "identifier").Value;
        }
        if (Check(TokenType::Colon)) {
            Consume();
            Node->Name += ":" + Expect(TokenType::Identifier, "identifier").Value;
        }
    }
    return ParseFunctionBody(L);
}

AstPtr Parser::ParseFunctionBody(int L) {
    auto Node = MakeNode(NodeType::FunctionDef, L);
    Expect(TokenType::LParen, "(");
    if (!Check(TokenType::RParen)) {
        Node->Params.append(Expect(TokenType::Identifier, "identifier").Value);
        while (Check(TokenType::Comma)) {
            Consume();
            if (Check(TokenType::Identifier))
                Node->Params.append(Expect(TokenType::Identifier, "identifier").Value);
        }
    }
    Expect(TokenType::RParen, ")");
    Node->Body = ParseBlock();
    Expect(TokenType::KwEnd, "end");
    return Node;
}

AstPtr Parser::ParseReturn() {
    int L = Cur.Line;
    Consume();
    auto Node = MakeNode(NodeType::Return, L);
    if (Cur.Type != TokenType::KwEnd && Cur.Type != TokenType::KwElse &&
        Cur.Type != TokenType::KwElseIf && Cur.Type != TokenType::KwUntil &&
        Cur.Type != TokenType::Eof) {
        Node->Args.append(ParseExpression());
        while (Check(TokenType::Comma)) {
            Consume();
            Node->Args.append(ParseExpression());
        }
    }
    return Node;
}

AstPtr Parser::ParseLocalDecl() {
    int L = Cur.Line;
    Consume();
    if (Check(TokenType::KwFunction)) {
        Consume();
        auto FuncNode = MakeNode(NodeType::FunctionDef, L);
        FuncNode->Name = Expect(TokenType::Identifier, "function name").Value;
        Expect(TokenType::LParen, "(");
        if (!Check(TokenType::RParen)) {
            FuncNode->Params.append(Expect(TokenType::Identifier, "param").Value);
            while (Check(TokenType::Comma)) {
                Consume();
                if (Check(TokenType::Identifier))
                    FuncNode->Params.append(Consume().Value);
            }
        }
        Expect(TokenType::RParen, ")");
        FuncNode->Body = ParseBlock();
        Expect(TokenType::KwEnd, "end");
        auto Decl = MakeNode(NodeType::LocalDecl, L);
        Decl->Name = FuncNode->Name;
        Decl->Right = FuncNode;
        return Decl;
    }
    auto Node = MakeNode(NodeType::LocalDecl, L);
    Node->Name = Expect(TokenType::Identifier, "identifier").Value;
    Node->Params.append(Node->Name);
    while (Check(TokenType::Comma)) {
        Consume();
        Node->Params.append(Expect(TokenType::Identifier, "identifier").Value);
    }
    if (Check(TokenType::Eq)) {
        Consume();
        Node->Args.append(ParseExpression());
        while (Check(TokenType::Comma)) {
            Consume();
            Node->Args.append(ParseExpression());
        }
    }
    return Node;
}

AstPtr Parser::ParseExpressionStatement() {
    auto Expr = ParseExpression();
    if (!Expr) return nullptr;
    if (Check(TokenType::Eq)) {
        Consume();
        auto Assign = MakeNode(NodeType::Assignment, Expr->Line);
        Assign->Left = Expr;
        Assign->Right = ParseExpression();
        return Assign;
    }
    if (Check(TokenType::Comma) && Expr->Type == NodeType::Identifier) {
        auto Assign = MakeNode(NodeType::Assignment, Expr->Line);
        Assign->Children.append(Expr);
        while (Check(TokenType::Comma)) {
            Consume();
            Assign->Children.append(ParseExpression());
        }
        Expect(TokenType::Eq, "=");
        Assign->Args.append(ParseExpression());
        while (Check(TokenType::Comma)) {
            Consume();
            Assign->Args.append(ParseExpression());
        }
        return Assign;
    }
    return Expr;
}

AstPtr Parser::ParseExpression() { return ParseOrExpr(); }

AstPtr Parser::ParseOrExpr() {
    auto Left = ParseAndExpr();
    while (Check(TokenType::KwOr)) {
        int L = Cur.Line; Consume();
        auto Node = MakeNode(NodeType::BinaryOp, L);
        Node->Op = "or"; Node->Left = Left; Node->Right = ParseAndExpr();
        Left = Node;
    }
    return Left;
}

AstPtr Parser::ParseAndExpr() {
    auto Left = ParseCompareExpr();
    while (Check(TokenType::KwAnd)) {
        int L = Cur.Line; Consume();
        auto Node = MakeNode(NodeType::BinaryOp, L);
        Node->Op = "and"; Node->Left = Left; Node->Right = ParseCompareExpr();
        Left = Node;
    }
    return Left;
}

AstPtr Parser::ParseCompareExpr() {
    auto Left = ParseConcatExpr();
    while (Check(TokenType::Lt) || Check(TokenType::Gt) || Check(TokenType::LtEq) ||
           Check(TokenType::GtEq) || Check(TokenType::EqEq) || Check(TokenType::TildeEq)) {
        int L = Cur.Line; Token Op = Consume();
        auto Node = MakeNode(NodeType::BinaryOp, L);
        Node->Op = Op.Value; Node->Left = Left; Node->Right = ParseConcatExpr();
        Left = Node;
    }
    return Left;
}

AstPtr Parser::ParseConcatExpr() {
    auto Left = ParseAddExpr();
    if (Check(TokenType::DotDot)) {
        int L = Cur.Line; Consume();
        auto Node = MakeNode(NodeType::BinaryOp, L);
        Node->Op = ".."; Node->Left = Left; Node->Right = ParseConcatExpr();
        return Node;
    }
    return Left;
}

AstPtr Parser::ParseAddExpr() {
    auto Left = ParseMulExpr();
    while (Check(TokenType::Plus) || Check(TokenType::Minus)) {
        int L = Cur.Line; Token Op = Consume();
        auto Node = MakeNode(NodeType::BinaryOp, L);
        Node->Op = Op.Value; Node->Left = Left; Node->Right = ParseMulExpr();
        Left = Node;
    }
    return Left;
}

AstPtr Parser::ParseMulExpr() {
    auto Left = ParseUnaryExpr();
    while (Check(TokenType::Star) || Check(TokenType::Slash) || Check(TokenType::Percent)) {
        int L = Cur.Line; Token Op = Consume();
        auto Node = MakeNode(NodeType::BinaryOp, L);
        Node->Op = Op.Value; Node->Left = Left; Node->Right = ParseUnaryExpr();
        Left = Node;
    }
    return Left;
}

AstPtr Parser::ParseUnaryExpr() {
    if (Check(TokenType::KwNot)) {
        int L = Cur.Line; Consume();
        auto Node = MakeNode(NodeType::UnaryOp, L);
        Node->Op = "not"; Node->Left = ParseUnaryExpr();
        return Node;
    }
    if (Check(TokenType::Minus)) {
        int L = Cur.Line; Consume();
        auto Node = MakeNode(NodeType::UnaryOp, L);
        Node->Op = "-"; Node->Left = ParseUnaryExpr();
        return Node;
    }
    if (Check(TokenType::Hash)) {
        int L = Cur.Line; Consume();
        auto Node = MakeNode(NodeType::UnaryOp, L);
        Node->Op = "#"; Node->Left = ParseUnaryExpr();
        return Node;
    }
    return ParsePowerExpr();
}

AstPtr Parser::ParsePowerExpr() {
    auto Left = ParsePostfixExpr();
    if (Check(TokenType::Caret)) {
        int L = Cur.Line; Consume();
        auto Node = MakeNode(NodeType::BinaryOp, L);
        Node->Op = "^"; Node->Left = Left; Node->Right = ParseUnaryExpr();
        return Node;
    }
    return Left;
}

AstPtr Parser::ParsePostfixExpr() {
    auto Expr = ParsePrimaryExpr();
    while (true) {
        if (Check(TokenType::Dot)) {
            int L = Cur.Line; Consume();
            auto Node = MakeNode(NodeType::FieldAccess, L);
            Node->Object = Expr; Node->Name = Expect(TokenType::Identifier, "field name").Value;
            Expr = Node;
        } else if (Check(TokenType::LBracket)) {
            int L = Cur.Line; Consume();
            auto Node = MakeNode(NodeType::IndexAccess, L);
            Node->Object = Expr; Node->Left = ParseExpression();
            Expect(TokenType::RBracket, "]"); Expr = Node;
        } else if (Check(TokenType::LParen)) {
            int L = Cur.Line; Consume();
            auto Call = MakeNode(NodeType::FunctionCall, L);
            Call->Object = Expr;
            if (!Check(TokenType::RParen)) {
                Call->Args.append(ParseExpression());
                while (Check(TokenType::Comma)) { Consume(); Call->Args.append(ParseExpression()); }
            }
            Expect(TokenType::RParen, ")"); Expr = Call;
        } else if (Check(TokenType::Colon)) {
            int L = Cur.Line; Consume();
            QString MethodName = Expect(TokenType::Identifier, "method name").Value;
            Expect(TokenType::LParen, "(");
            auto Call = MakeNode(NodeType::MethodCall, L);
            Call->Object = Expr; Call->Name = MethodName;
            if (!Check(TokenType::RParen)) {
                Call->Args.append(ParseExpression());
                while (Check(TokenType::Comma)) { Consume(); Call->Args.append(ParseExpression()); }
            }
            Expect(TokenType::RParen, ")"); Expr = Call;
        } else if (Check(TokenType::String)) {
            int L = Cur.Line;
            auto Call = MakeNode(NodeType::FunctionCall, L);
            Call->Object = Expr;
            auto StrArg = MakeNode(NodeType::StringLiteral, L);
            StrArg->StrVal = Consume().Value;
            Call->Args.append(StrArg); Expr = Call;
        } else if (Check(TokenType::LBrace)) {
            int L = Cur.Line;
            auto Call = MakeNode(NodeType::FunctionCall, L);
            Call->Object = Expr; Call->Args.append(ParseTableConstructor());
            Expr = Call;
        } else { break; }
    }
    return Expr;
}

AstPtr Parser::ParsePrimaryExpr() {
    if (Check(TokenType::Number)) {
        auto Node = MakeNode(NodeType::NumberLiteral, Cur.Line);
        QString Val = Consume().Value;
        if (Val.startsWith("0x") || Val.startsWith("0X"))
            Node->NumVal = static_cast<double>(Val.toULongLong(nullptr, 16));
        else Node->NumVal = Val.toDouble();
        return Node;
    }
    if (Check(TokenType::String)) {
        auto Node = MakeNode(NodeType::StringLiteral, Cur.Line);
        Node->StrVal = Consume().Value; return Node;
    }
    if (Check(TokenType::KwTrue)) { Consume(); auto N = MakeNode(NodeType::BoolLiteral, Cur.Line); N->BoolVal = true; return N; }
    if (Check(TokenType::KwFalse)) { Consume(); auto N = MakeNode(NodeType::BoolLiteral, Cur.Line); N->BoolVal = false; return N; }
    if (Check(TokenType::KwNil)) { Consume(); return MakeNode(NodeType::NilLiteral, Cur.Line); }
    if (Check(TokenType::Identifier) || Check(TokenType::KwPrint)) {
        auto Node = MakeNode(NodeType::Identifier, Cur.Line);
        Node->Name = Consume().Value; return Node;
    }
    if (Check(TokenType::LParen)) { Consume(); auto E = ParseExpression(); Expect(TokenType::RParen, ")"); return E; }
    if (Check(TokenType::LBrace)) return ParseTableConstructor();
    if (Check(TokenType::KwFunction)) { int L = Cur.Line; Consume(); return ParseFunctionBody(L); }
    Error("Unexpected token: " + Cur.Value); Consume();
    return MakeNode(NodeType::NilLiteral, Cur.Line);
}

AstPtr Parser::ParseTableConstructor() {
    int L = Cur.Line; Expect(TokenType::LBrace, "{");
    auto Node = MakeNode(NodeType::TableConstructor, L);
    while (!Check(TokenType::RBrace) && !Check(TokenType::Eof) && !HadError) {
        if (Check(TokenType::LBracket)) {
            Consume(); auto Key = ParseExpression();
            Expect(TokenType::RBracket, "]"); Expect(TokenType::Eq, "=");
            Node->Fields.append({Key, ParseExpression()});
        } else if (Check(TokenType::Identifier) && Lex.Peek().Type == TokenType::Eq) {
            auto Key = MakeNode(NodeType::StringLiteral, Cur.Line);
            Key->StrVal = Consume().Value; Consume();
            Node->Fields.append({Key, ParseExpression()});
        } else {
            Node->Children.append(ParseExpression());
        }
        if (Check(TokenType::Comma) || Check(TokenType::Semicolon)) Consume();
    }
    Expect(TokenType::RBrace, "}"); return Node;
}

ScriptValue::ScriptValue() : Type(ScriptType::Nil), BoolVal(false), NumberVal(0) {}
ScriptValuePtr ScriptValue::MakeNil() { return std::make_shared<ScriptValue>(); }
ScriptValuePtr ScriptValue::MakeBool(bool V) { auto R = std::make_shared<ScriptValue>(); R->Type = ScriptType::Bool; R->BoolVal = V; return R; }
ScriptValuePtr ScriptValue::MakeNumber(double V) { auto R = std::make_shared<ScriptValue>(); R->Type = ScriptType::Number; R->NumberVal = V; return R; }
ScriptValuePtr ScriptValue::MakeString(const QString& V) { auto R = std::make_shared<ScriptValue>(); R->Type = ScriptType::String; R->StringVal = V; return R; }

ScriptValuePtr ScriptValue::MakeTable() {
    auto R = std::make_shared<ScriptValue>(); R->Type = ScriptType::Table;
    R->TableVal = std::make_shared<ScriptTable>(); return R;
}

ScriptValuePtr ScriptValue::MakeFunction(const QVector<QString>& Params, AstPtr Body, const QMap<QString, ScriptValuePtr>& Closure) {
    auto R = std::make_shared<ScriptValue>(); R->Type = ScriptType::Function;
    R->FuncVal.Params = Params; R->FuncVal.Body = Body; R->FuncVal.Closure = Closure; return R;
}

ScriptValuePtr ScriptValue::MakeNativeFunction(NativeFunction Fn) {
    auto R = std::make_shared<ScriptValue>(); R->Type = ScriptType::NativeFunction;
    R->NativeFuncVal = Fn; return R;
}

bool ScriptValue::IsTruthy() const { if (Type == ScriptType::Nil) return false; if (Type == ScriptType::Bool) return BoolVal; return true; }

QString ScriptValue::ToString() const {
    switch (Type) {
    case ScriptType::Nil: return "nil";
    case ScriptType::Bool: return BoolVal ? "true" : "false";
    case ScriptType::Number:
        if (NumberVal == static_cast<int64_t>(NumberVal) && std::abs(NumberVal) < 1e15) return QString::number(static_cast<int64_t>(NumberVal));
        return QString::number(NumberVal, 'g', 14);
    case ScriptType::String: return StringVal;
    case ScriptType::Table: return "table";
    case ScriptType::Function: case ScriptType::NativeFunction: return "function";
    }
    return "nil";
}

QString ScriptValue::TypeName() const {
    switch (Type) {
    case ScriptType::Nil: return "nil"; case ScriptType::Bool: return "boolean";
    case ScriptType::Number: return "number"; case ScriptType::String: return "string";
    case ScriptType::Table: return "table";
    case ScriptType::Function: case ScriptType::NativeFunction: return "function";
    }
    return "nil";
}

ScriptValuePtr ScriptTable::Get(const QString& Key) const { auto It = Map.find(Key); if (It != Map.end()) return It.value(); return ScriptValue::MakeNil(); }
ScriptValuePtr ScriptTable::Get(int Index) const { if (Index >= 1 && Index <= Array.size()) return Array[Index - 1]; return ScriptValue::MakeNil(); }
void ScriptTable::Set(const QString& Key, ScriptValuePtr Val) { if (Val->Type == ScriptType::Nil) Map.remove(Key); else Map[Key] = Val; }
void ScriptTable::Set(int Index, ScriptValuePtr Val) { if (Index >= 1 && Index <= Array.size()) Array[Index - 1] = Val; else if (Index == Array.size() + 1) Array.append(Val); }
void ScriptTable::Append(ScriptValuePtr Val) { Array.append(Val); }
int ScriptTable::Length() const { return Array.size(); }

Environment::Environment(std::shared_ptr<Environment> Parent) : ParentEnv(Parent) {}
ScriptValuePtr Environment::Get(const QString& Name) const { auto It = Vars.find(Name); if (It != Vars.end()) return It.value(); if (ParentEnv) return ParentEnv->Get(Name); return ScriptValue::MakeNil(); }
bool Environment::Set(const QString& Name, ScriptValuePtr Value) { auto It = Vars.find(Name); if (It != Vars.end()) { Vars[Name] = Value; return true; } if (ParentEnv) return ParentEnv->Set(Name, Value); return false; }
void Environment::Define(const QString& Name, ScriptValuePtr Value) { Vars[Name] = Value; }
QStringList Environment::GetAllNames() const { QStringList N = Vars.keys(); if (ParentEnv) N.append(ParentEnv->GetAllNames()); return N; }

Interpreter::Interpreter() : InstructionCount(0) { CancelFlag.storeRelaxed(0); GlobalEnv = std::make_shared<Environment>(); }
void Interpreter::SetOutputCallback(std::function<void(const QString&)> Cb) { OutputCb = Cb; }
void Interpreter::SetErrorCallback(std::function<void(const QString&)> Cb) { ErrorCb = Cb; }
void Interpreter::RegisterGlobal(const QString& Name, ScriptValuePtr Value) { GlobalEnv->Define(Name, Value); }
void Interpreter::RegisterNative(const QString& Name, NativeFunction Fn) { GlobalEnv->Define(Name, ScriptValue::MakeNativeFunction(Fn)); }
void Interpreter::Cancel() { CancelFlag.storeRelaxed(1); }
bool Interpreter::WasCancelled() const { return CancelFlag.loadRelaxed() != 0; }
void Interpreter::RuntimeError(const QString& Msg, int Line) { QString F = Line > 0 ? QString("Line %1: %2").arg(Line).arg(Msg) : Msg; throw std::runtime_error(F.toStdString()); }
void Interpreter::Execute(AstPtr Root) { InstructionCount = 0; CancelFlag.storeRelaxed(0); ExecBlock(Root, GlobalEnv); }

void Interpreter::ExecBlock(AstPtr Node, std::shared_ptr<Environment> Env) { for (const auto& C : Node->Children) ExecStatement(C, Env); }

void Interpreter::ExecStatement(AstPtr Node, std::shared_ptr<Environment> Env) {
    if (CancelFlag.loadRelaxed()) throw std::runtime_error("Cancelled");
    if (++InstructionCount > MaxInstructions) RuntimeError("Instruction limit exceeded", Node->Line);
    switch (Node->Type) {
    case NodeType::Assignment: ExecAssignment(Node, Env); break;
    case NodeType::LocalDecl: ExecLocalDecl(Node, Env); break;
    case NodeType::IfStatement: ExecIf(Node, Env); break;
    case NodeType::WhileLoop: ExecWhile(Node, Env); break;
    case NodeType::NumericFor: ExecNumericFor(Node, Env); break;
    case NodeType::GenericFor: ExecGenericFor(Node, Env); break;
    case NodeType::RepeatUntil: ExecRepeatUntil(Node, Env); break;
    case NodeType::Return: { ReturnSignal S; for (const auto& A : Node->Args) S.Values.append(Eval(A, Env)); throw S; }
    case NodeType::Break: throw BreakSignal{};
    case NodeType::FunctionDef: {
        auto Fn = Eval(Node, Env);
        if (!Node->Name.isEmpty()) {
            if (Node->Name.contains(".")) {
                QStringList Parts = Node->Name.split("."); auto Obj = Env->Get(Parts[0]);
                for (int I = 1; I < Parts.size() - 1; ++I) { if (Obj->Type == ScriptType::Table) Obj = Obj->TableVal->Get(Parts[I]); }
                if (Obj->Type == ScriptType::Table) Obj->TableVal->Set(Parts.last(), Fn);
            } else { if (!Env->Set(Node->Name, Fn)) GlobalEnv->Define(Node->Name, Fn); }
        }
        break;
    }
    default: Eval(Node, Env); break;
    }
}

void Interpreter::ExecAssignment(AstPtr Node, std::shared_ptr<Environment> Env) {
    if (Node->Children.size() > 0) {
        QVector<ScriptValuePtr> Vals; for (const auto& A : Node->Args) Vals.append(Eval(A, Env));
        for (int I = 0; I < Node->Children.size(); ++I) SetTarget(Node->Children[I], I < Vals.size() ? Vals[I] : ScriptValue::MakeNil(), Env);
    } else { SetTarget(Node->Left, Eval(Node->Right, Env), Env); }
}

void Interpreter::ExecLocalDecl(AstPtr Node, std::shared_ptr<Environment> Env) {
    if (Node->Right && Node->Right->Type == NodeType::FunctionDef) { Env->Define(Node->Name, Eval(Node->Right, Env)); return; }
    QVector<ScriptValuePtr> Vals; for (const auto& A : Node->Args) Vals.append(Eval(A, Env));
    for (int I = 0; I < Node->Params.size(); ++I) Env->Define(Node->Params[I], I < Vals.size() ? Vals[I] : ScriptValue::MakeNil());
}

void Interpreter::ExecIf(AstPtr Node, std::shared_ptr<Environment> Env) {
    if (Eval(Node->Condition, Env)->IsTruthy()) { ExecBlock(Node->Body, std::make_shared<Environment>(Env)); }
    else if (Node->ElseBranch) { if (Node->ElseBranch->Type == NodeType::IfStatement) ExecIf(Node->ElseBranch, Env); else ExecBlock(Node->ElseBranch, std::make_shared<Environment>(Env)); }
}

void Interpreter::ExecWhile(AstPtr Node, std::shared_ptr<Environment> Env) {
    while (Eval(Node->Condition, Env)->IsTruthy()) { try { ExecBlock(Node->Body, std::make_shared<Environment>(Env)); } catch (BreakSignal&) { break; } }
}

void Interpreter::ExecNumericFor(AstPtr Node, std::shared_ptr<Environment> Env) {
    double Start = Eval(Node->Left, Env)->NumberVal, Limit = Eval(Node->Right, Env)->NumberVal;
    double Step = Node->Step ? Eval(Node->Step, Env)->NumberVal : 1.0;
    if (Step == 0) RuntimeError("for loop step is 0", Node->Line);
    for (double I = Start; Step > 0 ? I <= Limit : I >= Limit; I += Step) {
        auto Sub = std::make_shared<Environment>(Env); Sub->Define(Node->Name, ScriptValue::MakeNumber(I));
        try { ExecBlock(Node->Body, Sub); } catch (BreakSignal&) { break; }
    }
}

void Interpreter::ExecGenericFor(AstPtr Node, std::shared_ptr<Environment> Env) {
    auto IterFunc = Eval(Node->Left, Env);
    auto State = Node->Right ? Eval(Node->Right, Env) : ScriptValue::MakeNil();
    auto Control = Node->Step ? Eval(Node->Step, Env) : ScriptValue::MakeNil();
    while (true) {
        ScriptValuePtr Result; try { Result = CallFunction(IterFunc, {State, Control}, Env); } catch (...) { break; }
        if (!Result || Result->Type == ScriptType::Nil) break;
        auto Sub = std::make_shared<Environment>(Env);
        if (Result->Type == ScriptType::Table && Result->TableVal) {
            for (int I = 0; I < Node->Params.size() && I < Result->TableVal->Length(); ++I) Sub->Define(Node->Params[I], Result->TableVal->Get(I + 1));
            if (Result->TableVal->Length() > 0) Control = Result->TableVal->Get(1);
        } else { if (Node->Params.size() > 0) Sub->Define(Node->Params[0], Result); Control = Result; }
        if (Control->Type == ScriptType::Nil) break;
        try { ExecBlock(Node->Body, Sub); } catch (BreakSignal&) { break; }
    }
}

void Interpreter::ExecRepeatUntil(AstPtr Node, std::shared_ptr<Environment> Env) {
    while (true) { auto Sub = std::make_shared<Environment>(Env); try { ExecBlock(Node->Body, Sub); } catch (BreakSignal&) { break; } if (Eval(Node->Condition, Sub)->IsTruthy()) break; }
}

void Interpreter::SetTarget(AstPtr Target, ScriptValuePtr Value, std::shared_ptr<Environment> Env) {
    if (Target->Type == NodeType::Identifier) { if (!Env->Set(Target->Name, Value)) GlobalEnv->Define(Target->Name, Value); }
    else if (Target->Type == NodeType::FieldAccess) { auto O = Eval(Target->Object, Env); if (O->Type == ScriptType::Table) O->TableVal->Set(Target->Name, Value); }
    else if (Target->Type == NodeType::IndexAccess) { auto O = Eval(Target->Object, Env); auto K = Eval(Target->Left, Env); if (O->Type == ScriptType::Table) { if (K->Type == ScriptType::Number) O->TableVal->Set(static_cast<int>(K->NumberVal), Value); else O->TableVal->Set(K->ToString(), Value); } }
}

ScriptValuePtr Interpreter::CallFunction(ScriptValuePtr Fn, const QVector<ScriptValuePtr>& Args, std::shared_ptr<Environment> Env) {
    if (Fn->Type == ScriptType::NativeFunction) return Fn->NativeFuncVal(Args);
    if (Fn->Type == ScriptType::Function) {
        auto FE = std::make_shared<Environment>(GlobalEnv);
        for (auto It = Fn->FuncVal.Closure.begin(); It != Fn->FuncVal.Closure.end(); ++It) FE->Define(It.key(), It.value());
        for (int I = 0; I < Fn->FuncVal.Params.size(); ++I) FE->Define(Fn->FuncVal.Params[I], I < Args.size() ? Args[I] : ScriptValue::MakeNil());
        try { ExecBlock(Fn->FuncVal.Body, FE); } catch (ReturnSignal& R) { if (!R.Values.isEmpty()) return R.Values[0]; }
        return ScriptValue::MakeNil();
    }
    RuntimeError("Attempt to call a " + Fn->TypeName() + " value"); return ScriptValue::MakeNil();
}

ScriptValuePtr Interpreter::Eval(AstPtr Node, std::shared_ptr<Environment> Env) {
    if (!Node) return ScriptValue::MakeNil();
    if (CancelFlag.loadRelaxed()) throw std::runtime_error("Cancelled");
    ++InstructionCount;
    switch (Node->Type) {
    case NodeType::NumberLiteral: return ScriptValue::MakeNumber(Node->NumVal);
    case NodeType::StringLiteral: return ScriptValue::MakeString(Node->StrVal);
    case NodeType::BoolLiteral: return ScriptValue::MakeBool(Node->BoolVal);
    case NodeType::NilLiteral: return ScriptValue::MakeNil();
    case NodeType::Identifier: return Env->Get(Node->Name);
    case NodeType::FunctionDef: { QMap<QString, ScriptValuePtr> Cl; auto Ns = Env->GetAllNames(); for (const auto& N : Ns) Cl[N] = Env->Get(N); return ScriptValue::MakeFunction(Node->Params, Node->Body, Cl); }
    case NodeType::TableConstructor: { auto T = ScriptValue::MakeTable(); for (const auto& C : Node->Children) T->TableVal->Append(Eval(C, Env)); for (const auto& F : Node->Fields) { auto K = Eval(F.first, Env); auto V = Eval(F.second, Env); if (K->Type == ScriptType::Number) T->TableVal->Set(static_cast<int>(K->NumberVal), V); else T->TableVal->Set(K->ToString(), V); } return T; }
    case NodeType::FieldAccess: { auto O = Eval(Node->Object, Env); if (O->Type == ScriptType::Table) return O->TableVal->Get(Node->Name); if (O->Type == ScriptType::String) { auto SL = Env->Get("string"); if (SL->Type == ScriptType::Table) return SL->TableVal->Get(Node->Name); } return ScriptValue::MakeNil(); }
    case NodeType::IndexAccess: { auto O = Eval(Node->Object, Env); auto K = Eval(Node->Left, Env); if (O->Type == ScriptType::Table) { if (K->Type == ScriptType::Number) return O->TableVal->Get(static_cast<int>(K->NumberVal)); return O->TableVal->Get(K->ToString()); } return ScriptValue::MakeNil(); }
    case NodeType::FunctionCall: { auto C = Eval(Node->Object, Env); QVector<ScriptValuePtr> A; for (const auto& Ar : Node->Args) A.append(Eval(Ar, Env)); return CallFunction(C, A, Env); }
    case NodeType::MethodCall: { auto O = Eval(Node->Object, Env); ScriptValuePtr M; if (O->Type == ScriptType::Table) M = O->TableVal->Get(Node->Name); else if (O->Type == ScriptType::String) { auto SL = Env->Get("string"); if (SL->Type == ScriptType::Table) M = SL->TableVal->Get(Node->Name); } if (!M || (M->Type != ScriptType::Function && M->Type != ScriptType::NativeFunction)) RuntimeError("No method '" + Node->Name + "'", Node->Line); QVector<ScriptValuePtr> A = {O}; for (const auto& Ar : Node->Args) A.append(Eval(Ar, Env)); return CallFunction(M, A, Env); }
    case NodeType::BinaryOp: {
        if (Node->Op == "and") { auto L = Eval(Node->Left, Env); if (!L->IsTruthy()) return L; return Eval(Node->Right, Env); }
        if (Node->Op == "or") { auto L = Eval(Node->Left, Env); if (L->IsTruthy()) return L; return Eval(Node->Right, Env); }
        auto L = Eval(Node->Left, Env); auto R = Eval(Node->Right, Env);
        if (Node->Op == "..") return ScriptValue::MakeString(L->ToString() + R->ToString());
        if (Node->Op == "==") return ScriptValue::MakeBool(L->ToString() == R->ToString() && L->Type == R->Type);
        if (Node->Op == "~=") return ScriptValue::MakeBool(L->ToString() != R->ToString() || L->Type != R->Type);
        if (L->Type == ScriptType::Number && R->Type == ScriptType::Number) {
            double Lv = L->NumberVal, Rv = R->NumberVal;
            if (Node->Op == "+") return ScriptValue::MakeNumber(Lv + Rv);
            if (Node->Op == "-") return ScriptValue::MakeNumber(Lv - Rv);
            if (Node->Op == "*") return ScriptValue::MakeNumber(Lv * Rv);
            if (Node->Op == "/") { if (Rv == 0) RuntimeError("Division by zero", Node->Line); return ScriptValue::MakeNumber(Lv / Rv); }
            if (Node->Op == "%") { if (Rv == 0) RuntimeError("Modulo by zero", Node->Line); return ScriptValue::MakeNumber(Lv - std::floor(Lv / Rv) * Rv); }
            if (Node->Op == "^") return ScriptValue::MakeNumber(std::pow(Lv, Rv));
            if (Node->Op == "<") return ScriptValue::MakeBool(Lv < Rv); if (Node->Op == ">") return ScriptValue::MakeBool(Lv > Rv);
            if (Node->Op == "<=") return ScriptValue::MakeBool(Lv <= Rv); if (Node->Op == ">=") return ScriptValue::MakeBool(Lv >= Rv);
        }
        if (L->Type == ScriptType::String && R->Type == ScriptType::String) {
            if (Node->Op == "<") return ScriptValue::MakeBool(L->StringVal < R->StringVal); if (Node->Op == ">") return ScriptValue::MakeBool(L->StringVal > R->StringVal);
            if (Node->Op == "<=") return ScriptValue::MakeBool(L->StringVal <= R->StringVal); if (Node->Op == ">=") return ScriptValue::MakeBool(L->StringVal >= R->StringVal);
        }
        RuntimeError("Invalid operands for " + Node->Op, Node->Line); return ScriptValue::MakeNil();
    }
    case NodeType::UnaryOp: {
        auto Op = Eval(Node->Left, Env);
        if (Node->Op == "-") { if (Op->Type == ScriptType::Number) return ScriptValue::MakeNumber(-Op->NumberVal); RuntimeError("Negate non-number", Node->Line); }
        if (Node->Op == "not") return ScriptValue::MakeBool(!Op->IsTruthy());
        if (Node->Op == "#") { if (Op->Type == ScriptType::String) return ScriptValue::MakeNumber(Op->StringVal.length()); if (Op->Type == ScriptType::Table) return ScriptValue::MakeNumber(Op->TableVal->Length()); RuntimeError("Length of " + Op->TypeName(), Node->Line); }
        return ScriptValue::MakeNil();
    }
    default: return ScriptValue::MakeNil();
    }
}

QStringList Interpreter::GetCompletions(const QString& Prefix) const {
    QStringList R; auto Ns = GlobalEnv->GetAllNames();
    for (const auto& N : Ns) if (N.startsWith(Prefix, Qt::CaseInsensitive)) R.append(N);
    return R;
}

static QString FormatString(const QString& Fmt, const QVector<ScriptValuePtr>& Args, int StartIdx) {
    QString Result; int ArgIdx = StartIdx;
    for (int I = 0; I < Fmt.length(); ++I) {
        if (Fmt[I] == '%' && I + 1 < Fmt.length()) {
            ++I; if (Fmt[I] == '%') { Result += '%'; continue; }
            QString FS = "%";
            while (I < Fmt.length() && (Fmt[I] == '-' || Fmt[I] == '+' || Fmt[I] == ' ' || Fmt[I] == '0' || Fmt[I] == '#')) { FS += Fmt[I]; ++I; }
            while (I < Fmt.length() && Fmt[I].isDigit()) { FS += Fmt[I]; ++I; }
            if (I < Fmt.length() && Fmt[I] == '.') { FS += Fmt[I]; ++I; while (I < Fmt.length() && Fmt[I].isDigit()) { FS += Fmt[I]; ++I; } }
            if (I >= Fmt.length()) break;
            QChar Spec = Fmt[I]; auto Val = ArgIdx < Args.size() ? Args[ArgIdx] : ScriptValue::MakeNil(); ++ArgIdx;
            char Buf[64];
            if (Spec == 'd' || Spec == 'i') { snprintf(Buf, sizeof(Buf), (FS + "lld").toUtf8().constData(), static_cast<int64_t>(Val->NumberVal)); Result += QString::fromUtf8(Buf); }
            else if (Spec == 'u') { snprintf(Buf, sizeof(Buf), (FS + "llu").toUtf8().constData(), static_cast<uint64_t>(Val->NumberVal)); Result += QString::fromUtf8(Buf); }
            else if (Spec == 'f' || Spec == 'g' || Spec == 'e') { snprintf(Buf, sizeof(Buf), (FS + Spec).toUtf8().constData(), Val->NumberVal); Result += QString::fromUtf8(Buf); }
            else if (Spec == 'x' || Spec == 'X') { snprintf(Buf, sizeof(Buf), (FS + "ll" + Spec).toUtf8().constData(), static_cast<uint64_t>(Val->NumberVal)); Result += QString::fromUtf8(Buf); }
            else if (Spec == 'o') { snprintf(Buf, sizeof(Buf), (FS + "llo").toUtf8().constData(), static_cast<uint64_t>(Val->NumberVal)); Result += QString::fromUtf8(Buf); }
            else if (Spec == 's') Result += Val->ToString();
            else if (Spec == 'c') Result += QChar(static_cast<int>(Val->NumberVal));
            else if (Spec == 'q') Result += "\"" + Val->ToString().replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
        } else Result += Fmt[I];
    }
    return Result;
}

ScriptEngine::ScriptEngine(ICore* Core, QObject* Parent) : QObject(Parent), CoreRef(Core), DbRef(nullptr), Interp(std::make_unique<Interpreter>()) {
    Interp->SetOutputCallback([this](const QString& T) { OutputBuffer += T + "\n"; emit OutputReady(T); });
    Interp->SetErrorCallback([this](const QString& T) { ErrorBuffer += T + "\n"; emit ErrorOccurred(T); });
    RegisterBuiltins(); RegisterFidraApi();
}

ScriptEngine::~ScriptEngine() = default;
void ScriptEngine::SetAnalysisDatabase(AnalysisDatabase* Db) { DbRef = Db; }

bool ScriptEngine::Execute(const QString& Code) {
    OutputBuffer.clear(); ErrorBuffer.clear();
    Lexer Lex(Code); Parser Parse(Lex); auto Ast = Parse.ParseBlock();
    if (Parse.HadError) { ErrorBuffer = Parse.ErrorMsg; emit ErrorOccurred(Parse.ErrorMsg); emit ExecutionFinished(false); return false; }
    try { Interp->Execute(Ast); emit ExecutionFinished(true); return true; }
    catch (const std::runtime_error& E) { QString Err = QString::fromStdString(E.what()); ErrorBuffer = Err; emit ErrorOccurred(Err); emit ExecutionFinished(false); return false; }
    catch (ReturnSignal&) { emit ExecutionFinished(true); return true; }
    catch (...) { emit ErrorOccurred("Unknown error"); emit ExecutionFinished(false); return false; }
}

bool ScriptEngine::ExecuteFile(const QString& Path) {
    QFile F(Path); if (!F.open(QIODevice::ReadOnly | QIODevice::Text)) { emit ErrorOccurred("Cannot open: " + Path); return false; }
    QString Code = QTextStream(&F).readAll(); F.close(); return Execute(Code);
}

void ScriptEngine::Cancel() { Interp->Cancel(); }
QString ScriptEngine::GetOutput() const { return OutputBuffer; }
QString ScriptEngine::GetError() const { return ErrorBuffer; }
QStringList ScriptEngine::GetCompletions(const QString& Prefix) const { return Interp->GetCompletions(Prefix); }

void ScriptEngine::RegisterBuiltins() {
    Interp->RegisterNative("print", [this](const QVector<ScriptValuePtr>& Args) -> ScriptValuePtr { QStringList P; for (const auto& A : Args) P.append(A->ToString()); if (Interp->OutputCb) Interp->OutputCb(P.join("\t")); return ScriptValue::MakeNil(); });
    Interp->RegisterNative("type", [](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { return ScriptValue::MakeString(A.isEmpty() ? "nil" : A[0]->TypeName()); });
    Interp->RegisterNative("tostring", [](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { return ScriptValue::MakeString(A.isEmpty() ? "nil" : A[0]->ToString()); });
    Interp->RegisterNative("tonumber", [](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty()) return ScriptValue::MakeNil(); if (A[0]->Type == ScriptType::Number) return A[0]; if (A[0]->Type == ScriptType::String) { bool Ok; double V = A[0]->StringVal.toDouble(&Ok); if (Ok) return ScriptValue::MakeNumber(V); } return ScriptValue::MakeNil(); });
    Interp->RegisterNative("format", [](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty()) return ScriptValue::MakeString(""); return ScriptValue::MakeString(FormatString(A[0]->ToString(), A, 1)); });
    Interp->RegisterNative("error", [](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { throw std::runtime_error((A.isEmpty() ? "error" : A[0]->ToString()).toStdString()); return ScriptValue::MakeNil(); });
    Interp->RegisterNative("assert", [](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty() || !A[0]->IsTruthy()) throw std::runtime_error((A.size() > 1 ? A[1]->ToString() : "assertion failed").toStdString()); return A[0]; });
    Interp->RegisterNative("pcall", [this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty()) return ScriptValue::MakeBool(false); QVector<ScriptValuePtr> FA(A.begin()+1, A.end()); try { auto R = Interp->CallFunction(A[0], FA, Interp->GlobalEnv); auto T = ScriptValue::MakeTable(); T->TableVal->Append(ScriptValue::MakeBool(true)); T->TableVal->Append(R); return T; } catch (const std::exception& E) { auto T = ScriptValue::MakeTable(); T->TableVal->Append(ScriptValue::MakeBool(false)); T->TableVal->Append(ScriptValue::MakeString(QString::fromStdString(E.what()))); return T; } });
    Interp->RegisterNative("select", [](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty()) return ScriptValue::MakeNil(); if (A[0]->Type == ScriptType::String && A[0]->StringVal == "#") return ScriptValue::MakeNumber(A.size()-1); int I = static_cast<int>(A[0]->NumberVal); if (I >= 1 && I < A.size()) return A[I]; return ScriptValue::MakeNil(); });
    Interp->RegisterNative("unpack", [](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty() || A[0]->Type != ScriptType::Table) return ScriptValue::MakeNil(); auto T = ScriptValue::MakeTable(); for (int I = 0; I < A[0]->TableVal->Length(); ++I) T->TableVal->Append(A[0]->TableVal->Get(I+1)); return T; });

    Interp->RegisterNative("pairs", [](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr {
        if (A.isEmpty() || A[0]->Type != ScriptType::Table) return ScriptValue::MakeNil();
        auto Tbl = A[0]->TableVal; int Idx = 0;
        return ScriptValue::MakeNativeFunction([Tbl, Idx](const QVector<ScriptValuePtr>&) mutable -> ScriptValuePtr {
            if (Idx < Tbl->Length()) { auto R = ScriptValue::MakeTable(); R->TableVal->Append(ScriptValue::MakeNumber(Idx+1)); R->TableVal->Append(Tbl->Get(Idx+1)); ++Idx; return R; }
            auto Ks = Tbl->Map.keys(); int MI = Idx - Tbl->Length();
            if (MI < Ks.size()) { auto R = ScriptValue::MakeTable(); R->TableVal->Append(ScriptValue::MakeString(Ks[MI])); R->TableVal->Append(Tbl->Map[Ks[MI]]); ++Idx; return R; }
            return ScriptValue::MakeNil();
        });
    });

    Interp->RegisterNative("ipairs", [](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr {
        if (A.isEmpty() || A[0]->Type != ScriptType::Table) return ScriptValue::MakeNil();
        auto Tbl = A[0]->TableVal; int Idx = 0;
        return ScriptValue::MakeNativeFunction([Tbl, Idx](const QVector<ScriptValuePtr>&) mutable -> ScriptValuePtr {
            if (Idx < Tbl->Length()) { auto R = ScriptValue::MakeTable(); R->TableVal->Append(ScriptValue::MakeNumber(Idx+1)); R->TableVal->Append(Tbl->Get(Idx+1)); ++Idx; return R; }
            return ScriptValue::MakeNil();
        });
    });

    auto SL = ScriptValue::MakeTable();
    SL->TableVal->Set("format", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty()) return ScriptValue::MakeString(""); int S = 0; QString Fmt; if (A[0]->Type == ScriptType::String) { Fmt = A[0]->StringVal; S = 1; } else if (A.size()>1 && A[1]->Type == ScriptType::String) { Fmt = A[1]->StringVal; S = 2; } else return ScriptValue::MakeString(""); return ScriptValue::MakeString(FormatString(Fmt, A, S)); }));
    SL->TableVal->Set("len", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty() || A[0]->Type != ScriptType::String) return ScriptValue::MakeNumber(0); return ScriptValue::MakeNumber(A[0]->StringVal.length()); }));
    SL->TableVal->Set("sub", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty() || A[0]->Type != ScriptType::String) return ScriptValue::MakeString(""); QString S = A[0]->StringVal; int I = A.size()>1 ? static_cast<int>(A[1]->NumberVal) : 1; int J = A.size()>2 ? static_cast<int>(A[2]->NumberVal) : S.length(); if (I<0) I=S.length()+I+1; if (J<0) J=S.length()+J+1; if (I<1) I=1; if (J>S.length()) J=S.length(); if (I>J) return ScriptValue::MakeString(""); return ScriptValue::MakeString(S.mid(I-1, J-I+1)); }));
    SL->TableVal->Set("upper", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { return ScriptValue::MakeString(A.isEmpty() ? "" : A[0]->ToString().toUpper()); }));
    SL->TableVal->Set("lower", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { return ScriptValue::MakeString(A.isEmpty() ? "" : A[0]->ToString().toLower()); }));
    SL->TableVal->Set("rep", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.size()<2) return ScriptValue::MakeString(""); return ScriptValue::MakeString(A[0]->ToString().repeated(static_cast<int>(A[1]->NumberVal))); }));
    SL->TableVal->Set("reverse", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty()) return ScriptValue::MakeString(""); QString S = A[0]->ToString(); std::reverse(S.begin(), S.end()); return ScriptValue::MakeString(S); }));
    SL->TableVal->Set("byte", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty() || A[0]->Type != ScriptType::String || A[0]->StringVal.isEmpty()) return ScriptValue::MakeNil(); int I = A.size()>1 ? static_cast<int>(A[1]->NumberVal)-1 : 0; if (I<0 || I>=A[0]->StringVal.length()) return ScriptValue::MakeNil(); return ScriptValue::MakeNumber(A[0]->StringVal[I].unicode()); }));
    SL->TableVal->Set("char", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { QString R; for (const auto& V : A) R += QChar(static_cast<int>(V->NumberVal)); return ScriptValue::MakeString(R); }));
    SL->TableVal->Set("find", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.size()<2) return ScriptValue::MakeNil(); int Idx = A[0]->ToString().indexOf(A[1]->ToString(), A.size()>2 ? static_cast<int>(A[2]->NumberVal)-1 : 0); if (Idx<0) return ScriptValue::MakeNil(); auto R = ScriptValue::MakeTable(); R->TableVal->Append(ScriptValue::MakeNumber(Idx+1)); R->TableVal->Append(ScriptValue::MakeNumber(Idx+A[1]->ToString().length())); return R; }));
    Interp->RegisterGlobal("string", SL);

    auto ML = ScriptValue::MakeTable();
    ML->TableVal->Set("pi", ScriptValue::MakeNumber(3.14159265358979323846));
    ML->TableVal->Set("huge", ScriptValue::MakeNumber(std::numeric_limits<double>::infinity()));
    auto MF1 = [](double(*F)(double)) { return ScriptValue::MakeNativeFunction([F](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { return ScriptValue::MakeNumber(A.isEmpty() ? 0 : F(A[0]->NumberVal)); }); };
    ML->TableVal->Set("abs", MF1(std::abs)); ML->TableVal->Set("floor", MF1(std::floor)); ML->TableVal->Set("ceil", MF1(std::ceil));
    ML->TableVal->Set("sqrt", MF1(std::sqrt)); ML->TableVal->Set("sin", MF1(std::sin)); ML->TableVal->Set("cos", MF1(std::cos));
    ML->TableVal->Set("tan", MF1(std::tan)); ML->TableVal->Set("asin", MF1(std::asin)); ML->TableVal->Set("acos", MF1(std::acos));
    ML->TableVal->Set("atan", MF1(std::atan)); ML->TableVal->Set("exp", MF1(std::exp)); ML->TableVal->Set("log", MF1(std::log));
    ML->TableVal->Set("max", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty()) return ScriptValue::MakeNil(); double M = A[0]->NumberVal; for (int I=1; I<A.size(); ++I) M = std::max(M, A[I]->NumberVal); return ScriptValue::MakeNumber(M); }));
    ML->TableVal->Set("min", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty()) return ScriptValue::MakeNil(); double M = A[0]->NumberVal; for (int I=1; I<A.size(); ++I) M = std::min(M, A[I]->NumberVal); return ScriptValue::MakeNumber(M); }));
    ML->TableVal->Set("random", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { static std::mt19937 R(static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count())); if (A.isEmpty()) { std::uniform_real_distribution<double> D(0,1); return ScriptValue::MakeNumber(D(R)); } if (A.size()==1) { std::uniform_int_distribution<int> D(1, static_cast<int>(A[0]->NumberVal)); return ScriptValue::MakeNumber(D(R)); } std::uniform_int_distribution<int> D(static_cast<int>(A[0]->NumberVal), static_cast<int>(A[1]->NumberVal)); return ScriptValue::MakeNumber(D(R)); }));
    Interp->RegisterGlobal("math", ML);

    auto TL = ScriptValue::MakeTable();
    TL->TableVal->Set("insert", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty() || A[0]->Type != ScriptType::Table) return ScriptValue::MakeNil(); if (A.size()==2) A[0]->TableVal->Append(A[1]); else if (A.size()>=3) { int P = static_cast<int>(A[1]->NumberVal)-1; if (P>=0 && P<=A[0]->TableVal->Array.size()) A[0]->TableVal->Array.insert(P, A[2]); } return ScriptValue::MakeNil(); }));
    TL->TableVal->Set("remove", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty() || A[0]->Type != ScriptType::Table) return ScriptValue::MakeNil(); int P = A.size()>1 ? static_cast<int>(A[1]->NumberVal)-1 : A[0]->TableVal->Array.size()-1; if (P>=0 && P<A[0]->TableVal->Array.size()) { auto V = A[0]->TableVal->Array[P]; A[0]->TableVal->Array.removeAt(P); return V; } return ScriptValue::MakeNil(); }));
    TL->TableVal->Set("concat", ScriptValue::MakeNativeFunction([](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty() || A[0]->Type != ScriptType::Table) return ScriptValue::MakeString(""); QString Sep = A.size()>1 ? A[1]->ToString() : ""; QStringList P; for (int I=0; I<A[0]->TableVal->Length(); ++I) P.append(A[0]->TableVal->Get(I+1)->ToString()); return ScriptValue::MakeString(P.join(Sep)); }));
    TL->TableVal->Set("sort", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (A.isEmpty() || A[0]->Type != ScriptType::Table) return ScriptValue::MakeNil(); if (A.size()>1 && (A[1]->Type==ScriptType::Function || A[1]->Type==ScriptType::NativeFunction)) { auto C = A[1]; std::sort(A[0]->TableVal->Array.begin(), A[0]->TableVal->Array.end(), [this,&C](const ScriptValuePtr& X, const ScriptValuePtr& Y) { return Interp->CallFunction(C, {X,Y}, Interp->GlobalEnv)->IsTruthy(); }); } else { std::sort(A[0]->TableVal->Array.begin(), A[0]->TableVal->Array.end(), [](const ScriptValuePtr& X, const ScriptValuePtr& Y) { if (X->Type==ScriptType::Number && Y->Type==ScriptType::Number) return X->NumberVal < Y->NumberVal; return X->ToString() < Y->ToString(); }); } return ScriptValue::MakeNil(); }));
    Interp->RegisterGlobal("table", TL);
}

void ScriptEngine::RegisterFidraApi() {
    auto AT = ScriptValue::MakeTable();
    AT->TableVal->Set("read_u8", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached() || A.isEmpty()) return ScriptValue::MakeNumber(0); uint8_t V=0; CoreRef->ReadMemory(static_cast<Address>(A[0]->NumberVal), &V, 1); return ScriptValue::MakeNumber(V); }));
    AT->TableVal->Set("read_u16", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached() || A.isEmpty()) return ScriptValue::MakeNumber(0); uint16_t V=0; CoreRef->ReadMemory(static_cast<Address>(A[0]->NumberVal), &V, 2); return ScriptValue::MakeNumber(V); }));
    AT->TableVal->Set("read_u32", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached() || A.isEmpty()) return ScriptValue::MakeNumber(0); uint32_t V=0; CoreRef->ReadMemory(static_cast<Address>(A[0]->NumberVal), &V, 4); return ScriptValue::MakeNumber(V); }));
    AT->TableVal->Set("read_u64", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached() || A.isEmpty()) return ScriptValue::MakeNumber(0); uint64_t V=0; CoreRef->ReadMemory(static_cast<Address>(A[0]->NumberVal), &V, 8); return ScriptValue::MakeNumber(static_cast<double>(V)); }));
    AT->TableVal->Set("read_float", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached() || A.isEmpty()) return ScriptValue::MakeNumber(0); float V=0; CoreRef->ReadMemory(static_cast<Address>(A[0]->NumberVal), &V, sizeof(float)); return ScriptValue::MakeNumber(V); }));
    AT->TableVal->Set("read_double", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached() || A.isEmpty()) return ScriptValue::MakeNumber(0); double V=0; CoreRef->ReadMemory(static_cast<Address>(A[0]->NumberVal), &V, sizeof(double)); return ScriptValue::MakeNumber(V); }));
    AT->TableVal->Set("read_string", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached() || A.isEmpty()) return ScriptValue::MakeString(""); Address Ad = static_cast<Address>(A[0]->NumberVal); int ML = A.size()>1 ? static_cast<int>(A[1]->NumberVal) : 256; QByteArray B(ML,0); CoreRef->ReadMemory(Ad, B.data(), ML); int L=0; while (L<ML && B[L]!=0) ++L; return ScriptValue::MakeString(QString::fromUtf8(B.data(), L)); }));
    AT->TableVal->Set("read_bytes", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached() || A.size()<2) return ScriptValue::MakeNil(); int Sz = static_cast<int>(A[1]->NumberVal); QByteArray B(Sz,0); if (!CoreRef->ReadMemory(static_cast<Address>(A[0]->NumberVal), B.data(), Sz)) return ScriptValue::MakeNil(); auto T = ScriptValue::MakeTable(); for (int I=0; I<Sz; ++I) T->TableVal->Append(ScriptValue::MakeNumber(static_cast<uint8_t>(B[I]))); return T; }));
    AT->TableVal->Set("write_u8", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached() || A.size()<2) return ScriptValue::MakeBool(false); uint8_t V = static_cast<uint8_t>(A[1]->NumberVal); return ScriptValue::MakeBool(CoreRef->WriteMemory(static_cast<Address>(A[0]->NumberVal), &V, 1)); }));
    AT->TableVal->Set("write_u16", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached() || A.size()<2) return ScriptValue::MakeBool(false); uint16_t V = static_cast<uint16_t>(A[1]->NumberVal); return ScriptValue::MakeBool(CoreRef->WriteMemory(static_cast<Address>(A[0]->NumberVal), &V, 2)); }));
    AT->TableVal->Set("write_u32", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached() || A.size()<2) return ScriptValue::MakeBool(false); uint32_t V = static_cast<uint32_t>(A[1]->NumberVal); return ScriptValue::MakeBool(CoreRef->WriteMemory(static_cast<Address>(A[0]->NumberVal), &V, 4)); }));
    AT->TableVal->Set("write_u64", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached() || A.size()<2) return ScriptValue::MakeBool(false); uint64_t V = static_cast<uint64_t>(A[1]->NumberVal); return ScriptValue::MakeBool(CoreRef->WriteMemory(static_cast<Address>(A[0]->NumberVal), &V, 8)); }));
    AT->TableVal->Set("write_float", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached() || A.size()<2) return ScriptValue::MakeBool(false); float V = static_cast<float>(A[1]->NumberVal); return ScriptValue::MakeBool(CoreRef->WriteMemory(static_cast<Address>(A[0]->NumberVal), &V, sizeof(float))); }));
    AT->TableVal->Set("write_bytes", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached() || A.size()<2 || A[1]->Type!=ScriptType::Table) return ScriptValue::MakeBool(false); QByteArray B; for (int I=0; I<A[1]->TableVal->Length(); ++I) B.append(static_cast<char>(static_cast<uint8_t>(A[1]->TableVal->Get(I+1)->NumberVal))); return ScriptValue::MakeBool(CoreRef->WriteMemory(static_cast<Address>(A[0]->NumberVal), B.data(), B.size())); }));
    AT->TableVal->Set("is_attached", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>&) -> ScriptValuePtr { return ScriptValue::MakeBool(CoreRef && CoreRef->IsAttached()); }));
    AT->TableVal->Set("process_name", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>&) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached()) return ScriptValue::MakeString(""); return ScriptValue::MakeString(CoreRef->CurrentProcess().Name); }));
    AT->TableVal->Set("process_pid", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>&) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached()) return ScriptValue::MakeNumber(0); return ScriptValue::MakeNumber(CoreRef->CurrentProcess().Pid); }));
    AT->TableVal->Set("log", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (CoreRef && !A.isEmpty()) CoreRef->Log(A[0]->ToString()); return ScriptValue::MakeNil(); }));
    AT->TableVal->Set("regions", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>&) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached()) return ScriptValue::MakeNil(); auto Rs = CoreRef->GetMemoryRegions(); auto T = ScriptValue::MakeTable(); for (const auto& R : Rs) { auto E = ScriptValue::MakeTable(); E->TableVal->Set("base", ScriptValue::MakeNumber(static_cast<double>(R.Base))); E->TableVal->Set("size", ScriptValue::MakeNumber(static_cast<double>(R.Size))); E->TableVal->Set("protection", ScriptValue::MakeNumber(R.Protection)); E->TableVal->Set("module", ScriptValue::MakeString(R.ModuleName)); T->TableVal->Append(E); } return T; }));
    AT->TableVal->Set("modules", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>&) -> ScriptValuePtr { if (!CoreRef || !CoreRef->IsAttached()) return ScriptValue::MakeNil(); auto Rs = CoreRef->GetMemoryRegions(); QMap<QString, QPair<Address,size_t>> MM; for (const auto& R : Rs) { if (!R.ModuleName.isEmpty()) { if (!MM.contains(R.ModuleName)) MM[R.ModuleName]={R.Base,R.Size}; else { auto& E=MM[R.ModuleName]; Address End=std::max(E.first+E.second, R.Base+R.Size); E.first=std::min(E.first, R.Base); E.second=End-E.first; }}} auto T = ScriptValue::MakeTable(); for (auto It=MM.begin(); It!=MM.end(); ++It) { auto E = ScriptValue::MakeTable(); E->TableVal->Set("name", ScriptValue::MakeString(It.key())); E->TableVal->Set("base", ScriptValue::MakeNumber(static_cast<double>(It.value().first))); E->TableVal->Set("size", ScriptValue::MakeNumber(static_cast<double>(It.value().second))); T->TableVal->Append(E); } return T; }));
    AT->TableVal->Set("functions", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>&) -> ScriptValuePtr { if (!DbRef) return ScriptValue::MakeNil(); auto Fs = DbRef->GetAllFunctions(); auto T = ScriptValue::MakeTable(); for (const auto& F : Fs) { auto E = ScriptValue::MakeTable(); E->TableVal->Set("name", ScriptValue::MakeString(F.Name)); E->TableVal->Set("addr", ScriptValue::MakeNumber(static_cast<double>(F.Start))); E->TableVal->Set("end_addr", ScriptValue::MakeNumber(static_cast<double>(F.End))); E->TableVal->Set("size", ScriptValue::MakeNumber(static_cast<double>(F.Size))); E->TableVal->Set("is_imported", ScriptValue::MakeBool(F.IsImported)); E->TableVal->Set("is_exported", ScriptValue::MakeBool(F.IsExported)); T->TableVal->Append(E); } return T; }));
    AT->TableVal->Set("strings", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>&) -> ScriptValuePtr { if (!DbRef) return ScriptValue::MakeNil(); auto Ss = DbRef->GetAllStrings(); auto T = ScriptValue::MakeTable(); for (const auto& S : Ss) { auto E = ScriptValue::MakeTable(); E->TableVal->Set("addr", ScriptValue::MakeNumber(static_cast<double>(S.Addr))); E->TableVal->Set("value", ScriptValue::MakeString(S.Value)); E->TableVal->Set("is_wide", ScriptValue::MakeBool(S.IsWide)); E->TableVal->Set("length", ScriptValue::MakeNumber(S.Length)); T->TableVal->Append(E); } return T; }));
    AT->TableVal->Set("xrefs_to", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!DbRef || A.isEmpty()) return ScriptValue::MakeNil(); auto Xs = DbRef->GetXrefsTo(static_cast<Address>(A[0]->NumberVal)); auto T = ScriptValue::MakeTable(); for (const auto& X : Xs) { auto E = ScriptValue::MakeTable(); E->TableVal->Set("from", ScriptValue::MakeNumber(static_cast<double>(X.From))); E->TableVal->Set("to", ScriptValue::MakeNumber(static_cast<double>(X.To))); E->TableVal->Set("type", ScriptValue::MakeNumber(static_cast<int>(X.Type))); T->TableVal->Append(E); } return T; }));
    AT->TableVal->Set("xrefs_from", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!DbRef || A.isEmpty()) return ScriptValue::MakeNil(); auto Xs = DbRef->GetXrefsFrom(static_cast<Address>(A[0]->NumberVal)); auto T = ScriptValue::MakeTable(); for (const auto& X : Xs) { auto E = ScriptValue::MakeTable(); E->TableVal->Set("from", ScriptValue::MakeNumber(static_cast<double>(X.From))); E->TableVal->Set("to", ScriptValue::MakeNumber(static_cast<double>(X.To))); E->TableVal->Set("type", ScriptValue::MakeNumber(static_cast<int>(X.Type))); T->TableVal->Append(E); } return T; }));
    AT->TableVal->Set("disasm", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!DbRef || A.isEmpty()) return ScriptValue::MakeNil(); Address Ad = static_cast<Address>(A[0]->NumberVal); int Ct = A.size()>1 ? static_cast<int>(A[1]->NumberVal) : 10; auto T = ScriptValue::MakeTable(); for (int I=0; I<Ct; ++I) { if (!DbRef->HasInstruction(Ad)) break; auto In = DbRef->GetInstruction(Ad); auto E = ScriptValue::MakeTable(); E->TableVal->Set("addr", ScriptValue::MakeNumber(static_cast<double>(In.Addr))); E->TableVal->Set("mnemonic", ScriptValue::MakeString(In.Mnemonic)); E->TableVal->Set("operands", ScriptValue::MakeString(In.Operands)); E->TableVal->Set("size", ScriptValue::MakeNumber(In.Size)); E->TableVal->Set("is_call", ScriptValue::MakeBool(In.IsCall)); E->TableVal->Set("is_jump", ScriptValue::MakeBool(In.IsJump)); E->TableVal->Set("is_ret", ScriptValue::MakeBool(In.IsRet)); T->TableVal->Append(E); Ad += In.Size; } return T; }));
    AT->TableVal->Set("scan_pattern", ScriptValue::MakeNativeFunction([this](const QVector<ScriptValuePtr>& A) -> ScriptValuePtr { if (!DbRef || A.isEmpty() || A[0]->Type != ScriptType::String) return ScriptValue::MakeNil(); QStringList Ps = A[0]->StringVal.split(' ', Qt::SkipEmptyParts); QVector<int> Pat; for (const auto& P : Ps) { if (P=="?" || P=="??") Pat.append(-1); else { bool Ok; Pat.append(P.toInt(&Ok,16)); if (!Ok) Pat.last()=-1; } } if (Pat.isEmpty()) return ScriptValue::MakeNil(); auto Info = DbRef->GetBinaryInfo(); auto T = ScriptValue::MakeTable(); for (const auto& Seg : Info.Segments) { if (!Seg.IsExecutable || Seg.Data.isEmpty()) continue; const uint8_t* D = reinterpret_cast<const uint8_t*>(Seg.Data.constData()); int DS = Seg.Data.size(); for (int I=0; I<=DS-Pat.size(); ++I) { bool M=true; for (int J=0; J<Pat.size(); ++J) { if (Pat[J]!=-1 && D[I+J]!=static_cast<uint8_t>(Pat[J])) { M=false; break; } } if (M) T->TableVal->Append(ScriptValue::MakeNumber(static_cast<double>(Seg.VirtualAddress+I))); } } return T; }));
    Interp->RegisterGlobal("fidra", AT);
}

}
