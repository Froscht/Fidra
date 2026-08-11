#pragma once

#include <fidra/Types.h>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QAtomicInt>
#include <QMap>
#include <QVector>
#include <functional>
#include <memory>
#include <variant>
#include <optional>
#include <cmath>

namespace Fidra {

class ICore;
class AnalysisDatabase;

enum class TokenType {
    Number, String, Identifier,
    Plus, Minus, Star, Slash, Percent, Caret, Hash,
    EqEq, TildeEq, Lt, Gt, LtEq, GtEq,
    Eq, LParen, RParen, LBracket, RBracket, LBrace, RBrace,
    Comma, Semicolon, Dot, DotDot, Colon,
    KwFunction, KwEnd, KwIf, KwThen, KwElse, KwElseIf,
    KwWhile, KwDo, KwFor, KwIn, KwReturn, KwLocal,
    KwNil, KwTrue, KwFalse, KwAnd, KwOr, KwNot,
    KwBreak, KwRepeat, KwUntil, KwPrint,
    Eof, Error
};

struct Token {
    TokenType Type;
    QString Value;
    int Line;
    int Col;
};

class Lexer {
public:
    explicit Lexer(const QString& Source);
    Token Next();
    Token Peek();
private:
    QString Src;
    int Pos, Line, Col;
    std::optional<Token> Buffered;
    QChar Current() const;
    QChar Advance();
    bool AtEnd() const;
    Token MakeToken(TokenType Type, const QString& Value);
    void SkipWhitespace();
    void SkipComment();
    Token ReadNumber();
    Token ReadString(QChar Quote);
    Token ReadLongString();
    Token ReadIdentifier();
};

enum class NodeType {
    NumberLiteral, StringLiteral, BoolLiteral, NilLiteral, Identifier,
    BinaryOp, UnaryOp, Assignment, LocalDecl, FunctionDef,
    FunctionCall, MethodCall, IfStatement, WhileLoop,
    NumericFor, GenericFor, RepeatUntil, Block, Return, Break,
    TableConstructor, IndexAccess, FieldAccess
};

struct AstNode;
using AstPtr = std::shared_ptr<AstNode>;

struct AstNode {
    NodeType Type;
    int Line;
    QString Name, Op, StrVal;
    double NumVal;
    bool BoolVal;
    AstPtr Left, Right, Condition, Body, ElseBranch, Step, Object;
    QVector<AstPtr> Children, Args;
    QVector<QString> Params;
    QVector<QPair<AstPtr, AstPtr>> Fields;
};

AstPtr MakeNode(NodeType Type, int Line);

class Parser {
public:
    explicit Parser(Lexer& Lex);
    AstPtr ParseBlock();
    Lexer& Lex;
    bool HadError;
    QString ErrorMsg;
private:
    Token Cur;
    Token Expect(TokenType Type, const QString& What);
    bool Check(TokenType Type) const;
    Token Consume();
    void Error(const QString& Msg);
    AstPtr ParseStatement();
    AstPtr ParseIfStatement();
    AstPtr ParseWhileLoop();
    AstPtr ParseForLoop();
    AstPtr ParseRepeatUntil();
    AstPtr ParseFunctionDef(bool IsLocal);
    AstPtr ParseFunctionBody(int Line);
    AstPtr ParseReturn();
    AstPtr ParseLocalDecl();
    AstPtr ParseExpressionStatement();
    AstPtr ParseExpression();
    AstPtr ParseOrExpr();
    AstPtr ParseAndExpr();
    AstPtr ParseCompareExpr();
    AstPtr ParseConcatExpr();
    AstPtr ParseAddExpr();
    AstPtr ParseMulExpr();
    AstPtr ParseUnaryExpr();
    AstPtr ParsePowerExpr();
    AstPtr ParsePostfixExpr();
    AstPtr ParsePrimaryExpr();
    AstPtr ParseTableConstructor();
};

enum class ScriptType { Nil, Bool, Number, String, Table, Function, NativeFunction };

struct ScriptValue;
struct ScriptTable;
using ScriptValuePtr = std::shared_ptr<ScriptValue>;
using NativeFunction = std::function<ScriptValuePtr(const QVector<ScriptValuePtr>&)>;

struct ScriptFunction {
    QVector<QString> Params;
    AstPtr Body;
    QMap<QString, ScriptValuePtr> Closure;
};

struct ScriptTable {
    QVector<ScriptValuePtr> Array;
    QMap<QString, ScriptValuePtr> Map;
    ScriptValuePtr Get(const QString& Key) const;
    ScriptValuePtr Get(int Index) const;
    void Set(const QString& Key, ScriptValuePtr Val);
    void Set(int Index, ScriptValuePtr Val);
    void Append(ScriptValuePtr Val);
    int Length() const;
};

struct ScriptValue {
    ScriptType Type;
    bool BoolVal;
    double NumberVal;
    QString StringVal;
    std::shared_ptr<ScriptTable> TableVal;
    ScriptFunction FuncVal;
    NativeFunction NativeFuncVal;

    ScriptValue();
    static ScriptValuePtr MakeNil();
    static ScriptValuePtr MakeBool(bool V);
    static ScriptValuePtr MakeNumber(double V);
    static ScriptValuePtr MakeString(const QString& V);
    static ScriptValuePtr MakeTable();
    static ScriptValuePtr MakeFunction(const QVector<QString>& Params, AstPtr Body, const QMap<QString, ScriptValuePtr>& Closure);
    static ScriptValuePtr MakeNativeFunction(NativeFunction Fn);
    bool IsTruthy() const;
    QString ToString() const;
    QString TypeName() const;
};

class Environment {
public:
    explicit Environment(std::shared_ptr<Environment> Parent = nullptr);
    ScriptValuePtr Get(const QString& Name) const;
    bool Set(const QString& Name, ScriptValuePtr Value);
    void Define(const QString& Name, ScriptValuePtr Value);
    QStringList GetAllNames() const;
private:
    QMap<QString, ScriptValuePtr> Vars;
    std::shared_ptr<Environment> ParentEnv;
};

struct BreakSignal {};
struct ReturnSignal { QVector<ScriptValuePtr> Values; };

class Interpreter {
public:
    Interpreter();
    void SetOutputCallback(std::function<void(const QString&)> Cb);
    void SetErrorCallback(std::function<void(const QString&)> Cb);
    void RegisterGlobal(const QString& Name, ScriptValuePtr Value);
    void RegisterNative(const QString& Name, NativeFunction Fn);
    void Execute(AstPtr Root);
    void Cancel();
    bool WasCancelled() const;
    ScriptValuePtr CallFunction(ScriptValuePtr Fn, const QVector<ScriptValuePtr>& Args, std::shared_ptr<Environment> Env);
    QStringList GetCompletions(const QString& Prefix) const;
    std::shared_ptr<Environment> GlobalEnv;
    std::function<void(const QString&)> OutputCb;
private:
    std::function<void(const QString&)> ErrorCb;
    QAtomicInt CancelFlag;
    uint64_t InstructionCount;
    static constexpr uint64_t MaxInstructions = 100000000;
    void RuntimeError(const QString& Msg, int Line = 0);
    void ExecBlock(AstPtr Node, std::shared_ptr<Environment> Env);
    void ExecStatement(AstPtr Node, std::shared_ptr<Environment> Env);
    void ExecAssignment(AstPtr Node, std::shared_ptr<Environment> Env);
    void ExecLocalDecl(AstPtr Node, std::shared_ptr<Environment> Env);
    void ExecIf(AstPtr Node, std::shared_ptr<Environment> Env);
    void ExecWhile(AstPtr Node, std::shared_ptr<Environment> Env);
    void ExecNumericFor(AstPtr Node, std::shared_ptr<Environment> Env);
    void ExecGenericFor(AstPtr Node, std::shared_ptr<Environment> Env);
    void ExecRepeatUntil(AstPtr Node, std::shared_ptr<Environment> Env);
    void SetTarget(AstPtr Target, ScriptValuePtr Value, std::shared_ptr<Environment> Env);
    ScriptValuePtr Eval(AstPtr Node, std::shared_ptr<Environment> Env);
};

class ScriptEngine : public QObject {
    Q_OBJECT
public:
    explicit ScriptEngine(ICore* Core, QObject* Parent = nullptr);
    ~ScriptEngine() override;
    void SetAnalysisDatabase(AnalysisDatabase* Db);
    bool Execute(const QString& Code);
    bool ExecuteFile(const QString& Path);
    void Cancel();
    QString GetOutput() const;
    QString GetError() const;
    QStringList GetCompletions(const QString& Prefix) const;
signals:
    void OutputReady(const QString& Text);
    void ErrorOccurred(const QString& Error);
    void ExecutionFinished(bool Success);
private:
    void RegisterFidraApi();
    void RegisterBuiltins();
    ICore* CoreRef;
    AnalysisDatabase* DbRef;
    std::unique_ptr<Interpreter> Interp;
    QString OutputBuffer;
    QString ErrorBuffer;
};

}
