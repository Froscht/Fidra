#pragma once

#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <fidra/Types.h>
#include <QObject>
#include <QVector>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QAtomicInt>
#include <QPair>

namespace Fidra {

struct YaraString {
    QString Identifier;
    QByteArray Pattern;
    QVector<bool> Mask;
    bool IsHex;
    bool IsText;
    bool CaseInsensitive;
    bool Wide;
    bool Ascii;
    bool Nocase;
    bool Fullword;
    QVector<QPair<int, int>> Gaps;
    QVector<int> GapPositions;
};

struct YaraRule {
    QString Name;
    QStringList Tags;
    QMap<QString, QString> Meta;
    QVector<YaraString> Strings;
    QString Condition;
};

struct YaraMatch {
    QString RuleName;
    QStringList MatchedStrings;
    QVector<QPair<Address, QString>> Hits;
};

class YaraEngine : public QObject {
    Q_OBJECT

public:
    explicit YaraEngine(QObject* Parent = nullptr);
    ~YaraEngine() override;

    bool LoadRules(const QString& FilePath);
    bool LoadRulesFromString(const QString& RuleText);
    bool CompileRule(const QString& RuleText, QString& Error);

    QVector<YaraMatch> ScanBuffer(const QByteArray& Data, Address BaseAddress = 0);
    QVector<YaraMatch> ScanDatabase(AnalysisDatabase* Db);

    void Cancel();

    static QString GenerateRule(const QString& Name, const QByteArray& HexPattern,
                                const QMap<QString, QString>& Meta = {});
    static QString GenerateRuleFromFunction(AnalysisDatabase* Db, Address FuncAddr,
                                            const QString& RuleName);

    QVector<YaraRule> GetLoadedRules() const;
    int RuleCount() const;

signals:
    void ScanProgress(int Percent);
    void ScanComplete(int MatchCount);
    void RuleError(const QString& Error);

private:
    struct StringMatchResult {
        Address Offset;
        QString Identifier;
    };

    bool ParseRules(const QString& Text);
    QString StripComments(const QString& Text);
    bool ParseSingleRule(const QString& RuleText);
    YaraString ParseHexString(const QString& Identifier, const QString& HexBody);
    YaraString ParseTextString(const QString& Identifier, const QString& TextBody, const QString& Modifiers);

    QVector<StringMatchResult> MatchString(const YaraString& Str, const QByteArray& Data, Address BaseAddress);
    QVector<Address> BoyerMooreHorspoolSearch(const QByteArray& Data, const QByteArray& Pattern, const QVector<bool>& Mask, bool CaseInsensitive);
    QVector<Address> SearchWithGaps(const QByteArray& Data, const YaraString& Str);

    bool EvaluateCondition(const QString& Condition, const QMap<QString, QVector<Address>>& StringHits,
                           const QByteArray& Data, Address EntryPoint);

    struct ConditionContext {
        const QMap<QString, QVector<Address>>* StringHits;
        const QByteArray* Data;
        Address EntryPoint;
        int Pos;
        QString Condition;
    };

    bool EvalExpression(ConditionContext& Ctx);
    bool EvalOr(ConditionContext& Ctx);
    bool EvalAnd(ConditionContext& Ctx);
    bool EvalNot(ConditionContext& Ctx);
    bool EvalPrimary(ConditionContext& Ctx);
    int64_t EvalNumericExpression(ConditionContext& Ctx);
    int64_t EvalNumericPrimary(ConditionContext& Ctx);
    void SkipWhitespace(ConditionContext& Ctx);
    QString ReadToken(ConditionContext& Ctx);
    QString PeekToken(ConditionContext& Ctx);
    int64_t ParseNumber(const QString& Token);

    QVector<YaraRule> Rules;
    QAtomicInt Cancelled;
};

}
