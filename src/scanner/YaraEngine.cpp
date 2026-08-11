#include "YaraEngine.h"

#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QtEndian>
#include <algorithm>
#include <cstring>

namespace Fidra {

YaraEngine::YaraEngine(QObject* Parent)
    : QObject(Parent)
{
    Cancelled.storeRelaxed(0);
}

YaraEngine::~YaraEngine() = default;

bool YaraEngine::LoadRules(const QString& FilePath)
{
    QFile File(FilePath);
    if (!File.open(QIODevice::ReadOnly | QIODevice::Text)) {
        emit RuleError(QStringLiteral("Cannot open file: ") + FilePath);
        return false;
    }
    QTextStream Stream(&File);
    QString Text = Stream.readAll();
    File.close();
    return ParseRules(Text);
}

bool YaraEngine::LoadRulesFromString(const QString& RuleText)
{
    return ParseRules(RuleText);
}

bool YaraEngine::CompileRule(const QString& RuleText, QString& Error)
{
    QVector<YaraRule> OldRules = Rules;
    Rules.clear();
    bool Result = ParseRules(RuleText);
    if (!Result) {
        Error = QStringLiteral("Failed to parse rule");
        Rules = OldRules;
        return false;
    }
    Error.clear();
    return true;
}

QString YaraEngine::StripComments(const QString& Text)
{
    QString Result;
    Result.reserve(Text.size());
    int Len = Text.size();
    int I = 0;
    while (I < Len) {
        if (I + 1 < Len && Text[I] == '/' && Text[I + 1] == '/') {
            while (I < Len && Text[I] != '\n')
                ++I;
        } else if (I + 1 < Len && Text[I] == '/' && Text[I + 1] == '*') {
            I += 2;
            while (I + 1 < Len && !(Text[I] == '*' && Text[I + 1] == '/'))
                ++I;
            if (I + 1 < Len)
                I += 2;
        } else if (Text[I] == '"') {
            Result.append(Text[I]);
            ++I;
            while (I < Len && Text[I] != '"') {
                if (Text[I] == '\\' && I + 1 < Len) {
                    Result.append(Text[I]);
                    ++I;
                }
                Result.append(Text[I]);
                ++I;
            }
            if (I < Len) {
                Result.append(Text[I]);
                ++I;
            }
        } else {
            Result.append(Text[I]);
            ++I;
        }
    }
    return Result;
}

bool YaraEngine::ParseRules(const QString& Text)
{
    QString Cleaned = StripComments(Text);
    QRegularExpression RuleRe(QStringLiteral(R"(rule\s+(\w+)\s*(?::\s*([\w\s]+?))?\s*\{)"));
    auto It = RuleRe.globalMatch(Cleaned);
    while (It.hasNext()) {
        auto Match = It.next();
        int BraceStart = Match.capturedEnd() - 1;
        int Depth = 1;
        int Pos = BraceStart + 1;
        while (Pos < Cleaned.size() && Depth > 0) {
            if (Cleaned[Pos] == '{')
                ++Depth;
            else if (Cleaned[Pos] == '}')
                --Depth;
            ++Pos;
        }
        if (Depth != 0) {
            emit RuleError(QStringLiteral("Unmatched brace in rule: ") + Match.captured(1));
            return false;
        }
        QString FullRule = Cleaned.mid(Match.capturedStart(), Pos - Match.capturedStart());
        if (!ParseSingleRule(FullRule))
            return false;
    }
    return !Rules.isEmpty();
}

bool YaraEngine::ParseSingleRule(const QString& RuleText)
{
    YaraRule Rule;

    QRegularExpression HeaderRe(QStringLiteral(R"(rule\s+(\w+)\s*(?::\s*([\w\s]+?))?\s*\{)"));
    auto HeaderMatch = HeaderRe.match(RuleText);
    if (!HeaderMatch.hasMatch()) {
        emit RuleError(QStringLiteral("Invalid rule header"));
        return false;
    }
    Rule.Name = HeaderMatch.captured(1);
    QString TagStr = HeaderMatch.captured(2).trimmed();
    if (!TagStr.isEmpty())
        Rule.Tags = TagStr.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);

    int BodyStart = HeaderMatch.capturedEnd();
    int BodyEnd = RuleText.size() - 1;
    QString Body = RuleText.mid(BodyStart, BodyEnd - BodyStart);

    int MetaIdx = Body.indexOf(QStringLiteral("meta:"));
    int StringsIdx = Body.indexOf(QStringLiteral("strings:"));
    int CondIdx = Body.indexOf(QStringLiteral("condition:"));

    if (MetaIdx >= 0) {
        int MetaEnd = StringsIdx >= 0 ? StringsIdx : (CondIdx >= 0 ? CondIdx : Body.size());
        QString MetaSection = Body.mid(MetaIdx + 5, MetaEnd - MetaIdx - 5);
        QRegularExpression MetaRe(QStringLiteral(R"((\w+)\s*=\s*\"([^\"]*)\")"));
        auto MetaIt = MetaRe.globalMatch(MetaSection);
        while (MetaIt.hasNext()) {
            auto M = MetaIt.next();
            Rule.Meta[M.captured(1)] = M.captured(2);
        }
    }

    if (StringsIdx >= 0) {
        int StrEnd = CondIdx >= 0 ? CondIdx : Body.size();
        QString StringsSection = Body.mid(StringsIdx + 8, StrEnd - StringsIdx - 8);

        QRegularExpression HexStrRe(QStringLiteral(R"((\$\w+)\s*=\s*\{([^}]*)\})"));
        auto HexIt = HexStrRe.globalMatch(StringsSection);
        while (HexIt.hasNext()) {
            auto M = HexIt.next();
            YaraString Parsed = ParseHexString(M.captured(1), M.captured(2));
            Rule.Strings.append(Parsed);
        }

        QRegularExpression TextStrRe(QStringLiteral(R"((\$\w+)\s*=\s*\"([^\"]*)\"\s*((?:\b(?:ascii|wide|nocase|fullword)\b\s*)*))"));
        auto TextIt = TextStrRe.globalMatch(StringsSection);
        while (TextIt.hasNext()) {
            auto M = TextIt.next();
            YaraString Parsed = ParseTextString(M.captured(1), M.captured(2), M.captured(3));
            Rule.Strings.append(Parsed);
        }
    }

    if (CondIdx >= 0) {
        Rule.Condition = Body.mid(CondIdx + 10).trimmed();
        if (Rule.Condition.endsWith('}'))
            Rule.Condition.chop(1);
        Rule.Condition = Rule.Condition.trimmed();
    } else {
        Rule.Condition = QStringLiteral("all of them");
    }

    Rules.append(Rule);
    return true;
}

YaraString YaraEngine::ParseHexString(const QString& Identifier, const QString& HexBody)
{
    YaraString Str;
    Str.Identifier = Identifier;
    Str.IsHex = true;
    Str.IsText = false;
    Str.CaseInsensitive = false;
    Str.Wide = false;
    Str.Ascii = true;
    Str.Nocase = false;
    Str.Fullword = false;

    QString Trimmed = HexBody.trimmed();
    QStringList Tokens = Trimmed.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);

    for (int I = 0; I < Tokens.size(); ++I) {
        QString Token = Tokens[I];

        if (Token == QStringLiteral("??")) {
            Str.Pattern.append(static_cast<char>(0x00));
            Str.Mask.append(false);
        } else if (Token.startsWith('[') && Token.endsWith(']')) {
            QString GapSpec = Token.mid(1, Token.size() - 2);
            int MinGap = 0;
            int MaxGap = 0;
            if (GapSpec.contains('-')) {
                QStringList Parts = GapSpec.split('-');
                MinGap = Parts[0].toInt();
                MaxGap = Parts[1].toInt();
            } else {
                MinGap = MaxGap = GapSpec.toInt();
            }
            Str.GapPositions.append(Str.Pattern.size());
            Str.Gaps.append(qMakePair(MinGap, MaxGap));
            for (int G = 0; G < MinGap; ++G) {
                Str.Pattern.append(static_cast<char>(0x00));
                Str.Mask.append(false);
            }
        } else if (Token.size() == 2) {
            bool Ok = false;
            uint8_t Byte = static_cast<uint8_t>(Token.toUInt(&Ok, 16));
            if (Ok) {
                Str.Pattern.append(static_cast<char>(Byte));
                Str.Mask.append(true);
            } else {
                Str.Pattern.append(static_cast<char>(0x00));
                Str.Mask.append(false);
            }
        } else if (Token.size() == 1) {
            if (Token == QStringLiteral("?")) {
                Str.Pattern.append(static_cast<char>(0x00));
                Str.Mask.append(false);
            } else {
                bool Ok = false;
                uint8_t Byte = static_cast<uint8_t>(Token.toUInt(&Ok, 16));
                if (Ok) {
                    Str.Pattern.append(static_cast<char>(Byte));
                    Str.Mask.append(true);
                }
            }
        }
    }

    return Str;
}

YaraString YaraEngine::ParseTextString(const QString& Identifier, const QString& TextBody, const QString& Modifiers)
{
    YaraString Str;
    Str.Identifier = Identifier;
    Str.IsHex = false;
    Str.IsText = true;
    Str.CaseInsensitive = false;
    Str.Wide = false;
    Str.Ascii = true;
    Str.Nocase = false;
    Str.Fullword = false;

    QString ModLower = Modifiers.toLower().trimmed();
    if (ModLower.contains(QStringLiteral("wide")))
        Str.Wide = true;
    if (ModLower.contains(QStringLiteral("ascii")))
        Str.Ascii = true;
    if (ModLower.contains(QStringLiteral("nocase"))) {
        Str.Nocase = true;
        Str.CaseInsensitive = true;
    }
    if (ModLower.contains(QStringLiteral("fullword")))
        Str.Fullword = true;

    if (Str.Wide) {
        QByteArray Utf8 = TextBody.toUtf8();
        for (int I = 0; I < Utf8.size(); ++I) {
            Str.Pattern.append(Utf8[I]);
            Str.Mask.append(true);
            Str.Pattern.append(static_cast<char>(0x00));
            Str.Mask.append(true);
        }
    } else {
        QByteArray Utf8 = TextBody.toUtf8();
        for (int I = 0; I < Utf8.size(); ++I) {
            Str.Pattern.append(Utf8[I]);
            Str.Mask.append(true);
        }
    }

    return Str;
}

QVector<Address> YaraEngine::BoyerMooreHorspoolSearch(const QByteArray& Data, const QByteArray& Pattern, const QVector<bool>& Mask, bool CaseInsensitive)
{
    QVector<Address> Hits;
    int DataLen = Data.size();
    int PatLen = Pattern.size();

    if (PatLen == 0 || DataLen < PatLen)
        return Hits;

    int BadChar[256];
    for (int I = 0; I < 256; ++I)
        BadChar[I] = PatLen;

    bool HasNonWildcardSuffix = false;
    for (int I = PatLen - 1; I >= 0; --I) {
        if (Mask[I]) {
            HasNonWildcardSuffix = true;
            break;
        }
    }

    for (int I = 0; I < PatLen - 1; ++I) {
        if (Mask[I]) {
            uint8_t Byte = static_cast<uint8_t>(Pattern[I]);
            int Shift = PatLen - 1 - I;
            if (CaseInsensitive) {
                uint8_t Lower = static_cast<uint8_t>(std::tolower(Byte));
                uint8_t Upper = static_cast<uint8_t>(std::toupper(Byte));
                if (BadChar[Lower] > Shift)
                    BadChar[Lower] = Shift;
                if (BadChar[Upper] > Shift)
                    BadChar[Upper] = Shift;
            } else {
                if (BadChar[Byte] > Shift)
                    BadChar[Byte] = Shift;
            }
        } else {
            int Shift = PatLen - 1 - I;
            for (int J = 0; J < 256; ++J) {
                if (BadChar[J] > Shift)
                    BadChar[J] = Shift;
            }
        }
    }

    if (!HasNonWildcardSuffix) {
        for (int I = 0; I <= DataLen - PatLen; ++I) {
            bool Match = true;
            for (int J = 0; J < PatLen; ++J) {
                if (Mask[J]) {
                    uint8_t D = static_cast<uint8_t>(Data[I + J]);
                    uint8_t P = static_cast<uint8_t>(Pattern[J]);
                    if (CaseInsensitive) {
                        if (std::tolower(D) != std::tolower(P)) {
                            Match = false;
                            break;
                        }
                    } else {
                        if (D != P) {
                            Match = false;
                            break;
                        }
                    }
                }
            }
            if (Match)
                Hits.append(static_cast<Address>(I));
        }
        return Hits;
    }

    int I = 0;
    while (I <= DataLen - PatLen) {
        int J = PatLen - 1;
        while (J >= 0) {
            if (Mask[J]) {
                uint8_t D = static_cast<uint8_t>(Data[I + J]);
                uint8_t P = static_cast<uint8_t>(Pattern[J]);
                if (CaseInsensitive) {
                    if (std::tolower(D) != std::tolower(P))
                        break;
                } else {
                    if (D != P)
                        break;
                }
            }
            --J;
        }
        if (J < 0) {
            Hits.append(static_cast<Address>(I));
            I += 1;
        } else {
            uint8_t DataByte = static_cast<uint8_t>(Data[I + PatLen - 1]);
            I += BadChar[DataByte];
        }
    }

    return Hits;
}

QVector<Address> YaraEngine::SearchWithGaps(const QByteArray& Data, const YaraString& Str)
{
    if (Str.Gaps.isEmpty())
        return BoyerMooreHorspoolSearch(Data, Str.Pattern, Str.Mask, Str.CaseInsensitive);

    QVector<QByteArray> Segments;
    QVector<QVector<bool>> SegmentMasks;
    QVector<QPair<int, int>> SegmentGaps;

    int PrevEnd = 0;
    for (int I = 0; I < Str.GapPositions.size(); ++I) {
        int GapPos = Str.GapPositions[I];
        int MinGap = Str.Gaps[I].first;

        Segments.append(Str.Pattern.mid(PrevEnd, GapPos - PrevEnd));
        SegmentMasks.append(Str.Mask.mid(PrevEnd, GapPos - PrevEnd));
        SegmentGaps.append(Str.Gaps[I]);

        PrevEnd = GapPos + MinGap;
    }
    Segments.append(Str.Pattern.mid(PrevEnd));
    SegmentMasks.append(Str.Mask.mid(PrevEnd));

    if (Segments[0].isEmpty())
        return {};

    QVector<Address> FirstHits = BoyerMooreHorspoolSearch(Data, Segments[0], SegmentMasks[0], Str.CaseInsensitive);
    QVector<Address> Results;

    for (Address Start : FirstHits) {
        bool Valid = true;
        Address CurrentPos = Start + static_cast<Address>(Segments[0].size());

        for (int S = 1; S < Segments.size() && Valid; ++S) {
            int MinGap = SegmentGaps[S - 1].first;
            int MaxGap = SegmentGaps[S - 1].second;
            bool FoundSeg = false;

            for (int Gap = MinGap; Gap <= MaxGap && !FoundSeg; ++Gap) {
                Address TryPos = CurrentPos + static_cast<Address>(Gap);
                if (TryPos + static_cast<Address>(Segments[S].size()) > static_cast<Address>(Data.size()))
                    break;

                bool SegMatch = true;
                for (int B = 0; B < Segments[S].size(); ++B) {
                    if (SegmentMasks[S][B]) {
                        uint8_t D = static_cast<uint8_t>(Data[static_cast<int>(TryPos) + B]);
                        uint8_t P = static_cast<uint8_t>(Segments[S][B]);
                        if (Str.CaseInsensitive) {
                            if (std::tolower(D) != std::tolower(P)) {
                                SegMatch = false;
                                break;
                            }
                        } else {
                            if (D != P) {
                                SegMatch = false;
                                break;
                            }
                        }
                    }
                }
                if (SegMatch) {
                    CurrentPos = TryPos + static_cast<Address>(Segments[S].size());
                    FoundSeg = true;
                }
            }
            if (!FoundSeg)
                Valid = false;
        }
        if (Valid)
            Results.append(Start);
    }

    return Results;
}

QVector<YaraEngine::StringMatchResult> YaraEngine::MatchString(const YaraString& Str, const QByteArray& Data, Address BaseAddress)
{
    QVector<StringMatchResult> Results;

    QVector<Address> Hits = SearchWithGaps(Data, Str);

    for (Address Offset : Hits) {
        if (Str.Fullword && Str.IsText) {
            if (Offset > 0) {
                uint8_t Before = static_cast<uint8_t>(Data[static_cast<int>(Offset) - 1]);
                if (std::isalnum(Before) || Before == '_')
                    continue;
            }
            Address EndPos = Offset + static_cast<Address>(Str.Pattern.size());
            if (EndPos < static_cast<Address>(Data.size())) {
                uint8_t After = static_cast<uint8_t>(Data[static_cast<int>(EndPos)]);
                if (std::isalnum(After) || After == '_')
                    continue;
            }
        }

        StringMatchResult Res;
        Res.Offset = BaseAddress + Offset;
        Res.Identifier = Str.Identifier;
        Results.append(Res);
    }

    if (Str.IsText && Str.Wide && Str.Ascii) {
        YaraString AsciiCopy;
        AsciiCopy.Identifier = Str.Identifier;
        AsciiCopy.IsHex = false;
        AsciiCopy.IsText = true;
        AsciiCopy.CaseInsensitive = Str.CaseInsensitive;
        AsciiCopy.Wide = false;
        AsciiCopy.Ascii = true;
        AsciiCopy.Nocase = Str.Nocase;
        AsciiCopy.Fullword = Str.Fullword;

        QByteArray AsciiPattern;
        QVector<bool> AsciiMask;
        for (int I = 0; I < Str.Pattern.size(); I += 2) {
            AsciiPattern.append(Str.Pattern[I]);
            AsciiMask.append(Str.Mask[I]);
        }
        AsciiCopy.Pattern = AsciiPattern;
        AsciiCopy.Mask = AsciiMask;

        QVector<Address> AsciiHits = BoyerMooreHorspoolSearch(Data, AsciiPattern, AsciiMask, Str.CaseInsensitive);
        for (Address Offset : AsciiHits) {
            if (Str.Fullword) {
                if (Offset > 0) {
                    uint8_t Before = static_cast<uint8_t>(Data[static_cast<int>(Offset) - 1]);
                    if (std::isalnum(Before) || Before == '_')
                        continue;
                }
                Address EndPos = Offset + static_cast<Address>(AsciiPattern.size());
                if (EndPos < static_cast<Address>(Data.size())) {
                    uint8_t After = static_cast<uint8_t>(Data[static_cast<int>(EndPos)]);
                    if (std::isalnum(After) || After == '_')
                        continue;
                }
            }
            StringMatchResult Res;
            Res.Offset = BaseAddress + Offset;
            Res.Identifier = Str.Identifier;
            Results.append(Res);
        }
    }

    return Results;
}

void YaraEngine::SkipWhitespace(ConditionContext& Ctx)
{
    while (Ctx.Pos < Ctx.Condition.size() && Ctx.Condition[Ctx.Pos].isSpace())
        ++Ctx.Pos;
}

QString YaraEngine::ReadToken(ConditionContext& Ctx)
{
    SkipWhitespace(Ctx);
    if (Ctx.Pos >= Ctx.Condition.size())
        return {};

    QChar Ch = Ctx.Condition[Ctx.Pos];

    if (Ch == '(' || Ch == ')') {
        ++Ctx.Pos;
        return QString(Ch);
    }

    if (Ch == '>' || Ch == '<' || Ch == '=' || Ch == '!') {
        QString Op;
        Op.append(Ch);
        ++Ctx.Pos;
        if (Ctx.Pos < Ctx.Condition.size()) {
            QChar Next = Ctx.Condition[Ctx.Pos];
            if (Next == '=') {
                Op.append(Next);
                ++Ctx.Pos;
            }
        }
        return Op;
    }

    if (Ch == '$' || Ch == '#') {
        QString Token;
        Token.append(Ch);
        ++Ctx.Pos;
        while (Ctx.Pos < Ctx.Condition.size() &&
               (Ctx.Condition[Ctx.Pos].isLetterOrNumber() || Ctx.Condition[Ctx.Pos] == '_')) {
            Token.append(Ctx.Condition[Ctx.Pos]);
            ++Ctx.Pos;
        }
        return Token;
    }

    if (Ch.isDigit() || (Ch == '0' && Ctx.Pos + 1 < Ctx.Condition.size() && Ctx.Condition[Ctx.Pos + 1] == 'x')) {
        QString Token;
        if (Ch == '0' && Ctx.Pos + 1 < Ctx.Condition.size() && Ctx.Condition[Ctx.Pos + 1] == 'x') {
            Token.append(Ctx.Condition[Ctx.Pos]);
            ++Ctx.Pos;
            Token.append(Ctx.Condition[Ctx.Pos]);
            ++Ctx.Pos;
            while (Ctx.Pos < Ctx.Condition.size() &&
                   (Ctx.Condition[Ctx.Pos].isDigit() ||
                    (Ctx.Condition[Ctx.Pos] >= 'a' && Ctx.Condition[Ctx.Pos] <= 'f') ||
                    (Ctx.Condition[Ctx.Pos] >= 'A' && Ctx.Condition[Ctx.Pos] <= 'F'))) {
                Token.append(Ctx.Condition[Ctx.Pos]);
                ++Ctx.Pos;
            }
        } else {
            while (Ctx.Pos < Ctx.Condition.size() && Ctx.Condition[Ctx.Pos].isDigit()) {
                Token.append(Ctx.Condition[Ctx.Pos]);
                ++Ctx.Pos;
            }
        }
        return Token;
    }

    if (Ch.isLetter() || Ch == '_') {
        QString Token;
        while (Ctx.Pos < Ctx.Condition.size() &&
               (Ctx.Condition[Ctx.Pos].isLetterOrNumber() || Ctx.Condition[Ctx.Pos] == '_')) {
            Token.append(Ctx.Condition[Ctx.Pos]);
            ++Ctx.Pos;
        }
        return Token;
    }

    ++Ctx.Pos;
    return QString(Ch);
}

QString YaraEngine::PeekToken(ConditionContext& Ctx)
{
    int SavedPos = Ctx.Pos;
    QString Token = ReadToken(Ctx);
    Ctx.Pos = SavedPos;
    return Token;
}

int64_t YaraEngine::ParseNumber(const QString& Token)
{
    if (Token.startsWith(QStringLiteral("0x")) || Token.startsWith(QStringLiteral("0X")))
        return Token.mid(2).toLongLong(nullptr, 16);
    return Token.toLongLong();
}

bool YaraEngine::EvaluateCondition(const QString& Condition, const QMap<QString, QVector<Address>>& StringHits,
                                    const QByteArray& Data, Address EntryPoint)
{
    ConditionContext Ctx;
    Ctx.StringHits = &StringHits;
    Ctx.Data = &Data;
    Ctx.EntryPoint = EntryPoint;
    Ctx.Pos = 0;
    Ctx.Condition = Condition;
    return EvalExpression(Ctx);
}

bool YaraEngine::EvalExpression(ConditionContext& Ctx)
{
    return EvalOr(Ctx);
}

bool YaraEngine::EvalOr(ConditionContext& Ctx)
{
    bool Result = EvalAnd(Ctx);
    while (true) {
        QString Token = PeekToken(Ctx);
        if (Token == QStringLiteral("or")) {
            ReadToken(Ctx);
            bool Right = EvalAnd(Ctx);
            Result = Result || Right;
        } else {
            break;
        }
    }
    return Result;
}

bool YaraEngine::EvalAnd(ConditionContext& Ctx)
{
    bool Result = EvalNot(Ctx);
    while (true) {
        QString Token = PeekToken(Ctx);
        if (Token == QStringLiteral("and")) {
            ReadToken(Ctx);
            bool Right = EvalNot(Ctx);
            Result = Result && Right;
        } else {
            break;
        }
    }
    return Result;
}

bool YaraEngine::EvalNot(ConditionContext& Ctx)
{
    QString Token = PeekToken(Ctx);
    if (Token == QStringLiteral("not")) {
        ReadToken(Ctx);
        return !EvalNot(Ctx);
    }
    return EvalPrimary(Ctx);
}

int64_t YaraEngine::EvalNumericExpression(ConditionContext& Ctx)
{
    return EvalNumericPrimary(Ctx);
}

int64_t YaraEngine::EvalNumericPrimary(ConditionContext& Ctx)
{
    SkipWhitespace(Ctx);
    QString Token = PeekToken(Ctx);

    if (Token == QStringLiteral("filesize")) {
        ReadToken(Ctx);
        return static_cast<int64_t>(Ctx.Data->size());
    }

    if (Token == QStringLiteral("entrypoint")) {
        ReadToken(Ctx);
        return static_cast<int64_t>(Ctx.EntryPoint);
    }

    if (Token == QStringLiteral("uint8")) {
        ReadToken(Ctx);
        ReadToken(Ctx);
        int64_t Offset = EvalNumericExpression(Ctx);
        ReadToken(Ctx);
        if (Offset >= 0 && Offset < Ctx.Data->size())
            return static_cast<uint8_t>((*Ctx.Data)[static_cast<int>(Offset)]);
        return 0;
    }

    if (Token == QStringLiteral("uint16")) {
        ReadToken(Ctx);
        ReadToken(Ctx);
        int64_t Offset = EvalNumericExpression(Ctx);
        ReadToken(Ctx);
        if (Offset >= 0 && Offset + 2 <= Ctx.Data->size()) {
            uint16_t Val;
            std::memcpy(&Val, Ctx.Data->constData() + Offset, 2);
            return qFromLittleEndian(Val);
        }
        return 0;
    }

    if (Token == QStringLiteral("uint32")) {
        ReadToken(Ctx);
        ReadToken(Ctx);
        int64_t Offset = EvalNumericExpression(Ctx);
        ReadToken(Ctx);
        if (Offset >= 0 && Offset + 4 <= Ctx.Data->size()) {
            uint32_t Val;
            std::memcpy(&Val, Ctx.Data->constData() + Offset, 4);
            return qFromLittleEndian(Val);
        }
        return 0;
    }

    if (Token == QStringLiteral("int8")) {
        ReadToken(Ctx);
        ReadToken(Ctx);
        int64_t Offset = EvalNumericExpression(Ctx);
        ReadToken(Ctx);
        if (Offset >= 0 && Offset < Ctx.Data->size())
            return static_cast<int8_t>((*Ctx.Data)[static_cast<int>(Offset)]);
        return 0;
    }

    if (Token == QStringLiteral("int16")) {
        ReadToken(Ctx);
        ReadToken(Ctx);
        int64_t Offset = EvalNumericExpression(Ctx);
        ReadToken(Ctx);
        if (Offset >= 0 && Offset + 2 <= Ctx.Data->size()) {
            int16_t Val;
            std::memcpy(&Val, Ctx.Data->constData() + Offset, 2);
            return qFromLittleEndian(Val);
        }
        return 0;
    }

    if (Token == QStringLiteral("int32")) {
        ReadToken(Ctx);
        ReadToken(Ctx);
        int64_t Offset = EvalNumericExpression(Ctx);
        ReadToken(Ctx);
        if (Offset >= 0 && Offset + 4 <= Ctx.Data->size()) {
            int32_t Val;
            std::memcpy(&Val, Ctx.Data->constData() + Offset, 4);
            return qFromLittleEndian(Val);
        }
        return 0;
    }

    if (Token.startsWith('#')) {
        ReadToken(Ctx);
        QString Id = Token;
        if (Ctx.StringHits->contains(Id.mid(1)))
            return Ctx.StringHits->value(Id.mid(1)).size();
        QString DollarId = QStringLiteral("$") + Id.mid(1);
        if (Ctx.StringHits->contains(DollarId))
            return Ctx.StringHits->value(DollarId).size();
        return 0;
    }

    if (Token == QStringLiteral("(")) {
        ReadToken(Ctx);
        int64_t Val = EvalNumericExpression(Ctx);
        ReadToken(Ctx);
        return Val;
    }

    if (!Token.isEmpty() && (Token[0].isDigit() || Token.startsWith(QStringLiteral("0x")))) {
        ReadToken(Ctx);
        return ParseNumber(Token);
    }

    ReadToken(Ctx);
    return 0;
}

bool YaraEngine::EvalPrimary(ConditionContext& Ctx)
{
    SkipWhitespace(Ctx);
    QString Token = PeekToken(Ctx);

    if (Token == QStringLiteral("(")) {
        ReadToken(Ctx);
        bool Result = EvalExpression(Ctx);
        ReadToken(Ctx);
        return Result;
    }

    if (Token == QStringLiteral("true")) {
        ReadToken(Ctx);
        return true;
    }
    if (Token == QStringLiteral("false")) {
        ReadToken(Ctx);
        return false;
    }

    if (Token == QStringLiteral("all")) {
        ReadToken(Ctx);
        QString OfToken = ReadToken(Ctx);
        QString ThemToken = ReadToken(Ctx);
        if (Ctx.StringHits->isEmpty())
            return false;
        for (auto It = Ctx.StringHits->begin(); It != Ctx.StringHits->end(); ++It) {
            if (It.value().isEmpty())
                return false;
        }
        return true;
    }

    if (Token == QStringLiteral("any")) {
        ReadToken(Ctx);
        QString OfToken = ReadToken(Ctx);
        QString ThemToken = ReadToken(Ctx);
        for (auto It = Ctx.StringHits->begin(); It != Ctx.StringHits->end(); ++It) {
            if (!It.value().isEmpty())
                return true;
        }
        return false;
    }

    if (Token == QStringLiteral("none")) {
        ReadToken(Ctx);
        QString OfToken = ReadToken(Ctx);
        QString ThemToken = ReadToken(Ctx);
        for (auto It = Ctx.StringHits->begin(); It != Ctx.StringHits->end(); ++It) {
            if (!It.value().isEmpty())
                return false;
        }
        return true;
    }

    if (Token.startsWith('$')) {
        ReadToken(Ctx);
        QString Id = Token;

        SkipWhitespace(Ctx);
        QString NextToken = PeekToken(Ctx);

        if (NextToken == QStringLiteral("at")) {
            ReadToken(Ctx);
            int64_t Offset = EvalNumericExpression(Ctx);
            if (Ctx.StringHits->contains(Id)) {
                const QVector<Address>& Addrs = Ctx.StringHits->value(Id);
                for (Address Addr : Addrs) {
                    if (static_cast<int64_t>(Addr) == Offset)
                        return true;
                }
            }
            return false;
        }

        return Ctx.StringHits->contains(Id) && !Ctx.StringHits->value(Id).isEmpty();
    }

    if (Token.startsWith('#')) {
        int SavedPos = Ctx.Pos;
        int64_t Left = EvalNumericExpression(Ctx);
        QString Op = ReadToken(Ctx);
        int64_t Right = EvalNumericExpression(Ctx);

        if (Op == QStringLiteral(">")) return Left > Right;
        if (Op == QStringLiteral("<")) return Left < Right;
        if (Op == QStringLiteral(">=")) return Left >= Right;
        if (Op == QStringLiteral("<=")) return Left <= Right;
        if (Op == QStringLiteral("==")) return Left == Right;
        if (Op == QStringLiteral("!=")) return Left != Right;
        return Left > 0;
    }

    if (Token == QStringLiteral("filesize") || Token == QStringLiteral("entrypoint") ||
        Token == QStringLiteral("uint8") || Token == QStringLiteral("uint16") ||
        Token == QStringLiteral("uint32") || Token == QStringLiteral("int8") ||
        Token == QStringLiteral("int16") || Token == QStringLiteral("int32")) {
        int64_t Left = EvalNumericExpression(Ctx);
        QString Op = ReadToken(Ctx);
        int64_t Right = EvalNumericExpression(Ctx);

        if (Op == QStringLiteral("==")) return Left == Right;
        if (Op == QStringLiteral("!=")) return Left != Right;
        if (Op == QStringLiteral(">")) return Left > Right;
        if (Op == QStringLiteral("<")) return Left < Right;
        if (Op == QStringLiteral(">=")) return Left >= Right;
        if (Op == QStringLiteral("<=")) return Left <= Right;
        return false;
    }

    if (!Token.isEmpty() && Token[0].isDigit()) {
        int64_t Num = EvalNumericExpression(Ctx);
        QString NextTok = PeekToken(Ctx);
        if (NextTok == QStringLiteral("of")) {
            ReadToken(Ctx);
            QString ThemToken = ReadToken(Ctx);
            int Count = 0;
            for (auto It = Ctx.StringHits->begin(); It != Ctx.StringHits->end(); ++It) {
                if (!It.value().isEmpty())
                    ++Count;
            }
            return Count >= static_cast<int>(Num);
        }
        QString Op = ReadToken(Ctx);
        int64_t Right = EvalNumericExpression(Ctx);
        if (Op == QStringLiteral("==")) return Num == Right;
        if (Op == QStringLiteral("!=")) return Num != Right;
        if (Op == QStringLiteral(">")) return Num > Right;
        if (Op == QStringLiteral("<")) return Num < Right;
        if (Op == QStringLiteral(">=")) return Num >= Right;
        if (Op == QStringLiteral("<=")) return Num <= Right;
        return false;
    }

    ReadToken(Ctx);
    return false;
}

QVector<YaraMatch> YaraEngine::ScanBuffer(const QByteArray& Data, Address BaseAddress)
{
    Cancelled.storeRelaxed(0);
    QVector<YaraMatch> AllMatches;
    int TotalRules = Rules.size();

    for (int R = 0; R < TotalRules; ++R) {
        if (Cancelled.loadRelaxed())
            break;

        const YaraRule& Rule = Rules[R];
        QMap<QString, QVector<Address>> StringHits;

        for (const YaraString& Str : Rule.Strings) {
            if (Cancelled.loadRelaxed())
                break;

            QVector<StringMatchResult> Matches = MatchString(Str, Data, BaseAddress);
            QVector<Address> Offsets;
            for (const StringMatchResult& M : Matches)
                Offsets.append(M.Offset);
            StringHits[Str.Identifier] = Offsets;
        }

        Address EntryPoint = 0;
        bool CondResult = EvaluateCondition(Rule.Condition, StringHits, Data, EntryPoint);

        if (CondResult) {
            YaraMatch Match;
            Match.RuleName = Rule.Name;
            for (auto It = StringHits.begin(); It != StringHits.end(); ++It) {
                if (!It.value().isEmpty()) {
                    Match.MatchedStrings.append(It.key());
                    for (Address Addr : It.value())
                        Match.Hits.append(qMakePair(Addr, It.key()));
                }
            }
            AllMatches.append(Match);
        }

        int Percent = ((R + 1) * 100) / TotalRules;
        emit ScanProgress(Percent);
    }

    emit ScanComplete(AllMatches.size());
    return AllMatches;
}

QVector<YaraMatch> YaraEngine::ScanDatabase(AnalysisDatabase* Db)
{
    if (!Db) {
        emit RuleError(QStringLiteral("No analysis database provided"));
        return {};
    }

    BinaryInfo Info = Db->GetBinaryInfo();
    QByteArray CombinedData;
    QVector<QPair<Address, int>> SegmentMap;

    for (const Segment& Seg : Info.Segments) {
        SegmentMap.append(qMakePair(Seg.VirtualAddress, CombinedData.size()));
        CombinedData.append(Seg.Data);
    }

    if (CombinedData.isEmpty()) {
        emit RuleError(QStringLiteral("No segment data available"));
        return {};
    }

    Cancelled.storeRelaxed(0);
    QVector<YaraMatch> AllMatches;
    int TotalRules = Rules.size();

    for (int R = 0; R < TotalRules; ++R) {
        if (Cancelled.loadRelaxed())
            break;

        const YaraRule& Rule = Rules[R];
        QMap<QString, QVector<Address>> StringHits;

        for (const YaraString& Str : Rule.Strings) {
            if (Cancelled.loadRelaxed())
                break;

            QVector<StringMatchResult> RawMatches = MatchString(Str, CombinedData, 0);
            QVector<Address> MappedAddresses;

            for (const StringMatchResult& M : RawMatches) {
                Address RawOffset = M.Offset;
                Address VirtualAddr = RawOffset;

                for (int S = SegmentMap.size() - 1; S >= 0; --S) {
                    Address SegVa = SegmentMap[S].first;
                    int SegFileOffset = SegmentMap[S].second;
                    int NextSegOffset = (S + 1 < SegmentMap.size()) ?
                        SegmentMap[S + 1].second : CombinedData.size();

                    if (static_cast<int>(RawOffset) >= SegFileOffset &&
                        static_cast<int>(RawOffset) < NextSegOffset) {
                        VirtualAddr = SegVa + (RawOffset - static_cast<Address>(SegFileOffset));
                        break;
                    }
                }
                MappedAddresses.append(VirtualAddr);
            }
            StringHits[Str.Identifier] = MappedAddresses;
        }

        bool CondResult = EvaluateCondition(Rule.Condition, StringHits, CombinedData, Info.EntryPoint);

        if (CondResult) {
            YaraMatch Match;
            Match.RuleName = Rule.Name;
            for (auto It = StringHits.begin(); It != StringHits.end(); ++It) {
                if (!It.value().isEmpty()) {
                    Match.MatchedStrings.append(It.key());
                    for (Address Addr : It.value())
                        Match.Hits.append(qMakePair(Addr, It.key()));
                }
            }
            AllMatches.append(Match);
        }

        int Percent = ((R + 1) * 100) / TotalRules;
        emit ScanProgress(Percent);
    }

    emit ScanComplete(AllMatches.size());
    return AllMatches;
}

void YaraEngine::Cancel()
{
    Cancelled.storeRelaxed(1);
}

QString YaraEngine::GenerateRule(const QString& Name, const QByteArray& HexPattern,
                                  const QMap<QString, QString>& Meta)
{
    QString Result;
    QTextStream Out(&Result);

    Out << "rule " << Name << " {\n";

    if (!Meta.isEmpty()) {
        Out << "    meta:\n";
        for (auto It = Meta.begin(); It != Meta.end(); ++It)
            Out << "        " << It.key() << " = \"" << It.value() << "\"\n";
    }

    Out << "    strings:\n";
    Out << "        $pattern = { ";

    for (int I = 0; I < HexPattern.size(); ++I) {
        if (I > 0)
            Out << " ";
        Out << QString::asprintf("%02X", static_cast<uint8_t>(HexPattern[I]));
    }

    Out << " }\n";
    Out << "    condition:\n";
    Out << "        $pattern\n";
    Out << "}\n";

    return Result;
}

QString YaraEngine::GenerateRuleFromFunction(AnalysisDatabase* Db, Address FuncAddr,
                                              const QString& RuleName)
{
    if (!Db)
        return {};

    AnalyzedFunction Func = Db->GetFunction(FuncAddr);
    if (Func.Start == 0)
        return {};

    int BytesToCapture = 32;
    if (static_cast<int>(Func.Size) < BytesToCapture)
        BytesToCapture = static_cast<int>(Func.Size);

    QByteArray FuncBytes = Db->ReadBytes(Func.Start, static_cast<size_t>(BytesToCapture));
    if (FuncBytes.isEmpty())
        return {};

    QVector<bool> MaskBytes(FuncBytes.size(), true);

    QList<AnalyzedInstruction> Instructions = Db->GetInstructions(Func.Start, Func.Start + static_cast<Address>(BytesToCapture));

    for (const AnalyzedInstruction& Inst : Instructions) {
        if (Inst.Addr < Func.Start)
            continue;
        int InsnOffset = static_cast<int>(Inst.Addr - Func.Start);
        if (InsnOffset + Inst.Size > FuncBytes.size())
            continue;

        bool HasRelativeOffset = (Inst.IsCall || Inst.IsJump) && Inst.BranchTarget != 0;

        if (HasRelativeOffset && Inst.Size >= 5) {
            int RelStart = InsnOffset + static_cast<int>(Inst.Size) - 4;
            for (int B = RelStart; B < InsnOffset + static_cast<int>(Inst.Size) && B < FuncBytes.size(); ++B)
                MaskBytes[B] = false;
        }

        if (Inst.MemoryRef != 0 && !Inst.IsCall && !Inst.IsJump && Inst.Size >= 5) {
            int RelStart = InsnOffset + static_cast<int>(Inst.Size) - 4;
            for (int B = RelStart; B < InsnOffset + static_cast<int>(Inst.Size) && B < FuncBytes.size(); ++B)
                MaskBytes[B] = false;
        }
    }

    QString HexStr;
    for (int I = 0; I < FuncBytes.size(); ++I) {
        if (I > 0)
            HexStr += ' ';
        if (MaskBytes[I])
            HexStr += QString::asprintf("%02X", static_cast<uint8_t>(FuncBytes[I]));
        else
            HexStr += QStringLiteral("??");
    }

    QMap<QString, QString> Meta;
    Meta[QStringLiteral("description")] = QStringLiteral("Auto-generated from function ") + Func.Name;
    Meta[QStringLiteral("address")] = QString::asprintf("0x%llX", static_cast<unsigned long long>(Func.Start));

    QString Result;
    QTextStream Out(&Result);
    Out << "rule " << RuleName << " {\n";
    Out << "    meta:\n";
    for (auto It = Meta.begin(); It != Meta.end(); ++It)
        Out << "        " << It.key() << " = \"" << It.value() << "\"\n";
    Out << "    strings:\n";
    Out << "        $func_bytes = { " << HexStr << " }\n";
    Out << "    condition:\n";
    Out << "        $func_bytes\n";
    Out << "}\n";

    return Result;
}

QVector<YaraRule> YaraEngine::GetLoadedRules() const
{
    return Rules;
}

int YaraEngine::RuleCount() const
{
    return Rules.size();
}

}
