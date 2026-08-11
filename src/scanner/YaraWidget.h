#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QPlainTextEdit>
#include <QTreeWidget>
#include <QPushButton>
#include <QProgressBar>
#include <QLabel>
#include <QSyntaxHighlighter>
#include <QRegularExpression>

namespace Fidra {

struct YaraMatch;
class YaraEngine;
class AnalysisDatabase;

class YaraHighlighter : public QSyntaxHighlighter {
    Q_OBJECT

public:
    explicit YaraHighlighter(QTextDocument* Parent = nullptr);

protected:
    void highlightBlock(const QString& Text) override;

private:
    struct HighlightRule {
        QRegularExpression Pattern;
        QTextCharFormat Format;
    };

    QVector<HighlightRule> Rules;
    QTextCharFormat KeywordFormat;
    QTextCharFormat HexFormat;
    QTextCharFormat StringFormat;
    QTextCharFormat CommentFormat;
    QTextCharFormat MultiLineCommentFormat;
    QRegularExpression CommentStartExpr;
    QRegularExpression CommentEndExpr;
};

class YaraWidget : public QWidget {
    Q_OBJECT

public:
    explicit YaraWidget(QWidget* Parent = nullptr);
    ~YaraWidget() override;

    void SetAnalysisDatabase(AnalysisDatabase* Db);

signals:
    void NavigateToAddress(Address Addr);

private slots:
    void OnLoadRules();
    void OnScanBinary();
    void OnScanMemory();
    void OnGenerateRule();
    void OnClear();
    void OnScanProgress(int Percent);
    void OnScanComplete(int MatchCount);
    void OnResultDoubleClicked(QTreeWidgetItem* Item, int Column);

private:
    void SetupUi();
    void PopulateResults(const QVector<YaraMatch>& Matches);
    void ShowGenerateDialog();

    AnalysisDatabase* DbRef;
    YaraEngine* Engine;

    QPlainTextEdit* RuleEditor;
    YaraHighlighter* Highlighter;
    QTreeWidget* ResultsTree;
    QPushButton* LoadRulesBtn;
    QPushButton* ScanBinaryBtn;
    QPushButton* ScanMemoryBtn;
    QPushButton* GenerateRuleBtn;
    QPushButton* ClearBtn;
    QProgressBar* Progress;
    QLabel* StatusLabel;
};

}
