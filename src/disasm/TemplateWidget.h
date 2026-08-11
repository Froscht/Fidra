#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QPlainTextEdit>
#include <QTreeWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QSplitter>
#include <QSyntaxHighlighter>
#include <QRegularExpression>

namespace Fidra {

class AnalysisDatabase;
class TemplateEngine;
struct TemplateResult;
enum class TemplateFieldType;

class TemplateSyntaxHighlighter : public QSyntaxHighlighter {
    Q_OBJECT

public:
    explicit TemplateSyntaxHighlighter(QTextDocument* Parent = nullptr);

protected:
    void highlightBlock(const QString& Text) override;

private:
    struct HighlightRule {
        QRegularExpression Pattern;
        QTextCharFormat Format;
    };
    QVector<HighlightRule> Rules;
    QTextCharFormat KeywordFormat;
    QTextCharFormat TypeFormat;
    QTextCharFormat NumberFormat;
    QTextCharFormat StringFormat;
    QTextCharFormat CommentFormat;
    QRegularExpression CommentStartExpr;
    QRegularExpression CommentEndExpr;
};

class TemplateWidget : public QWidget {
    Q_OBJECT

public:
    explicit TemplateWidget(QWidget* Parent = nullptr);
    ~TemplateWidget() override;

    void SetAnalysisDatabase(AnalysisDatabase* Db);

signals:
    void NavigateToAddress(Address Addr);
    void HighlightBytes(Address Start, int Size, QColor Color);

private slots:
    void OnApplyTemplate();
    void OnLoadTemplate();
    void OnSaveTemplate();
    void OnBuiltinSelected(int Index);
    void OnResultDoubleClicked(QTreeWidgetItem* Item, int Column);

private:
    void PopulateResults(const QVector<TemplateResult>& Results, QTreeWidgetItem* Parent = nullptr);
    QString FieldTypeToString(TemplateFieldType Type) const;
    QString BytesToHex(const QByteArray& Data) const;

    QSplitter* MainSplitter;
    QPlainTextEdit* SourceEditor;
    TemplateSyntaxHighlighter* Highlighter;
    QTreeWidget* ResultTree;
    QPlainTextEdit* ErrorOutput;
    QLineEdit* AddressInput;
    QPushButton* ApplyButton;
    QPushButton* LoadButton;
    QPushButton* SaveButton;
    QComboBox* BuiltinCombo;
    TemplateEngine* Engine;
    AnalysisDatabase* AnalysisDb;
};

}
