#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QPlainTextEdit>
#include <QSyntaxHighlighter>
#include <QPushButton>
#include <QSplitter>
#include <QListWidget>
#include <QTabWidget>
#include <QLineEdit>
#include <QRegularExpression>
#include <QCompleter>

namespace Fidra {

class ICore;
class ScriptEngine;
class AnalysisDatabase;
struct ProcessInfo;

struct HighlightRule {
    QRegularExpression Pattern;
    QTextCharFormat Format;
};

class FidraScriptHighlighter : public QSyntaxHighlighter {
    Q_OBJECT
public:
    explicit FidraScriptHighlighter(QTextDocument* Parent = nullptr);
protected:
    void highlightBlock(const QString& Text) override;
private:
    QVector<HighlightRule> Rules;
    QTextCharFormat CommentFormat;
};

class LineNumberArea;

class ScriptCodeEditor : public QPlainTextEdit {
    Q_OBJECT
public:
    explicit ScriptCodeEditor(QWidget* Parent = nullptr);
    void LineNumberAreaPaintEvent(QPaintEvent* Event);
    int LineNumberAreaWidth() const;
protected:
    void resizeEvent(QResizeEvent* Event) override;
    void keyPressEvent(QKeyEvent* Event) override;
private:
    void UpdateLineNumberAreaWidth(int NewBlockCount);
    void HighlightCurrentLine();
    void UpdateLineNumberArea(const QRect& Rect, int Dy);
    LineNumberArea* NumberArea;
};

class LineNumberArea : public QWidget {
public:
    explicit LineNumberArea(ScriptCodeEditor* Editor);
    QSize sizeHint() const override;
protected:
    void paintEvent(QPaintEvent* Event) override;
private:
    ScriptCodeEditor* EditorRef;
};

class ScriptWidget : public QWidget {
    Q_OBJECT
public:
    explicit ScriptWidget(QWidget* Parent, ICore* Core);
    ~ScriptWidget() override;

    void SetDatabase(AnalysisDatabase* Db);
    void OnProcessAttached(const ProcessInfo& Info);
    void OnProcessDetached();

private:
    void SetupUi();
    void LoadSnippets();
    void OnExecute();
    void OnStop();
    void OnClear();
    void OnLoad();
    void OnSave();
    void OnNewTab();
    void OnCloseTab(int Index);
    void OnReplSubmit();
    void OnScriptOutput(const QString& Text);
    void OnScriptError(const QString& Error);
    void OnSnippetClicked(QListWidgetItem* Item);
    void OnExecutionDone(bool Success);
    ScriptCodeEditor* CurrentEditor() const;

    ICore* CoreRef;
    ScriptEngine* Engine;
    QPushButton* RunBtn;
    QPushButton* StopBtn;
    QPushButton* ClearBtn;
    QPushButton* LoadBtn;
    QPushButton* SaveBtn;
    QPushButton* NewTabBtn;
    QSplitter* MainSplitter;
    QSplitter* EditorSplitter;
    QListWidget* SnippetList;
    QTabWidget* TabWidget;
    QPlainTextEdit* OutputView;
    QLineEdit* ReplLine;
    int TabCounter;
};

}
