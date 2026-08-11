#include "ScriptWidget.h"
#include "ScriptEngine.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFile>
#include <QFileDialog>
#include <QFont>
#include <QPainter>
#include <QScrollBar>
#include <QTextBlock>
#include <QKeyEvent>
#include <QRegularExpression>
#include <QThread>

namespace Fidra {

FidraScriptHighlighter::FidraScriptHighlighter(QTextDocument* Parent)
    : QSyntaxHighlighter(Parent)
{
    QTextCharFormat KeywordFmt;
    KeywordFmt.setForeground(QColor(86, 156, 214));
    KeywordFmt.setFontWeight(QFont::Bold);
    QStringList Keywords = {
        "\\bfunction\\b", "\\bend\\b", "\\bif\\b", "\\bthen\\b", "\\belse\\b",
        "\\belseif\\b", "\\bwhile\\b", "\\bdo\\b", "\\bfor\\b", "\\bin\\b",
        "\\breturn\\b", "\\blocal\\b", "\\bnil\\b", "\\btrue\\b", "\\bfalse\\b",
        "\\band\\b", "\\bor\\b", "\\bnot\\b", "\\bbreak\\b", "\\brepeat\\b", "\\buntil\\b"
    };
    for (const QString& Kw : Keywords)
        Rules.append({QRegularExpression(Kw), KeywordFmt});

    QTextCharFormat BuiltinFmt;
    BuiltinFmt.setForeground(QColor(220, 220, 170));
    QStringList Builtins = {
        "\\bprint\\b", "\\btostring\\b", "\\btonumber\\b", "\\btype\\b",
        "\\berror\\b", "\\bpcall\\b", "\\bipairs\\b", "\\bpairs\\b",
        "\\bunpack\\b", "\\bselect\\b", "\\bsetmetatable\\b", "\\bgetmetatable\\b"
    };
    for (const QString& B : Builtins)
        Rules.append({QRegularExpression(B), BuiltinFmt});

    QTextCharFormat FidraFmt;
    FidraFmt.setForeground(QColor(78, 201, 176));
    Rules.append({QRegularExpression("\\baida\\b\\.\\w+"), FidraFmt});
    Rules.append({QRegularExpression("\\baida\\b"), FidraFmt});

    QTextCharFormat StringFmt;
    StringFmt.setForeground(QColor(206, 145, 120));
    Rules.append({QRegularExpression("\"[^\"]*\""), StringFmt});
    Rules.append({QRegularExpression("'[^']*'"), StringFmt});

    QTextCharFormat NumberFmt;
    NumberFmt.setForeground(QColor(181, 206, 168));
    Rules.append({QRegularExpression("\\b0x[0-9a-fA-F]+\\b"), NumberFmt});
    Rules.append({QRegularExpression("\\b[0-9]+\\.?[0-9]*([eE][+-]?[0-9]+)?\\b"), NumberFmt});

    CommentFormat.setForeground(QColor(106, 153, 85));
    CommentFormat.setFontItalic(true);
    Rules.append({QRegularExpression("--(?!\\[\\[).*$"), CommentFormat});
}

void FidraScriptHighlighter::highlightBlock(const QString& Text) {
    for (const auto& Rule : Rules) {
        auto MatchIt = Rule.Pattern.globalMatch(Text);
        while (MatchIt.hasNext()) {
            auto Match = MatchIt.next();
            setFormat(Match.capturedStart(), Match.capturedLength(), Rule.Format);
        }
    }

    int BlockCommentStart = Text.indexOf("--[[");
    if (BlockCommentStart >= 0) {
        int End = Text.indexOf("]]", BlockCommentStart + 4);
        if (End >= 0) {
            setFormat(BlockCommentStart, End - BlockCommentStart + 2, CommentFormat);
        } else {
            setFormat(BlockCommentStart, Text.size() - BlockCommentStart, CommentFormat);
            setCurrentBlockState(1);
        }
    }

    if (previousBlockState() == 1) {
        int End = Text.indexOf("]]");
        if (End >= 0) {
            setFormat(0, End + 2, CommentFormat);
            setCurrentBlockState(0);
        } else {
            setFormat(0, Text.size(), CommentFormat);
            setCurrentBlockState(1);
        }
    }
}

ScriptCodeEditor::ScriptCodeEditor(QWidget* Parent)
    : QPlainTextEdit(Parent)
{
    NumberArea = new LineNumberArea(this);

    connect(this, &QPlainTextEdit::blockCountChanged, this, &ScriptCodeEditor::UpdateLineNumberAreaWidth);
    connect(this, &QPlainTextEdit::updateRequest, this, &ScriptCodeEditor::UpdateLineNumberArea);
    connect(this, &QPlainTextEdit::cursorPositionChanged, this, &ScriptCodeEditor::HighlightCurrentLine);

    UpdateLineNumberAreaWidth(0);
    HighlightCurrentLine();

    QFont MonoFont("Consolas", 10);
    MonoFont.setStyleHint(QFont::Monospace);
    MonoFont.setFamilies({"Consolas", "Courier New", "monospace"});
    setFont(MonoFont);
    setTabStopDistance(28);

    QPalette Pal = palette();
    Pal.setColor(QPalette::Base, QColor(30, 30, 30));
    Pal.setColor(QPalette::Text, QColor(212, 212, 212));
    setPalette(Pal);
}

int ScriptCodeEditor::LineNumberAreaWidth() const {
    int Digits = 1;
    int Max = qMax(1, blockCount());
    while (Max >= 10) { Max /= 10; ++Digits; }
    return 10 + fontMetrics().horizontalAdvance(QLatin1Char('9')) * Digits;
}

void ScriptCodeEditor::UpdateLineNumberAreaWidth(int) {
    setViewportMargins(LineNumberAreaWidth(), 0, 0, 0);
}

void ScriptCodeEditor::UpdateLineNumberArea(const QRect& Rect, int Dy) {
    if (Dy)
        NumberArea->scroll(0, Dy);
    else
        NumberArea->update(0, Rect.y(), NumberArea->width(), Rect.height());
    if (Rect.contains(viewport()->rect()))
        UpdateLineNumberAreaWidth(0);
}

void ScriptCodeEditor::resizeEvent(QResizeEvent* Event) {
    QPlainTextEdit::resizeEvent(Event);
    QRect Cr = contentsRect();
    NumberArea->setGeometry(QRect(Cr.left(), Cr.top(), LineNumberAreaWidth(), Cr.height()));
}

void ScriptCodeEditor::HighlightCurrentLine() {
    QList<QTextEdit::ExtraSelection> Selections;
    QTextEdit::ExtraSelection Selection;
    Selection.format.setBackground(QColor(40, 40, 40));
    Selection.format.setProperty(QTextFormat::FullWidthSelection, true);
    Selection.cursor = textCursor();
    Selection.cursor.clearSelection();
    Selections.append(Selection);
    setExtraSelections(Selections);
}

void ScriptCodeEditor::keyPressEvent(QKeyEvent* Event) {
    if (Event->key() == Qt::Key_Tab) {
        insertPlainText("    ");
        return;
    }
    if (Event->key() == Qt::Key_Return || Event->key() == Qt::Key_Enter) {
        QTextCursor Cur = textCursor();
        QString Line = Cur.block().text();
        int Indent = 0;
        while (Indent < Line.size() && Line[Indent] == ' ') ++Indent;
        QString IndentStr = QString(Indent, ' ');
        static QRegularExpression IncreasePattern("\\b(function|if|else|elseif|for|while|repeat|do)\\b");
        if (Line.trimmed().contains(IncreasePattern))
            IndentStr += "    ";
        QPlainTextEdit::keyPressEvent(Event);
        insertPlainText(IndentStr);
        return;
    }
    QPlainTextEdit::keyPressEvent(Event);
}

void ScriptCodeEditor::LineNumberAreaPaintEvent(QPaintEvent* Event) {
    QPainter Painter(NumberArea);
    Painter.fillRect(Event->rect(), QColor(35, 35, 35));
    Painter.setPen(QColor(100, 100, 100));

    QTextBlock Block = firstVisibleBlock();
    int BlockNumber = Block.blockNumber();
    int Top = static_cast<int>(blockBoundingGeometry(Block).translated(contentOffset()).top());
    int Bottom = Top + static_cast<int>(blockBoundingRect(Block).height());

    while (Block.isValid() && Top <= Event->rect().bottom()) {
        if (Block.isVisible() && Bottom >= Event->rect().top()) {
            Painter.drawText(0, Top, NumberArea->width() - 4, fontMetrics().height(),
                             Qt::AlignRight, QString::number(BlockNumber + 1));
        }
        Block = Block.next();
        Top = Bottom;
        Bottom = Top + static_cast<int>(blockBoundingRect(Block).height());
        ++BlockNumber;
    }
}

LineNumberArea::LineNumberArea(ScriptCodeEditor* Editor)
    : QWidget(Editor), EditorRef(Editor) {}

QSize LineNumberArea::sizeHint() const {
    return QSize(EditorRef->LineNumberAreaWidth(), 0);
}

void LineNumberArea::paintEvent(QPaintEvent* Event) {
    EditorRef->LineNumberAreaPaintEvent(Event);
}

ScriptWidget::ScriptWidget(QWidget* Parent, ICore* Core)
    : QWidget(Parent)
    , CoreRef(Core)
    , Engine(new ScriptEngine(Core, this))
    , RunBtn(nullptr)
    , StopBtn(nullptr)
    , ClearBtn(nullptr)
    , LoadBtn(nullptr)
    , SaveBtn(nullptr)
    , NewTabBtn(nullptr)
    , MainSplitter(nullptr)
    , EditorSplitter(nullptr)
    , SnippetList(nullptr)
    , TabWidget(nullptr)
    , OutputView(nullptr)
    , ReplLine(nullptr)
    , TabCounter(1)
{
    SetupUi();
    LoadSnippets();

    connect(Engine, &ScriptEngine::OutputReady, this, &ScriptWidget::OnScriptOutput);
    connect(Engine, &ScriptEngine::ErrorOccurred, this, &ScriptWidget::OnScriptError);
    connect(Engine, &ScriptEngine::ExecutionFinished, this, &ScriptWidget::OnExecutionDone);
}

ScriptWidget::~ScriptWidget() = default;

void ScriptWidget::SetDatabase(AnalysisDatabase* Db) {
    Engine->SetAnalysisDatabase(Db);
}

void ScriptWidget::OnProcessAttached(const ProcessInfo&) {}
void ScriptWidget::OnProcessDetached() {}

ScriptCodeEditor* ScriptWidget::CurrentEditor() const {
    return qobject_cast<ScriptCodeEditor*>(TabWidget->currentWidget());
}

void ScriptWidget::SetupUi() {
    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(0, 0, 0, 0);
    MainLayout->setSpacing(2);

    auto* ToolLayout = new QHBoxLayout();
    RunBtn = new QPushButton("Run");
    StopBtn = new QPushButton("Stop");
    ClearBtn = new QPushButton("Clear");
    LoadBtn = new QPushButton("Load");
    SaveBtn = new QPushButton("Save");
    NewTabBtn = new QPushButton("+");
    NewTabBtn->setMaximumWidth(30);

    StopBtn->setEnabled(false);
    ToolLayout->addWidget(RunBtn);
    ToolLayout->addWidget(StopBtn);
    ToolLayout->addWidget(ClearBtn);
    ToolLayout->addStretch();
    ToolLayout->addWidget(NewTabBtn);
    ToolLayout->addWidget(LoadBtn);
    ToolLayout->addWidget(SaveBtn);
    MainLayout->addLayout(ToolLayout);

    MainSplitter = new QSplitter(Qt::Horizontal, this);

    SnippetList = new QListWidget();
    SnippetList->setMaximumWidth(180);
    MainSplitter->addWidget(SnippetList);

    EditorSplitter = new QSplitter(Qt::Vertical);

    TabWidget = new QTabWidget();
    TabWidget->setTabsClosable(true);
    auto* FirstEditor = new ScriptCodeEditor();
    new FidraScriptHighlighter(FirstEditor->document());
    FirstEditor->setPlaceholderText("-- FidraScript\n-- Use fidra.functions(), fidra.strings(), fidra.regions(), etc.");
    TabWidget->addTab(FirstEditor, "Script 1");

    QFont MonoFont("Consolas", 10);
    MonoFont.setStyleHint(QFont::Monospace);
    MonoFont.setFamilies({"Consolas", "Courier New", "monospace"});

    OutputView = new QPlainTextEdit();
    OutputView->setFont(MonoFont);
    OutputView->setReadOnly(true);
    OutputView->setMaximumBlockCount(10000);
    QPalette OutPal = OutputView->palette();
    OutPal.setColor(QPalette::Base, QColor(25, 25, 25));
    OutPal.setColor(QPalette::Text, QColor(200, 200, 200));
    OutputView->setPalette(OutPal);

    ReplLine = new QLineEdit();
    ReplLine->setFont(MonoFont);
    ReplLine->setPlaceholderText(">>> Type expression and press Enter...");
    QPalette ReplPal = ReplLine->palette();
    ReplPal.setColor(QPalette::Base, QColor(30, 30, 30));
    ReplPal.setColor(QPalette::Text, QColor(212, 212, 212));
    ReplLine->setPalette(ReplPal);

    EditorSplitter->addWidget(TabWidget);
    EditorSplitter->addWidget(OutputView);
    EditorSplitter->addWidget(ReplLine);
    EditorSplitter->setStretchFactor(0, 3);
    EditorSplitter->setStretchFactor(1, 1);
    EditorSplitter->setStretchFactor(2, 0);

    MainSplitter->addWidget(EditorSplitter);
    MainSplitter->setStretchFactor(0, 0);
    MainSplitter->setStretchFactor(1, 1);

    MainLayout->addWidget(MainSplitter);

    connect(RunBtn, &QPushButton::clicked, this, &ScriptWidget::OnExecute);
    connect(StopBtn, &QPushButton::clicked, this, &ScriptWidget::OnStop);
    connect(ClearBtn, &QPushButton::clicked, this, &ScriptWidget::OnClear);
    connect(LoadBtn, &QPushButton::clicked, this, &ScriptWidget::OnLoad);
    connect(SaveBtn, &QPushButton::clicked, this, &ScriptWidget::OnSave);
    connect(NewTabBtn, &QPushButton::clicked, this, &ScriptWidget::OnNewTab);
    connect(TabWidget, &QTabWidget::tabCloseRequested, this, &ScriptWidget::OnCloseTab);
    connect(ReplLine, &QLineEdit::returnPressed, this, &ScriptWidget::OnReplSubmit);
    connect(SnippetList, &QListWidget::itemClicked, this, &ScriptWidget::OnSnippetClicked);
}

void ScriptWidget::LoadSnippets() {
    auto AddSnippet = [this](const QString& Title, const QString& Code) {
        auto* Item = new QListWidgetItem(Title);
        Item->setData(Qt::UserRole, Code);
        SnippetList->addItem(Item);
    };

    AddSnippet("Hello World",
        "print(\"Hello from FidraScript!\")\n"
        "print(\"2 + 2 = \" .. tostring(2 + 2))\n");

    AddSnippet("Process Info",
        "if fidra.is_attached() then\n"
        "    print(\"Process: \" .. fidra.process_name())\n"
        "    print(\"PID: \" .. tostring(fidra.process_pid()))\n"
        "else\n"
        "    print(\"No process attached\")\n"
        "end\n");

    AddSnippet("Read Memory",
        "local Addr = 0x400000\n"
        "print(string.format(\"u8:  %d\", fidra.read_u8(Addr)))\n"
        "print(string.format(\"u16: %d\", fidra.read_u16(Addr)))\n"
        "print(string.format(\"u32: %d\", fidra.read_u32(Addr)))\n"
        "print(string.format(\"u64: %d\", fidra.read_u64(Addr)))\n"
        "local Bytes = fidra.read_bytes(Addr, 16)\n"
        "if Bytes then\n"
        "    local Hex = \"\"\n"
        "    for I, B in ipairs(Bytes) do\n"
        "        Hex = Hex .. string.format(\"%02x \", B)\n"
        "    end\n"
        "    print(Hex)\n"
        "end\n");

    AddSnippet("List Functions",
        "local Funcs = fidra.functions()\n"
        "if Funcs then\n"
        "    print(\"Functions found: \" .. #Funcs)\n"
        "    for I, F in ipairs(Funcs) do\n"
        "        print(string.format(\"0x%x  %s  size=%d\", F.addr, F.name, F.size))\n"
        "    end\n"
        "end\n");

    AddSnippet("List Modules",
        "local Mods = fidra.modules()\n"
        "if Mods then\n"
        "    for I, M in ipairs(Mods) do\n"
        "        print(string.format(\"%-30s  base=0x%x  size=0x%x\", M.name, M.base, M.size))\n"
        "    end\n"
        "end\n");

    AddSnippet("Find Strings",
        "local Strs = fidra.strings()\n"
        "if Strs then\n"
        "    print(\"Strings found: \" .. #Strs)\n"
        "    for I, S in ipairs(Strs) do\n"
        "        print(string.format(\"0x%x  \\\"%s\\\"\", S.addr, S.value))\n"
        "    end\n"
        "end\n");

    AddSnippet("Memory Regions",
        "local Regs = fidra.regions()\n"
        "if Regs then\n"
        "    for I, R in ipairs(Regs) do\n"
        "        print(string.format(\"0x%x  size=0x%x  prot=%d  %s\",\n"
        "            R.base, R.size, R.protection, R.module))\n"
        "    end\n"
        "end\n");

    AddSnippet("Pattern Scan",
        "local Results = fidra.scan_pattern(\"48 89 5C 24 ?? 48 89 74 24 ??\")\n"
        "if Results then\n"
        "    print(\"Matches: \" .. #Results)\n"
        "    for I, Addr in ipairs(Results) do\n"
        "        print(string.format(\"  0x%x\", Addr))\n"
        "    end\n"
        "end\n");

    AddSnippet("Disassemble",
        "local Instrs = fidra.disasm(0x400000, 20)\n"
        "if Instrs then\n"
        "    for I, Ins in ipairs(Instrs) do\n"
        "        print(string.format(\"0x%x  %-8s %s\", Ins.addr, Ins.mnemonic, Ins.operands))\n"
        "    end\n"
        "end\n");
}

void ScriptWidget::OnExecute() {
    auto* Ed = CurrentEditor();
    if (!Ed) return;
    QString Code = Ed->toPlainText();
    if (Code.trimmed().isEmpty()) return;

    OutputView->appendPlainText(">>> Running script...");
    RunBtn->setEnabled(false);
    StopBtn->setEnabled(true);

    auto* Worker = QThread::create([this, Code]() {
        Engine->Execute(Code);
    });
    connect(Worker, &QThread::finished, Worker, &QThread::deleteLater);
    Worker->start();
}

void ScriptWidget::OnStop() {
    Engine->Cancel();
}

void ScriptWidget::OnClear() {
    OutputView->clear();
}

void ScriptWidget::OnLoad() {
    QString Path = QFileDialog::getOpenFileName(this, "Load Script", QString(), "FidraScript (*.lua *.fidra);;All Files (*)");
    if (Path.isEmpty()) return;

    QFile File(Path);
    if (File.open(QIODevice::ReadOnly | QIODevice::Text)) {
        auto* Ed = CurrentEditor();
        if (Ed) Ed->setPlainText(QString::fromUtf8(File.readAll()));
        File.close();
    }
}

void ScriptWidget::OnSave() {
    QString Path = QFileDialog::getSaveFileName(this, "Save Script", QString(), "FidraScript (*.lua *.fidra);;All Files (*)");
    if (Path.isEmpty()) return;

    auto* Ed = CurrentEditor();
    if (!Ed) return;

    QFile File(Path);
    if (File.open(QIODevice::WriteOnly | QIODevice::Text)) {
        File.write(Ed->toPlainText().toUtf8());
        File.close();
    }
}

void ScriptWidget::OnNewTab() {
    ++TabCounter;
    auto* NewEditor = new ScriptCodeEditor();
    new FidraScriptHighlighter(NewEditor->document());
    TabWidget->addTab(NewEditor, QString("Script %1").arg(TabCounter));
    TabWidget->setCurrentWidget(NewEditor);
}

void ScriptWidget::OnCloseTab(int Index) {
    if (TabWidget->count() <= 1) return;
    QWidget* W = TabWidget->widget(Index);
    TabWidget->removeTab(Index);
    delete W;
}

void ScriptWidget::OnReplSubmit() {
    QString Code = ReplLine->text().trimmed();
    if (Code.isEmpty()) return;
    ReplLine->clear();
    OutputView->appendPlainText(">>> " + Code);

    auto* Worker = QThread::create([this, Code]() {
        Engine->Execute(Code);
    });
    connect(Worker, &QThread::finished, Worker, &QThread::deleteLater);
    Worker->start();
}

void ScriptWidget::OnScriptOutput(const QString& Text) {
    QMetaObject::invokeMethod(this, [this, Text]() {
        OutputView->appendPlainText(Text);
    }, Qt::QueuedConnection);
}

void ScriptWidget::OnScriptError(const QString& Error) {
    QMetaObject::invokeMethod(this, [this, Error]() {
        OutputView->appendPlainText("[ERROR] " + Error);
    }, Qt::QueuedConnection);
}

void ScriptWidget::OnSnippetClicked(QListWidgetItem* Item) {
    QString Code = Item->data(Qt::UserRole).toString();
    auto* Ed = CurrentEditor();
    if (Ed) Ed->setPlainText(Code);
}

void ScriptWidget::OnExecutionDone(bool Success) {
    QMetaObject::invokeMethod(this, [this, Success]() {
        RunBtn->setEnabled(true);
        StopBtn->setEnabled(false);
        if (Success)
            OutputView->appendPlainText(">>> Done.");
        else
            OutputView->appendPlainText(">>> Failed.");
    }, Qt::QueuedConnection);
}

}
