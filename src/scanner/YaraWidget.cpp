#include "YaraWidget.h"
#include "YaraEngine.h"
#include "../analysis/AnalysisDatabase.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QFileDialog>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QMessageBox>
#include <QHeaderView>
#include <QFont>
#include <QRegularExpression>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <QLineEdit>
#include <QInputDialog>

namespace Fidra {

YaraHighlighter::YaraHighlighter(QTextDocument* Parent)
    : QSyntaxHighlighter(Parent)
{
    KeywordFormat.setForeground(QColor(86, 156, 214));
    KeywordFormat.setFontWeight(QFont::Bold);

    HighlightRule KeywordRule;
    KeywordRule.Pattern = QRegularExpression(
        QStringLiteral("\\b(rule|meta|strings|condition|all|any|of|them|true|false|"
                        "and|or|not|at|filesize|entrypoint|uint8|uint16|uint32|"
                        "int8|int16|int32|ascii|wide|nocase|fullword|private|"
                        "global|import|include|for|in)\\b"));
    KeywordRule.Format = KeywordFormat;
    Rules.append(KeywordRule);

    HexFormat.setForeground(QColor(78, 201, 176));
    HighlightRule HexRule;
    HexRule.Pattern = QRegularExpression(QStringLiteral("\\{[^}]*\\}"));
    HexRule.Format = HexFormat;
    Rules.append(HexRule);

    StringFormat.setForeground(QColor(200, 120, 0));
    HighlightRule StringRule;
    StringRule.Pattern = QRegularExpression(QStringLiteral("\"[^\"]*\""));
    StringRule.Format = StringFormat;
    Rules.append(StringRule);

    CommentFormat.setForeground(QColor(128, 128, 128));
    CommentFormat.setFontItalic(true);
    HighlightRule SingleLineCommentRule;
    SingleLineCommentRule.Pattern = QRegularExpression(QStringLiteral("//[^\n]*"));
    SingleLineCommentRule.Format = CommentFormat;
    Rules.append(SingleLineCommentRule);

    MultiLineCommentFormat.setForeground(QColor(128, 128, 128));
    MultiLineCommentFormat.setFontItalic(true);
    CommentStartExpr = QRegularExpression(QStringLiteral("/\\*"));
    CommentEndExpr = QRegularExpression(QStringLiteral("\\*/"));
}

void YaraHighlighter::highlightBlock(const QString& Text)
{
    for (const auto& Rule : Rules) {
        auto MatchIter = Rule.Pattern.globalMatch(Text);
        while (MatchIter.hasNext()) {
            auto Match = MatchIter.next();
            setFormat(Match.capturedStart(), Match.capturedLength(), Rule.Format);
        }
    }

    setCurrentBlockState(0);

    int StartIndex = 0;
    if (previousBlockState() != 1) {
        auto Match = CommentStartExpr.match(Text);
        StartIndex = Match.hasMatch() ? Match.capturedStart() : -1;
    }

    while (StartIndex >= 0) {
        auto EndMatch = CommentEndExpr.match(Text, StartIndex);
        int EndIndex = EndMatch.hasMatch() ? EndMatch.capturedStart() : -1;
        int CommentLength;
        if (EndIndex == -1) {
            setCurrentBlockState(1);
            CommentLength = Text.length() - StartIndex;
        } else {
            CommentLength = EndIndex - StartIndex + EndMatch.capturedLength();
        }
        setFormat(StartIndex, CommentLength, MultiLineCommentFormat);
        auto NextMatch = CommentStartExpr.match(Text, StartIndex + CommentLength);
        StartIndex = NextMatch.hasMatch() ? NextMatch.capturedStart() : -1;
    }
}

YaraWidget::YaraWidget(QWidget* Parent)
    : QWidget(Parent)
    , DbRef(nullptr)
    , Engine(new YaraEngine(this))
    , RuleEditor(nullptr)
    , Highlighter(nullptr)
    , ResultsTree(nullptr)
    , LoadRulesBtn(nullptr)
    , ScanBinaryBtn(nullptr)
    , ScanMemoryBtn(nullptr)
    , GenerateRuleBtn(nullptr)
    , ClearBtn(nullptr)
    , Progress(nullptr)
    , StatusLabel(nullptr)
{
    SetupUi();

    connect(Engine, &YaraEngine::ScanProgress, this, &YaraWidget::OnScanProgress);
    connect(Engine, &YaraEngine::ScanComplete, this, &YaraWidget::OnScanComplete);
    connect(Engine, &YaraEngine::RuleError, this, [this](const QString& Error) {
        StatusLabel->setText(QStringLiteral("Rule error: %1").arg(Error));
    });

    connect(LoadRulesBtn, &QPushButton::clicked, this, &YaraWidget::OnLoadRules);
    connect(ScanBinaryBtn, &QPushButton::clicked, this, &YaraWidget::OnScanBinary);
    connect(ScanMemoryBtn, &QPushButton::clicked, this, &YaraWidget::OnScanMemory);
    connect(GenerateRuleBtn, &QPushButton::clicked, this, &YaraWidget::OnGenerateRule);
    connect(ClearBtn, &QPushButton::clicked, this, &YaraWidget::OnClear);
    connect(ResultsTree, &QTreeWidget::itemDoubleClicked, this, &YaraWidget::OnResultDoubleClicked);
}

YaraWidget::~YaraWidget() = default;

void YaraWidget::SetAnalysisDatabase(AnalysisDatabase* Db)
{
    DbRef = Db;
}

void YaraWidget::SetupUi()
{
    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(4, 4, 4, 4);
    MainLayout->setSpacing(4);

    auto* ToolbarLayout = new QHBoxLayout();
    ToolbarLayout->setSpacing(4);

    LoadRulesBtn = new QPushButton(QStringLiteral("Load Rules"), this);
    ScanBinaryBtn = new QPushButton(QStringLiteral("Scan Binary"), this);
    ScanMemoryBtn = new QPushButton(QStringLiteral("Scan Memory"), this);
    GenerateRuleBtn = new QPushButton(QStringLiteral("Generate Rule"), this);
    ClearBtn = new QPushButton(QStringLiteral("Clear"), this);

    ToolbarLayout->addWidget(LoadRulesBtn);
    ToolbarLayout->addWidget(ScanBinaryBtn);
    ToolbarLayout->addWidget(ScanMemoryBtn);
    ToolbarLayout->addWidget(GenerateRuleBtn);
    ToolbarLayout->addWidget(ClearBtn);
    ToolbarLayout->addStretch();

    MainLayout->addLayout(ToolbarLayout);

    auto* Splitter = new QSplitter(Qt::Horizontal, this);

    RuleEditor = new QPlainTextEdit(Splitter);
    QFont MonoFont(QStringLiteral("Monospace"));
    MonoFont.setStyleHint(QFont::Monospace);
    MonoFont.setPointSize(10);
    RuleEditor->setFont(MonoFont);
    RuleEditor->setPlaceholderText(QStringLiteral("Enter YARA rules here..."));
    RuleEditor->setTabStopDistance(28.0);
    Highlighter = new YaraHighlighter(RuleEditor->document());

    ResultsTree = new QTreeWidget(Splitter);
    ResultsTree->setHeaderLabels({
        QStringLiteral("Rule Name"),
        QStringLiteral("Tags"),
        QStringLiteral("Matches"),
        QStringLiteral("Details")
    });
    ResultsTree->setAlternatingRowColors(true);
    ResultsTree->setRootIsDecorated(true);
    ResultsTree->header()->setStretchLastSection(true);
    ResultsTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ResultsTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ResultsTree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);

    Splitter->addWidget(RuleEditor);
    Splitter->addWidget(ResultsTree);
    Splitter->setStretchFactor(0, 1);
    Splitter->setStretchFactor(1, 1);

    MainLayout->addWidget(Splitter, 1);

    auto* BottomLayout = new QHBoxLayout();
    BottomLayout->setSpacing(4);

    Progress = new QProgressBar(this);
    Progress->setRange(0, 100);
    Progress->setValue(0);
    Progress->setVisible(false);
    Progress->setMaximumHeight(18);

    StatusLabel = new QLabel(QStringLiteral("Ready"), this);

    BottomLayout->addWidget(Progress);
    BottomLayout->addWidget(StatusLabel, 1);
    MainLayout->addLayout(BottomLayout);
}

void YaraWidget::OnLoadRules()
{
    QString FilePath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("Load YARA Rules"),
        QString(),
        QStringLiteral("YARA Rules (*.yar *.yara);;All Files (*)")
    );

    if (FilePath.isEmpty())
        return;

    QFile File(FilePath);
    if (!File.open(QIODevice::ReadOnly | QIODevice::Text)) {
        StatusLabel->setText(QStringLiteral("Failed to open: %1").arg(FilePath));
        return;
    }

    QTextStream Stream(&File);
    QString Content = Stream.readAll();
    File.close();

    RuleEditor->setPlainText(Content);

    QString Error;
    if (Engine->CompileRule(Content, Error)) {
        StatusLabel->setText(QStringLiteral("Loaded %1 rules from %2")
            .arg(Engine->RuleCount())
            .arg(QFileInfo(FilePath).fileName()));
    } else {
        StatusLabel->setText(QStringLiteral("Parse error: %1").arg(Error));
    }
}

void YaraWidget::OnScanBinary()
{
    QString RuleText = RuleEditor->toPlainText().trimmed();
    if (RuleText.isEmpty()) {
        StatusLabel->setText(QStringLiteral("No rules to scan with"));
        return;
    }

    if (!DbRef) {
        StatusLabel->setText(QStringLiteral("No analysis database loaded"));
        return;
    }

    QString Error;
    if (!Engine->CompileRule(RuleText, Error)) {
        StatusLabel->setText(QStringLiteral("Compile error: %1").arg(Error));
        return;
    }

    Progress->setVisible(true);
    Progress->setValue(0);
    StatusLabel->setText(QStringLiteral("Scanning binary..."));

    ScanBinaryBtn->setEnabled(false);
    ScanMemoryBtn->setEnabled(false);

    auto Matches = Engine->ScanDatabase(DbRef);

    ScanBinaryBtn->setEnabled(true);
    ScanMemoryBtn->setEnabled(true);

    PopulateResults(Matches);
}

void YaraWidget::OnScanMemory()
{
    QString RuleText = RuleEditor->toPlainText().trimmed();
    if (RuleText.isEmpty()) {
        StatusLabel->setText(QStringLiteral("No rules to scan with"));
        return;
    }

    if (!DbRef) {
        StatusLabel->setText(QStringLiteral("No analysis database loaded"));
        return;
    }

    QString Error;
    if (!Engine->CompileRule(RuleText, Error)) {
        StatusLabel->setText(QStringLiteral("Compile error: %1").arg(Error));
        return;
    }

    Progress->setVisible(true);
    Progress->setValue(0);
    StatusLabel->setText(QStringLiteral("Scanning memory regions..."));

    ScanBinaryBtn->setEnabled(false);
    ScanMemoryBtn->setEnabled(false);

    BinaryInfo Info = DbRef->GetBinaryInfo();
    QByteArray AllData;
    Address BaseAddr = Info.ImageBase;

    for (const auto& Seg : Info.Segments) {
        if (!Seg.Data.isEmpty()) {
            AllData.append(Seg.Data);
        }
    }

    QVector<YaraMatch> Matches;
    if (!AllData.isEmpty()) {
        Matches = Engine->ScanBuffer(AllData, BaseAddr);
    }

    ScanBinaryBtn->setEnabled(true);
    ScanMemoryBtn->setEnabled(true);

    PopulateResults(Matches);
}

void YaraWidget::OnGenerateRule()
{
    ShowGenerateDialog();
}

void YaraWidget::OnClear()
{
    RuleEditor->clear();
    ResultsTree->clear();
    Progress->setVisible(false);
    Progress->setValue(0);
    StatusLabel->setText(QStringLiteral("Ready"));
}

void YaraWidget::OnScanProgress(int Percent)
{
    Progress->setValue(Percent);
}

void YaraWidget::OnScanComplete(int MatchCount)
{
    Progress->setVisible(false);
    StatusLabel->setText(QStringLiteral("Scan complete: %1 matches found").arg(MatchCount));
}

void YaraWidget::OnResultDoubleClicked(QTreeWidgetItem* Item, int Column)
{
    Q_UNUSED(Column);

    if (!Item->parent())
        return;

    QString AddrText = Item->text(3);
    if (AddrText.isEmpty())
        return;

    bool Ok = false;
    Address Addr = AddrText.toULongLong(&Ok, 16);
    if (Ok) {
        emit NavigateToAddress(Addr);
    }
}

void YaraWidget::PopulateResults(const QVector<YaraMatch>& Matches)
{
    ResultsTree->clear();

    for (const auto& Match : Matches) {
        auto* RuleItem = new QTreeWidgetItem(ResultsTree);
        RuleItem->setText(0, Match.RuleName);
        RuleItem->setText(1, Match.MatchedStrings.join(QStringLiteral(", ")));
        RuleItem->setText(2, QString::number(Match.Hits.size()));
        RuleItem->setExpanded(true);

        for (const auto& Hit : Match.Hits) {
            auto* HitItem = new QTreeWidgetItem(RuleItem);
            HitItem->setText(0, Hit.second);
            HitItem->setText(3, QStringLiteral("%1").arg(Hit.first, 16, 16, QLatin1Char('0')));
        }
    }

    if (Matches.isEmpty() && Engine->RuleCount() > 0) {
        StatusLabel->setText(QStringLiteral("No matches found (%1 rules checked)").arg(Engine->RuleCount()));
    }
}

void YaraWidget::ShowGenerateDialog()
{
    auto* Dialog = new QDialog(this);
    Dialog->setWindowTitle(QStringLiteral("Generate YARA Rule"));
    Dialog->setMinimumWidth(500);
    Dialog->setMinimumHeight(350);

    auto* DialogLayout = new QVBoxLayout(Dialog);
    auto* FormLayout = new QFormLayout();

    auto* NameInput = new QLineEdit(Dialog);
    NameInput->setPlaceholderText(QStringLiteral("my_rule"));
    FormLayout->addRow(QStringLiteral("Rule Name:"), NameInput);

    auto* AuthorInput = new QLineEdit(Dialog);
    AuthorInput->setPlaceholderText(QStringLiteral("Analyst"));
    FormLayout->addRow(QStringLiteral("Author:"), AuthorInput);

    auto* DescInput = new QLineEdit(Dialog);
    DescInput->setPlaceholderText(QStringLiteral("Description of the rule"));
    FormLayout->addRow(QStringLiteral("Description:"), DescInput);

    DialogLayout->addLayout(FormLayout);

    auto* HexLabel = new QLabel(QStringLiteral("Hex Pattern (e.g. 4D 5A ?? ?? 00):"), Dialog);
    DialogLayout->addWidget(HexLabel);

    auto* HexInput = new QPlainTextEdit(Dialog);
    QFont HexFont(QStringLiteral("Monospace"));
    HexFont.setStyleHint(QFont::Monospace);
    HexFont.setPointSize(10);
    HexInput->setFont(HexFont);
    HexInput->setMaximumHeight(100);
    DialogLayout->addWidget(HexInput);

    auto* FuncBtnLayout = new QHBoxLayout();
    auto* GenFromFuncBtn = new QPushButton(QStringLiteral("Generate from Function"), Dialog);
    GenFromFuncBtn->setEnabled(DbRef != nullptr);
    FuncBtnLayout->addWidget(GenFromFuncBtn);
    FuncBtnLayout->addStretch();
    DialogLayout->addLayout(FuncBtnLayout);

    auto* PreviewLabel = new QLabel(QStringLiteral("Preview:"), Dialog);
    DialogLayout->addWidget(PreviewLabel);

    auto* PreviewEdit = new QPlainTextEdit(Dialog);
    PreviewEdit->setReadOnly(true);
    PreviewEdit->setFont(HexFont);
    DialogLayout->addWidget(PreviewEdit);

    auto* ButtonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, Dialog);
    DialogLayout->addWidget(ButtonBox);

    auto UpdatePreview = [&]() {
        QString Name = NameInput->text().trimmed();
        if (Name.isEmpty())
            Name = QStringLiteral("unnamed_rule");

        QString HexText = HexInput->toPlainText().trimmed();
        QByteArray HexBytes;
        QStringList Tokens = HexText.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
        for (const auto& Token : Tokens) {
            if (Token == QStringLiteral("??")) {
                HexBytes.append('\x00');
            } else {
                bool Ok = false;
                uint8_t Byte = static_cast<uint8_t>(Token.toUInt(&Ok, 16));
                if (Ok) HexBytes.append(static_cast<char>(Byte));
            }
        }

        QMap<QString, QString> Meta;
        if (!AuthorInput->text().trimmed().isEmpty())
            Meta[QStringLiteral("author")] = AuthorInput->text().trimmed();
        if (!DescInput->text().trimmed().isEmpty())
            Meta[QStringLiteral("description")] = DescInput->text().trimmed();

        QString Generated = YaraEngine::GenerateRule(Name, HexBytes, Meta);
        PreviewEdit->setPlainText(Generated);
    };

    connect(NameInput, &QLineEdit::textChanged, Dialog, UpdatePreview);
    connect(HexInput, &QPlainTextEdit::textChanged, Dialog, UpdatePreview);
    connect(AuthorInput, &QLineEdit::textChanged, Dialog, UpdatePreview);
    connect(DescInput, &QLineEdit::textChanged, Dialog, UpdatePreview);

    connect(GenFromFuncBtn, &QPushButton::clicked, Dialog, [&]() {
        if (!DbRef) return;

        bool Ok = false;
        QString AddrStr = QInputDialog::getText(
            Dialog,
            QStringLiteral("Function Address"),
            QStringLiteral("Enter function start address (hex):"),
            QLineEdit::Normal,
            QString(),
            &Ok
        );

        if (!Ok || AddrStr.isEmpty()) return;

        Address FuncAddr = AddrStr.toULongLong(&Ok, 16);
        if (!Ok) {
            QMessageBox::warning(Dialog, QStringLiteral("Error"), QStringLiteral("Invalid hex address"));
            return;
        }

        QString RuleName = NameInput->text().trimmed();
        if (RuleName.isEmpty())
            RuleName = QStringLiteral("func_%1").arg(FuncAddr, 0, 16);

        QString Generated = YaraEngine::GenerateRuleFromFunction(DbRef, FuncAddr, RuleName);
        if (Generated.isEmpty()) {
            QMessageBox::warning(Dialog, QStringLiteral("Error"),
                QStringLiteral("Could not generate rule from function at 0x%1").arg(FuncAddr, 0, 16));
            return;
        }

        PreviewEdit->setPlainText(Generated);
        HexInput->clear();
    });

    connect(ButtonBox, &QDialogButtonBox::accepted, Dialog, &QDialog::accept);
    connect(ButtonBox, &QDialogButtonBox::rejected, Dialog, &QDialog::reject);

    if (Dialog->exec() == QDialog::Accepted) {
        QString Preview = PreviewEdit->toPlainText().trimmed();
        if (!Preview.isEmpty()) {
            QString CurrentText = RuleEditor->toPlainText();
            if (!CurrentText.isEmpty() && !CurrentText.endsWith(QLatin1Char('\n')))
                CurrentText.append(QStringLiteral("\n\n"));
            else if (!CurrentText.isEmpty())
                CurrentText.append(QLatin1Char('\n'));
            CurrentText.append(Preview);
            RuleEditor->setPlainText(CurrentText);

            QString Error;
            if (Engine->CompileRule(RuleEditor->toPlainText(), Error)) {
                StatusLabel->setText(QStringLiteral("Rule added (%1 rules total)").arg(Engine->RuleCount()));
            } else {
                StatusLabel->setText(QStringLiteral("Rule added but has errors: %1").arg(Error));
            }
        }
    }

    delete Dialog;
}

}
