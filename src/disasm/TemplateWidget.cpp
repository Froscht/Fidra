#include "TemplateWidget.h"
#include "TemplateEngine.h"
#include "../analysis/AnalysisDatabase.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QFontMetrics>
#include <QHeaderView>

namespace Fidra {

TemplateSyntaxHighlighter::TemplateSyntaxHighlighter(QTextDocument* Parent)
    : QSyntaxHighlighter(Parent)
    , CommentStartExpr(QRegularExpression(QStringLiteral("/\\*")))
    , CommentEndExpr(QRegularExpression(QStringLiteral("\\*/")))
{
    KeywordFormat.setForeground(QColor(86, 156, 214));
    KeywordFormat.setFontWeight(QFont::Bold);

    TypeFormat.setForeground(QColor(78, 201, 176));

    NumberFormat.setForeground(QColor(181, 137, 0));

    StringFormat.setForeground(QColor(214, 157, 133));

    CommentFormat.setForeground(QColor(106, 153, 85));
    CommentFormat.setFontItalic(true);

    HighlightRule Rule;

    Rule.Pattern = QRegularExpression(QStringLiteral("\\b(struct|enum|if|padding|array|be)\\b"));
    Rule.Format = KeywordFormat;
    Rules.append(Rule);

    Rule.Pattern = QRegularExpression(QStringLiteral("\\b(u8|u16|u32|u64|i8|i16|i32|i64|float|double|bool|char|wchar|string|wstring|pointer|color|bitfield)\\b"));
    Rule.Format = TypeFormat;
    Rules.append(Rule);

    Rule.Pattern = QRegularExpression(QStringLiteral("\\b(0x[0-9A-Fa-f]+|0b[01]+|\\d+)\\b"));
    Rule.Format = NumberFormat;
    Rules.append(Rule);

    Rule.Pattern = QRegularExpression(QStringLiteral("\"[^\"]*\""));
    Rule.Format = StringFormat;
    Rules.append(Rule);

    Rule.Pattern = QRegularExpression(QStringLiteral("//[^\n]*"));
    Rule.Format = CommentFormat;
    Rules.append(Rule);
}

void TemplateSyntaxHighlighter::highlightBlock(const QString& Text) {
    for (const HighlightRule& Rule : Rules) {
        QRegularExpressionMatchIterator MatchIter = Rule.Pattern.globalMatch(Text);
        while (MatchIter.hasNext()) {
            QRegularExpressionMatch Match = MatchIter.next();
            setFormat(Match.capturedStart(), Match.capturedLength(), Rule.Format);
        }
    }

    setCurrentBlockState(0);

    int StartIndex = 0;
    if (previousBlockState() != 1) {
        QRegularExpressionMatch StartMatch = CommentStartExpr.match(Text);
        StartIndex = StartMatch.hasMatch() ? StartMatch.capturedStart() : -1;
    }

    while (StartIndex >= 0) {
        QRegularExpressionMatch EndMatch = CommentEndExpr.match(Text, StartIndex + 2);
        int EndIndex = EndMatch.hasMatch() ? EndMatch.capturedStart() : -1;
        int CommentLength;
        if (EndIndex == -1) {
            setCurrentBlockState(1);
            CommentLength = Text.length() - StartIndex;
        } else {
            CommentLength = EndIndex - StartIndex + EndMatch.capturedLength();
        }
        setFormat(StartIndex, CommentLength, CommentFormat);
        QRegularExpressionMatch NextStart = CommentStartExpr.match(Text, StartIndex + CommentLength);
        StartIndex = NextStart.hasMatch() ? NextStart.capturedStart() : -1;
    }
}

TemplateWidget::TemplateWidget(QWidget* Parent)
    : QWidget(Parent)
    , MainSplitter(nullptr)
    , SourceEditor(nullptr)
    , Highlighter(nullptr)
    , ResultTree(nullptr)
    , ErrorOutput(nullptr)
    , AddressInput(nullptr)
    , ApplyButton(nullptr)
    , LoadButton(nullptr)
    , SaveButton(nullptr)
    , BuiltinCombo(nullptr)
    , Engine(new TemplateEngine(this))
    , AnalysisDb(nullptr)
{
    QVBoxLayout* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(4, 4, 4, 4);
    MainLayout->setSpacing(4);

    QHBoxLayout* ToolbarLayout = new QHBoxLayout();
    ToolbarLayout->setSpacing(6);

    QLabel* AddrLabel = new QLabel(QStringLiteral("Address:"), this);
    ToolbarLayout->addWidget(AddrLabel);

    AddressInput = new QLineEdit(this);
    AddressInput->setPlaceholderText(QStringLiteral("0x00000000"));
    QFont MonoFont(QStringLiteral("Consolas"), 10);
    MonoFont.setStyleHint(QFont::Monospace, QFont::PreferDefault);
    MonoFont.setFamilies({QStringLiteral("Consolas"), QStringLiteral("Courier New"), QStringLiteral("monospace")});
    AddressInput->setFont(MonoFont);
    AddressInput->setFixedWidth(180);
    ToolbarLayout->addWidget(AddressInput);

    ApplyButton = new QPushButton(QStringLiteral("Apply Template"), this);
    ToolbarLayout->addWidget(ApplyButton);

    LoadButton = new QPushButton(QStringLiteral("Load"), this);
    ToolbarLayout->addWidget(LoadButton);

    SaveButton = new QPushButton(QStringLiteral("Save"), this);
    ToolbarLayout->addWidget(SaveButton);

    ToolbarLayout->addSpacing(12);

    QLabel* BuiltinLabel = new QLabel(QStringLiteral("Built-in:"), this);
    ToolbarLayout->addWidget(BuiltinLabel);

    BuiltinCombo = new QComboBox(this);
    BuiltinCombo->addItem(QStringLiteral("-- Select --"));
    QStringList BuiltinNames = TemplateEngine::GetBuiltinTemplateNames();
    for (const QString& Name : BuiltinNames) {
        BuiltinCombo->addItem(Name);
    }
    ToolbarLayout->addWidget(BuiltinCombo);

    ToolbarLayout->addStretch();
    MainLayout->addLayout(ToolbarLayout);

    MainSplitter = new QSplitter(Qt::Horizontal, this);

    SourceEditor = new QPlainTextEdit(this);
    SourceEditor->setFont(MonoFont);
    QFontMetrics Fm(MonoFont);
    SourceEditor->setTabStopDistance(Fm.horizontalAdvance(QStringLiteral("    ")));
    QPalette EditorPalette = SourceEditor->palette();
    EditorPalette.setColor(QPalette::Base, QColor(30, 30, 30));
    EditorPalette.setColor(QPalette::Text, QColor(212, 212, 212));
    SourceEditor->setPalette(EditorPalette);
    Highlighter = new TemplateSyntaxHighlighter(SourceEditor->document());

    MainSplitter->addWidget(SourceEditor);

    ResultTree = new QTreeWidget(this);
    ResultTree->setHeaderLabels({
        QStringLiteral("Offset"),
        QStringLiteral("Field Name"),
        QStringLiteral("Type"),
        QStringLiteral("Size"),
        QStringLiteral("Value"),
        QStringLiteral("Raw Hex")
    });
    ResultTree->setAlternatingRowColors(true);
    ResultTree->setFont(MonoFont);
    ResultTree->header()->setStretchLastSection(true);
    ResultTree->setColumnWidth(0, 120);
    ResultTree->setColumnWidth(1, 160);
    ResultTree->setColumnWidth(2, 80);
    ResultTree->setColumnWidth(3, 60);
    ResultTree->setColumnWidth(4, 180);

    MainSplitter->addWidget(ResultTree);
    MainSplitter->setStretchFactor(0, 1);
    MainSplitter->setStretchFactor(1, 1);

    MainLayout->addWidget(MainSplitter, 1);

    ErrorOutput = new QPlainTextEdit(this);
    ErrorOutput->setReadOnly(true);
    ErrorOutput->setMaximumHeight(80);
    ErrorOutput->setFont(MonoFont);
    QPalette ErrorPalette = ErrorOutput->palette();
    ErrorPalette.setColor(QPalette::Base, QColor(30, 30, 30));
    ErrorPalette.setColor(QPalette::Text, QColor(255, 80, 80));
    ErrorOutput->setPalette(ErrorPalette);
    ErrorOutput->setPlaceholderText(QStringLiteral("Parse errors will appear here..."));
    MainLayout->addWidget(ErrorOutput);

    connect(ApplyButton, &QPushButton::clicked, this, &TemplateWidget::OnApplyTemplate);
    connect(LoadButton, &QPushButton::clicked, this, &TemplateWidget::OnLoadTemplate);
    connect(SaveButton, &QPushButton::clicked, this, &TemplateWidget::OnSaveTemplate);
    connect(BuiltinCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &TemplateWidget::OnBuiltinSelected);
    connect(ResultTree, &QTreeWidget::itemDoubleClicked, this, &TemplateWidget::OnResultDoubleClicked);
}

TemplateWidget::~TemplateWidget() = default;

void TemplateWidget::SetAnalysisDatabase(AnalysisDatabase* Db) {
    AnalysisDb = Db;
}

void TemplateWidget::OnApplyTemplate() {
    ErrorOutput->clear();
    ResultTree->clear();

    QString Source = SourceEditor->toPlainText();
    if (Source.trimmed().isEmpty()) {
        ErrorOutput->setPlainText(QStringLiteral("No template source to apply."));
        return;
    }

    QString AddrText = AddressInput->text().trimmed();
    if (AddrText.startsWith(QStringLiteral("0x")) || AddrText.startsWith(QStringLiteral("0X"))) {
        AddrText = AddrText.mid(2);
    }
    bool Ok = false;
    Address BaseAddr = AddrText.toULongLong(&Ok, 16);
    if (!Ok && !AddrText.isEmpty()) {
        ErrorOutput->setPlainText(QStringLiteral("Invalid address format. Use hexadecimal (e.g. 0x00400000)."));
        return;
    }

    QString Error;
    if (!Engine->Parse(Source, Error)) {
        ErrorOutput->setPlainText(Error);
        return;
    }

    if (!AnalysisDb) {
        ErrorOutput->setPlainText(QStringLiteral("No analysis database loaded."));
        return;
    }

    QVector<TemplateResult> Results = Engine->Apply(AnalysisDb, BaseAddr);
    PopulateResults(Results);

    for (int I = 0; I < ResultTree->topLevelItemCount(); ++I) {
        ResultTree->topLevelItem(I)->setExpanded(true);
    }
}

void TemplateWidget::PopulateResults(const QVector<TemplateResult>& Results, QTreeWidgetItem* Parent) {
    for (const TemplateResult& Res : Results) {
        QTreeWidgetItem* Item;
        if (Parent) {
            Item = new QTreeWidgetItem(Parent);
        } else {
            Item = new QTreeWidgetItem(ResultTree);
        }

        Item->setText(0, QStringLiteral("0x") + QString::number(Res.Offset, 16).toUpper());
        Item->setText(1, Res.FieldName);
        Item->setText(2, FieldTypeToString(Res.Type));
        Item->setText(3, QString::number(Res.Size));
        Item->setText(4, Res.DisplayValue);

        if (AnalysisDb && Res.Size > 0) {
            QByteArray RawBytes = AnalysisDb->ReadBytes(Res.Offset, static_cast<size_t>(Res.Size));
            Item->setText(5, BytesToHex(RawBytes));
        }

        if (Res.Color.isValid()) {
            QColor BgColor = Res.Color;
            BgColor.setAlpha(60);
            for (int Col = 0; Col < 6; ++Col) {
                Item->setBackground(Col, QBrush(BgColor));
            }
            emit HighlightBytes(Res.Offset, Res.Size, Res.Color);
        }

        Item->setData(0, Qt::UserRole, QVariant::fromValue(static_cast<quint64>(Res.Offset)));
        Item->setToolTip(4, Res.DisplayValue);

        if (!Res.Children.isEmpty()) {
            PopulateResults(Res.Children, Item);
        }
    }
}

QString TemplateWidget::FieldTypeToString(TemplateFieldType Type) const {
    switch (Type) {
    case TemplateFieldType::U8: return QStringLiteral("u8");
    case TemplateFieldType::U16: return QStringLiteral("u16");
    case TemplateFieldType::U32: return QStringLiteral("u32");
    case TemplateFieldType::U64: return QStringLiteral("u64");
    case TemplateFieldType::I8: return QStringLiteral("i8");
    case TemplateFieldType::I16: return QStringLiteral("i16");
    case TemplateFieldType::I32: return QStringLiteral("i32");
    case TemplateFieldType::I64: return QStringLiteral("i64");
    case TemplateFieldType::Float: return QStringLiteral("float");
    case TemplateFieldType::Double: return QStringLiteral("double");
    case TemplateFieldType::Bool: return QStringLiteral("bool");
    case TemplateFieldType::Char: return QStringLiteral("char");
    case TemplateFieldType::WChar: return QStringLiteral("wchar");
    case TemplateFieldType::String: return QStringLiteral("string");
    case TemplateFieldType::WString: return QStringLiteral("wstring");
    case TemplateFieldType::Padding: return QStringLiteral("padding");
    case TemplateFieldType::Array: return QStringLiteral("array");
    case TemplateFieldType::Struct: return QStringLiteral("struct");
    case TemplateFieldType::Enum: return QStringLiteral("enum");
    case TemplateFieldType::Bitfield: return QStringLiteral("bitfield");
    case TemplateFieldType::Pointer: return QStringLiteral("pointer");
    case TemplateFieldType::Color: return QStringLiteral("color");
    }
    return QStringLiteral("unknown");
}

QString TemplateWidget::BytesToHex(const QByteArray& Data) const {
    QString Result;
    Result.reserve(Data.size() * 3);
    for (int I = 0; I < Data.size(); ++I) {
        if (I > 0) {
            Result.append(QChar(' '));
        }
        Result.append(QString::number(static_cast<uint8_t>(Data.at(I)), 16).toUpper().rightJustified(2, QChar('0')));
    }
    return Result;
}

void TemplateWidget::OnLoadTemplate() {
    QString Path = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("Load Template"),
        QString(),
        QStringLiteral("Template Files (*.bt *.hbt);;All Files (*)")
    );
    if (Path.isEmpty()) {
        return;
    }

    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly | QIODevice::Text)) {
        ErrorOutput->setPlainText(QStringLiteral("Failed to open file: ") + Path);
        return;
    }

    QTextStream Stream(&File);
    SourceEditor->setPlainText(Stream.readAll());
    File.close();
}

void TemplateWidget::OnSaveTemplate() {
    QString Path = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("Save Template"),
        QString(),
        QStringLiteral("Template Files (*.bt *.hbt);;All Files (*)")
    );
    if (Path.isEmpty()) {
        return;
    }

    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly | QIODevice::Text)) {
        ErrorOutput->setPlainText(QStringLiteral("Failed to save file: ") + Path);
        return;
    }

    QTextStream Stream(&File);
    Stream << SourceEditor->toPlainText();
    File.close();
}

void TemplateWidget::OnBuiltinSelected(int Index) {
    if (Index <= 0) {
        return;
    }
    QString Name = BuiltinCombo->itemText(Index);
    QString Source = TemplateEngine::GetBuiltinTemplate(Name);
    if (!Source.isEmpty()) {
        SourceEditor->setPlainText(Source);
    }
}

void TemplateWidget::OnResultDoubleClicked(QTreeWidgetItem* Item, int Column) {
    Q_UNUSED(Column);
    if (!Item) {
        return;
    }
    QVariant Data = Item->data(0, Qt::UserRole);
    if (Data.isValid()) {
        Address Addr = static_cast<Address>(Data.toULongLong());
        emit NavigateToAddress(Addr);
    }
}

}
