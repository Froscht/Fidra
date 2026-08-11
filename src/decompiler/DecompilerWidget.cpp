#include "DecompilerWidget.h"
#include "Lifter.h"
#include "Optimizer.h"
#include "CodeGenerator.h"
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFont>
#include <QTextCharFormat>
#include <QSyntaxHighlighter>
#include <QRegularExpression>
#include <QApplication>
#include <QClipboard>

namespace Fidra {

class CSyntaxHighlighter : public QSyntaxHighlighter {
public:
    explicit CSyntaxHighlighter(QTextDocument* Parent = nullptr)
        : QSyntaxHighlighter(Parent)
    {
        KeywordFmt.setForeground(QColor(86, 156, 214));
        KeywordFmt.setFontWeight(QFont::Bold);
        QStringList KeywordPatterns = {
            "\\bif\\b", "\\belse\\b", "\\bwhile\\b", "\\bfor\\b", "\\bdo\\b",
            "\\breturn\\b", "\\bbreak\\b", "\\bcontinue\\b", "\\bswitch\\b",
            "\\bcase\\b", "\\bdefault\\b", "\\bgoto\\b", "\\bsizeof\\b",
            "\\btypedef\\b", "\\bstruct\\b", "\\bunion\\b", "\\benum\\b",
            "\\bconst\\b", "\\bstatic\\b", "\\bextern\\b", "\\bvolatile\\b",
            "\\bregister\\b", "\\binline\\b", "\\b__asm\\b", "\\b__declspec\\b",
            "\\b__cdecl\\b", "\\b__stdcall\\b", "\\b__fastcall\\b", "\\b__thiscall\\b"
        };
        for (const QString& P : KeywordPatterns) AddRule(P, KeywordFmt);

        TypeFmt.setForeground(QColor(78, 201, 176));
        QStringList TypePatterns = {
            "\\bvoid\\b", "\\bchar\\b", "\\bshort\\b", "\\bint\\b", "\\blong\\b",
            "\\bfloat\\b", "\\bdouble\\b", "\\bsigned\\b", "\\bunsigned\\b",
            "\\bint8_t\\b", "\\bint16_t\\b", "\\bint32_t\\b", "\\bint64_t\\b",
            "\\buint8_t\\b", "\\buint16_t\\b", "\\buint32_t\\b", "\\buint64_t\\b",
            "\\bBOOL\\b", "\\bDWORD\\b", "\\bWORD\\b", "\\bBYTE\\b",
            "\\bLPVOID\\b", "\\bHANDLE\\b", "\\bPVOID\\b", "\\bULONG\\b",
            "\\bsize_t\\b", "\\bunknown_t\\b"
        };
        for (const QString& P : TypePatterns) AddRule(P, TypeFmt);

        NumberFmt.setForeground(QColor(181, 206, 168));
        AddRule("\\b0x[0-9a-fA-F]+\\b|\\b-?0x[0-9a-fA-F]+\\b|\\b[0-9]+\\b", NumberFmt);

        StringFmt.setForeground(QColor(214, 157, 133));
        AddRule("\"[^\"]*\"", StringFmt);

        FuncFmt.setForeground(QColor(220, 220, 170));
        AddRule("\\b[a-zA-Z_][a-zA-Z0-9_]*(?=\\s*\\()", FuncFmt);

        OpFmt.setForeground(QColor(180, 180, 180));
        AddRule("[\\+\\-\\*/%&\\|\\^~!=<>]+", OpFmt);

        CommentFmt.setForeground(QColor(106, 153, 85));
        CommentFmt.setFontItalic(true);
        AddRule("//[^\n]*", CommentFmt);
        AddRule("/\\*.*?\\*/", CommentFmt);
    }

protected:
    void highlightBlock(const QString& Text) override {
        for (const Rule& R : RuleList) {
            QRegularExpressionMatchIterator It = R.Re.globalMatch(Text);
            while (It.hasNext()) {
                QRegularExpressionMatch M = It.next();
                setFormat(M.capturedStart(), M.capturedLength(), R.Fmt);
            }
        }
        int Idx = 0;
        if (previousBlockState() != 1) Idx = Text.indexOf("/*");
        while (Idx >= 0) {
            int End = Text.indexOf("*/", Idx + 2);
            int Len = (End == -1) ? Text.length() - Idx : End - Idx + 2;
            if (End == -1) setCurrentBlockState(1);
            setFormat(Idx, Len, CommentFmt);
            Idx = Text.indexOf("/*", Idx + Len);
        }
    }

private:
    struct Rule { QRegularExpression Re; QTextCharFormat Fmt; };
    QVector<Rule> RuleList;
    QTextCharFormat KeywordFmt, TypeFmt, NumberFmt, StringFmt, FuncFmt, OpFmt, CommentFmt;

    void AddRule(const QString& Pattern, const QTextCharFormat& Fmt) {
        RuleList.append({QRegularExpression(Pattern), Fmt});
    }
};

DecompilerWidget::DecompilerWidget(QWidget* Parent, ICore* Core)
    : QWidget(Parent)
    , CoreRef(Core)
    , DbRef(nullptr)
    , CurrentAddr(0)
{
    SetupUi();
}

void DecompilerWidget::SetupUi() {
    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(4, 4, 4, 4);

    auto* ControlRow = new QHBoxLayout();

    DecompileButton = new QPushButton("Decompile");
    ControlRow->addWidget(DecompileButton);

    ControlRow->addWidget(new QLabel("Optimization:"));
    OptLevelCombo = new QComboBox();
    OptLevelCombo->addItem("None");
    OptLevelCombo->addItem("Basic");
    OptLevelCombo->addItem("Full");
    OptLevelCombo->setCurrentIndex(2);
    ControlRow->addWidget(OptLevelCombo);

    ShowAddressesCheck = new QCheckBox("Addresses");
    ControlRow->addWidget(ShowAddressesCheck);

    ShowTypesCheck = new QCheckBox("Types");
    ShowTypesCheck->setChecked(true);
    ControlRow->addWidget(ShowTypesCheck);

    ControlRow->addStretch();

    ComplexityLabel = new QLabel();
    ControlRow->addWidget(ComplexityLabel);

    MainLayout->addLayout(ControlRow);

    OutputTabs = new QTabWidget();

    QFont MonoFont("Monospace", 10);

    PseudoCEdit = new QTextEdit();
    PseudoCEdit->setReadOnly(true);
    PseudoCEdit->setFont(MonoFont);
    PseudoCEdit->setLineWrapMode(QTextEdit::NoWrap);
    QPalette CodePal = PseudoCEdit->palette();
    CodePal.setColor(QPalette::Base, QColor(30, 30, 30));
    CodePal.setColor(QPalette::Text, QColor(212, 212, 212));
    PseudoCEdit->setPalette(CodePal);
    new CSyntaxHighlighter(PseudoCEdit->document());
    OutputTabs->addTab(PseudoCEdit, "Pseudo-C");

    IrEdit = new QTextEdit();
    IrEdit->setReadOnly(true);
    IrEdit->setFont(MonoFont);
    IrEdit->setLineWrapMode(QTextEdit::NoWrap);
    QPalette IrPal = IrEdit->palette();
    IrPal.setColor(QPalette::Base, QColor(30, 30, 30));
    IrPal.setColor(QPalette::Text, QColor(180, 210, 180));
    IrEdit->setPalette(IrPal);
    OutputTabs->addTab(IrEdit, "IR");

    MainLayout->addWidget(OutputTabs, 1);

    StatusLabel = new QLabel("Ready");
    MainLayout->addWidget(StatusLabel);

    connect(DecompileButton, &QPushButton::clicked, this, [this]() {
        if (DbRef && CurrentAddr != 0)
            DecompileFunction(CurrentAddr, DbRef);
    });
}

void DecompilerWidget::SetDatabase(AnalysisDatabase* Db) {
    DbRef = Db;
}

void DecompilerWidget::DecompileFunction(Address Addr, AnalysisDatabase* Db) {
    if (!Db) {
        StatusLabel->setText("No database");
        return;
    }

    DbRef = Db;
    CurrentAddr = Addr;

    AnalyzedFunction Func = Db->GetFunction(Addr);
    if (Func.Start == 0) {
        StatusLabel->setText(QString("No function at 0x%1").arg(Addr, 0, 16));
        return;
    }

    StatusLabel->setText("Decompiling...");

    Decomp::Lifter Lft;
    Decomp::IrFunction IrFunc = Lft.LiftFunction(Func, Db);

    int OptLevel = OptLevelCombo->currentIndex();

    if (OptLevel > 0) {
        Decomp::Optimizer Opt;

        if (OptLevel == 1) {
            Opt.SetPassEnabled("ExpressionSimplification", false);
            Opt.SetPassEnabled("ConditionRecovery", false);
        }

        IrFunc = Opt.Optimize(IrFunc);
    }

    Decomp::CodeGenerator Gen;
    Gen.SetShowAddresses(ShowAddressesCheck->isChecked());
    Gen.SetShowTypes(ShowTypesCheck->isChecked());

    Decomp::DecompOutput Out = Gen.Generate(IrFunc, Db);

    PseudoCEdit->setPlainText(Out.PseudoC);
    IrEdit->setPlainText(Out.IrDump);

    ComplexityLabel->setText(QString("Complexity: %1 | %2ms").arg(Out.Complexity).arg(Out.TimeMs, 0, 'f', 1));
    StatusLabel->setText(QString("Decompiled: %1").arg(Out.FunctionSignature));
}

}
