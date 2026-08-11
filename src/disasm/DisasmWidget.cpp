#include "DisasmWidget.h"
#include "Disassembler.h"
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QPainter>
#include <QRegularExpression>
#include <QApplication>
#include <QStyle>
#include <QFont>
#include <QMenu>
#include <QAction>
#include <QClipboard>
#include <QShortcut>
#include <QKeySequence>
#include <algorithm>
#include <cmath>

namespace Fidra {

DisasmModel::DisasmModel(QObject* Parent)
    : QAbstractTableModel(Parent) {
}

int DisasmModel::rowCount(const QModelIndex& Parent) const {
    if (Parent.isValid())
        return 0;
    return static_cast<int>(Instructions.size());
}

int DisasmModel::columnCount(const QModelIndex& Parent) const {
    if (Parent.isValid())
        return 0;
    return ColCount;
}

QVariant DisasmModel::data(const QModelIndex& Index, int Role) const {
    if (!Index.isValid() || Index.row() >= Instructions.size())
        return {};

    if (Role == Qt::DisplayRole) {
        const auto& Instr = Instructions[Index.row()];
        switch (Index.column()) {
        case ColAddress:
            return QString("%1").arg(Instr.Location, 16, 16, QChar('0')).toUpper();
        case ColBytes:
            return QString(Instr.Bytes.toHex(' ')).toUpper();
        case ColMnemonic:
            return Instr.Mnemonic;
        case ColOperands: {
            QString Formatted = ApplyOperandFormats(Instr.Location, Instr.Operands);
            return ApplyStackVarSubstitution(Instr.Location, Formatted);
        }
        case ColComment:
            return Instr.Comment;
        }
    }

    if (Role == Qt::FontRole) {
        QFont MonoFont("Consolas", 10);
        MonoFont.setStyleHint(QFont::Monospace);
        return MonoFont;
    }

    return {};
}

QVariant DisasmModel::headerData(int Section, Qt::Orientation Orientation, int Role) const {
    if (Orientation != Qt::Horizontal || Role != Qt::DisplayRole)
        return {};

    switch (Section) {
    case ColAddress:  return QStringLiteral("Address");
    case ColBytes:    return QStringLiteral("Bytes");
    case ColMnemonic: return QStringLiteral("Mnemonic");
    case ColOperands: return QStringLiteral("Operands");
    case ColComment:  return QStringLiteral("Comment");
    }
    return {};
}

void DisasmModel::SetInstructions(const QList<DisasmInstruction>& NewInstructions) {
    beginResetModel();
    Instructions = NewInstructions;
    endResetModel();
}

void DisasmModel::Clear() {
    beginResetModel();
    Instructions.clear();
    endResetModel();
}

DisasmInstruction DisasmModel::GetInstruction(int Row) const {
    if (Row >= 0 && Row < Instructions.size())
        return Instructions[Row];
    return {};
}

void DisasmModel::SetFormatMap(const QMap<Address, QMap<int, OperandFormat>>* Map) {
    Formats = Map;
}

void DisasmModel::SetStackVarMap(const QMap<Address, QMap<int, QString>>* Map, Address CurrentFunc) {
    StackVars = Map;
    CurrentStackVarFunc = CurrentFunc;
}

QString DisasmModel::ApplyStackVarSubstitution(Address InstrAddr, const QString& Operands) const {
    Q_UNUSED(InstrAddr);
    if (!StackVars || CurrentStackVarFunc == 0 || !StackVars->contains(CurrentStackVarFunc))
        return Operands;

    const QMap<int, QString>& VarMap = (*StackVars)[CurrentStackVarFunc];
    if (VarMap.isEmpty())
        return Operands;

    static QRegularExpression StackRefRe(
        "\\[(rbp|rsp)\\s*([+-])\\s*0x([0-9a-fA-F]+)\\]",
        QRegularExpression::CaseInsensitiveOption);

    QString Result = Operands;
    QRegularExpressionMatchIterator It = StackRefRe.globalMatch(Result);
    QList<QPair<int, int>> MatchPositions;
    QList<QString> Replacements;

    while (It.hasNext()) {
        QRegularExpressionMatch M = It.next();
        QString Reg = M.captured(1).toLower();
        QString Sign = M.captured(2);
        bool Ok = false;
        int Off = M.captured(3).toInt(&Ok, 16);
        if (!Ok) continue;

        int Key = 0;
        if (Reg == "rbp") {
            Key = (Sign == "-") ? -Off : Off;
        } else {
            Key = 0x10000 + Off;
        }

        if (VarMap.contains(Key)) {
            QString VarName = VarMap[Key];
            QString Replacement = QString("[%1 + %2]").arg(Reg, VarName);
            MatchPositions.append({M.capturedStart(), M.capturedLength()});
            Replacements.append(Replacement);
        }
    }

    for (int I = MatchPositions.size() - 1; I >= 0; --I) {
        Result.replace(MatchPositions[I].first, MatchPositions[I].second, Replacements[I]);
    }

    return Result;
}

QString DisasmModel::ApplyOperandFormats(Address Addr, const QString& OriginalOperands) const {
    if (!Formats || !Formats->contains(Addr))
        return OriginalOperands;

    const auto& FormatMap = (*Formats)[Addr];
    if (FormatMap.isEmpty())
        return OriginalOperands;

    OperandFormat Fmt = OperandFormat::Default;
    if (FormatMap.contains(0))
        Fmt = FormatMap[0];

    if (Fmt == OperandFormat::Default)
        return OriginalOperands;

    static QRegularExpression HexPattern("0[xX]([0-9a-fA-F]+)");
    static QRegularExpression DecSuffixPattern("([0-9][0-9a-fA-F]*)h\\b");

    QString Result = OriginalOperands;

    QRegularExpressionMatchIterator It = HexPattern.globalMatch(Result);
    QList<QPair<int, int>> Matches;
    QList<QString> Replacements;

    while (It.hasNext()) {
        QRegularExpressionMatch Match = It.next();
        bool Ok = false;
        int64_t Value = static_cast<int64_t>(Match.captured(1).toULongLong(&Ok, 16));
        if (Ok) {
            QString Replacement;
            switch (Fmt) {
            case OperandFormat::Hex:
                Replacement = QString("0x%1").arg(static_cast<uint64_t>(Value), 0, 16).toUpper();
                break;
            case OperandFormat::Decimal:
                Replacement = QString::number(Value);
                break;
            case OperandFormat::Octal:
                Replacement = QString("0%1").arg(static_cast<uint64_t>(Value), 0, 8);
                break;
            case OperandFormat::Binary:
                Replacement = QString("%1b").arg(static_cast<uint64_t>(Value), 0, 2);
                break;
            case OperandFormat::Char: {
                uint64_t UVal = static_cast<uint64_t>(Value);
                QString CharRepr;
                bool AllPrintable = true;
                if (UVal == 0) {
                    CharRepr = "'\\0'";
                } else {
                    while (UVal > 0) {
                        char Ch = static_cast<char>(UVal & 0xFF);
                        if (Ch >= 0x20 && Ch <= 0x7E) {
                            CharRepr.prepend(QChar(Ch));
                        } else {
                            AllPrintable = false;
                            break;
                        }
                        UVal >>= 8;
                    }
                    if (AllPrintable && !CharRepr.isEmpty()) {
                        CharRepr = QString("'%1'").arg(CharRepr);
                    }
                }
                if (AllPrintable && !CharRepr.isEmpty()) {
                    Replacement = CharRepr;
                } else {
                    Replacement = QString("0x%1").arg(static_cast<uint64_t>(Value), 0, 16).toUpper();
                }
                break;
            }
            case OperandFormat::Offset:
                Replacement = QString("0x%1").arg(static_cast<uint64_t>(Value), 0, 16).toUpper();
                break;
            default:
                Replacement = Match.captured(0);
                break;
            }

            Matches.append({Match.capturedStart(), Match.capturedLength()});
            Replacements.append(Replacement);
        }
    }

    for (int I = Matches.size() - 1; I >= 0; --I) {
        Result.replace(Matches[I].first, Matches[I].second, Replacements[I]);
    }

    It = DecSuffixPattern.globalMatch(Result);
    Matches.clear();
    Replacements.clear();

    while (It.hasNext()) {
        QRegularExpressionMatch Match = It.next();
        bool Ok = false;
        int64_t Value = static_cast<int64_t>(Match.captured(1).toULongLong(&Ok, 16));
        if (Ok) {
            QString Replacement;
            switch (Fmt) {
            case OperandFormat::Hex:
                Replacement = QString("0x%1").arg(static_cast<uint64_t>(Value), 0, 16).toUpper();
                break;
            case OperandFormat::Decimal:
                Replacement = QString::number(Value);
                break;
            case OperandFormat::Octal:
                Replacement = QString("0%1").arg(static_cast<uint64_t>(Value), 0, 8);
                break;
            case OperandFormat::Binary:
                Replacement = QString("%1b").arg(static_cast<uint64_t>(Value), 0, 2);
                break;
            case OperandFormat::Char: {
                uint64_t UVal = static_cast<uint64_t>(Value);
                QString CharRepr;
                bool AllPrintable = true;
                if (UVal == 0) {
                    CharRepr = "'\\0'";
                } else {
                    while (UVal > 0) {
                        char Ch = static_cast<char>(UVal & 0xFF);
                        if (Ch >= 0x20 && Ch <= 0x7E) {
                            CharRepr.prepend(QChar(Ch));
                        } else {
                            AllPrintable = false;
                            break;
                        }
                        UVal >>= 8;
                    }
                    if (AllPrintable && !CharRepr.isEmpty()) {
                        CharRepr = QString("'%1'").arg(CharRepr);
                    }
                }
                if (AllPrintable && !CharRepr.isEmpty()) {
                    Replacement = CharRepr;
                } else {
                    Replacement = QString("0x%1").arg(static_cast<uint64_t>(Value), 0, 16).toUpper();
                }
                break;
            }
            case OperandFormat::Offset:
                Replacement = QString("0x%1").arg(static_cast<uint64_t>(Value), 0, 16).toUpper();
                break;
            default:
                Replacement = Match.captured(0);
                break;
            }

            Matches.append({Match.capturedStart(), Match.capturedLength()});
            Replacements.append(Replacement);
        }
    }

    for (int I = Matches.size() - 1; I >= 0; --I) {
        Result.replace(Matches[I].first, Matches[I].second, Replacements[I]);
    }

    return Result;
}

DisasmHighlightDelegate::DisasmHighlightDelegate(QObject* Parent)
    : QStyledItemDelegate(Parent)
    , ColorRegister(0x56, 0x9C, 0xD6)
    , ColorImmediate(0xB5, 0xCE, 0xA8)
    , ColorMemory(0xDC, 0xDC, 0xAA)
    , ColorJumpCall(0xC5, 0x86, 0xC0)
    , ColorRetNop(0x80, 0x80, 0x80)
    , ColorDefault(0xD4, 0xD4, 0xD4) {

    RegisterNames = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        "ax", "bx", "cx", "dx", "si", "di", "sp", "bp",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
        "al", "bl", "cl", "dl", "sil", "dil", "spl", "bpl",
        "ah", "bh", "ch", "dh",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
        "rip", "eip", "ip",
        "cs", "ds", "es", "fs", "gs", "ss",
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
        "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
        "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
        "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",
        "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7",
        "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15",
        "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
        "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",
        "cr0", "cr2", "cr3", "cr4", "cr8",
        "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"
    };
}

void DisasmHighlightDelegate::paint(QPainter* Painter, const QStyleOptionViewItem& Option,
                                     const QModelIndex& Index) const {
    if (Index.column() != DisasmModel::ColMnemonic && Index.column() != DisasmModel::ColOperands) {
        QStyledItemDelegate::paint(Painter, Option, Index);
        return;
    }

    QStyleOptionViewItem Opt = Option;
    initStyleOption(&Opt, Index);

    Painter->save();

    QStyle* Style = Opt.widget ? Opt.widget->style() : QApplication::style();
    Opt.text.clear();
    Style->drawControl(QStyle::CE_ItemViewItem, &Opt, Painter, Opt.widget);

    QString Text = Index.data(Qt::DisplayRole).toString();
    QRect TextRect = Style->subElementRect(QStyle::SE_ItemViewItemText, &Opt, Opt.widget);
    TextRect.adjust(4, 0, -4, 0);

    QFont MonoFont("Consolas", 10);
    MonoFont.setStyleHint(QFont::Monospace);
    Painter->setFont(MonoFont);

    if (Index.column() == DisasmModel::ColMnemonic) {
        PaintMnemonic(Painter, Opt, Text);
    } else {
        PaintOperands(Painter, Opt, Text);
    }

    Painter->restore();
}

void DisasmHighlightDelegate::PaintMnemonic(QPainter* Painter, const QStyleOptionViewItem& Option,
                                             const QString& Text) const {
    QStyle* Style = Option.widget ? Option.widget->style() : QApplication::style();
    QRect TextRect = Style->subElementRect(QStyle::SE_ItemViewItemText, &Option, Option.widget);
    TextRect.adjust(4, 0, -4, 0);

    QString Lower = Text.toLower().trimmed();
    QColor TextColor;

    if (Lower.startsWith("j") || Lower == "call" || Lower == "loop" ||
        Lower == "loope" || Lower == "loopne") {
        TextColor = ColorJumpCall;
    } else if (Lower == "ret" || Lower == "retn" || Lower == "retf" ||
               Lower == "nop" || Lower == "int3") {
        TextColor = ColorRetNop;
    } else {
        TextColor = ColorDefault;
    }

    if (Option.state & QStyle::State_Selected)
        TextColor = Option.palette.highlightedText().color();

    Painter->setPen(TextColor);
    Painter->drawText(TextRect, Qt::AlignLeft | Qt::AlignVCenter, Text);
}

void DisasmHighlightDelegate::PaintOperands(QPainter* Painter, const QStyleOptionViewItem& Option,
                                             const QString& Text) const {
    QStyle* Style = Option.widget ? Option.widget->style() : QApplication::style();
    QRect TextRect = Style->subElementRect(QStyle::SE_ItemViewItemText, &Option, Option.widget);
    TextRect.adjust(4, 0, -4, 0);

    if (Option.state & QStyle::State_Selected) {
        Painter->setPen(Option.palette.highlightedText().color());
        Painter->drawText(TextRect, Qt::AlignLeft | Qt::AlignVCenter, Text);
        return;
    }

    QFontMetrics Fm(Painter->font());
    int X = TextRect.left();
    int Y = TextRect.top() + (TextRect.height() + Fm.ascent() - Fm.descent()) / 2;

    int BracketDepth = 0;
    QString CurrentToken;

    auto FlushToken = [&]() {
        if (CurrentToken.isEmpty())
            return;

        QColor TokenColor;
        if (BracketDepth > 0) {
            TokenColor = ColorMemory;
        } else if (IsRegister(CurrentToken.toLower())) {
            TokenColor = ColorRegister;
        } else if (IsHexNumber(CurrentToken)) {
            TokenColor = ColorImmediate;
        } else {
            TokenColor = ColorDefault;
        }

        Painter->setPen(TokenColor);
        Painter->drawText(X, Y, CurrentToken);
        X += Fm.horizontalAdvance(CurrentToken);
        CurrentToken.clear();
    };

    for (int I = 0; I < Text.size(); ++I) {
        QChar Ch = Text[I];

        if (Ch == '[') {
            FlushToken();
            BracketDepth++;
            Painter->setPen(ColorMemory);
            Painter->drawText(X, Y, QString(Ch));
            X += Fm.horizontalAdvance(Ch);
        } else if (Ch == ']') {
            FlushToken();
            Painter->setPen(ColorMemory);
            Painter->drawText(X, Y, QString(Ch));
            X += Fm.horizontalAdvance(Ch);
            BracketDepth--;
        } else if (Ch == ',' || Ch == ' ' || Ch == '+' || Ch == '-' || Ch == '*' || Ch == ':') {
            FlushToken();
            QColor SepColor = (BracketDepth > 0) ? ColorMemory : ColorDefault;
            Painter->setPen(SepColor);
            Painter->drawText(X, Y, QString(Ch));
            X += Fm.horizontalAdvance(Ch);
        } else {
            CurrentToken.append(Ch);
        }
    }
    FlushToken();
}

bool DisasmHighlightDelegate::IsRegister(const QString& Token) const {
    return RegisterNames.contains(Token);
}

bool DisasmHighlightDelegate::IsHexNumber(const QString& Token) const {
    if (Token.isEmpty())
        return false;

    if (Token.startsWith("0x") || Token.startsWith("0X")) {
        static QRegularExpression HexRe("^0[xX][0-9a-fA-F]+$");
        return HexRe.match(Token).hasMatch();
    }

    static QRegularExpression NumRe("^-?[0-9][0-9a-fA-F]*h?$");
    return NumRe.match(Token).hasMatch();
}

DisasmWidget::DisasmWidget(QWidget* Parent)
    : QWidget(Parent)
    , TreeView(new QTreeView(this))
    , Model(new DisasmModel(this))
    , HighlightDelegate(new DisasmHighlightDelegate(this))
    , Engine(nullptr)
    , CorePtr(nullptr)
    , AnalysisDb(nullptr)
    , AddressInput(new QLineEdit(this))
    , GoButton(new QPushButton("Go", this))
    , BackButton(new QPushButton("<", this))
    , ForwardButton(new QPushButton(">", this))
    , CurrentAddress(0) {

    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(0, 0, 0, 0);
    MainLayout->setSpacing(0);

    auto* ToolbarLayout = new QHBoxLayout();
    ToolbarLayout->setContentsMargins(4, 4, 4, 4);
    ToolbarLayout->setSpacing(4);

    BackButton->setFixedWidth(30);
    ForwardButton->setFixedWidth(30);
    BackButton->setEnabled(false);
    ForwardButton->setEnabled(false);

    AddressInput->setPlaceholderText("Address (hex)");
    AddressInput->setFixedWidth(200);

    QFont MonoFont("Consolas", 10);
    MonoFont.setStyleHint(QFont::Monospace);
    AddressInput->setFont(MonoFont);

    ToolbarLayout->addWidget(BackButton);
    ToolbarLayout->addWidget(ForwardButton);
    ToolbarLayout->addWidget(AddressInput);
    ToolbarLayout->addWidget(GoButton);
    ToolbarLayout->addStretch();

    MainLayout->addLayout(ToolbarLayout);

    TreeView->setModel(Model);
    TreeView->setItemDelegate(HighlightDelegate);
    TreeView->setRootIsDecorated(false);
    TreeView->setAlternatingRowColors(true);
    TreeView->setSelectionBehavior(QAbstractItemView::SelectRows);
    TreeView->setSelectionMode(QAbstractItemView::SingleSelection);
    TreeView->setFont(MonoFont);
    TreeView->setUniformRowHeights(true);

    auto* Header = TreeView->header();
    Header->setStretchLastSection(true);
    Header->setSectionResizeMode(DisasmModel::ColAddress, QHeaderView::ResizeToContents);
    Header->setSectionResizeMode(DisasmModel::ColBytes, QHeaderView::ResizeToContents);
    Header->setSectionResizeMode(DisasmModel::ColMnemonic, QHeaderView::ResizeToContents);
    Header->setSectionResizeMode(DisasmModel::ColOperands, QHeaderView::Stretch);
    Header->setSectionResizeMode(DisasmModel::ColComment, QHeaderView::Stretch);

    MainLayout->addWidget(TreeView);

    connect(GoButton, &QPushButton::clicked, this, &DisasmWidget::OnGoClicked);
    connect(AddressInput, &QLineEdit::returnPressed, this, &DisasmWidget::OnGoClicked);
    connect(BackButton, &QPushButton::clicked, this, &DisasmWidget::GoBack);
    connect(ForwardButton, &QPushButton::clicked, this, &DisasmWidget::GoForward);
    connect(TreeView, &QTreeView::doubleClicked, this, &DisasmWidget::OnItemDoubleClicked);

    Model->SetFormatMap(&OperandFormats);
    Model->SetStackVarMap(&StackVarNames, 0);

    TreeView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(TreeView, &QTreeView::customContextMenuRequested, this, &DisasmWidget::ShowContextMenu);

    auto* ShortcutH = new QShortcut(QKeySequence(Qt::Key_H), TreeView);
    connect(ShortcutH, &QShortcut::activated, this, [this]() {
        QModelIndex Idx = TreeView->currentIndex();
        if (!Idx.isValid()) return;
        DisasmInstruction Instr = Model->GetInstruction(Idx.row());
        int OperandIdx = DetectOperandIndexAtColumn(Idx, QPoint());
        SetOperandFormat(Instr.Location, OperandIdx, OperandFormat::Hex);
    });

    auto* ShortcutD = new QShortcut(QKeySequence(Qt::Key_D), TreeView);
    connect(ShortcutD, &QShortcut::activated, this, [this]() {
        QModelIndex Idx = TreeView->currentIndex();
        if (!Idx.isValid()) return;
        DisasmInstruction Instr = Model->GetInstruction(Idx.row());
        int OperandIdx = DetectOperandIndexAtColumn(Idx, QPoint());
        SetOperandFormat(Instr.Location, OperandIdx, OperandFormat::Decimal);
    });

    auto* ShortcutO = new QShortcut(QKeySequence(Qt::Key_O), TreeView);
    connect(ShortcutO, &QShortcut::activated, this, [this]() {
        QModelIndex Idx = TreeView->currentIndex();
        if (!Idx.isValid()) return;
        DisasmInstruction Instr = Model->GetInstruction(Idx.row());
        int OperandIdx = DetectOperandIndexAtColumn(Idx, QPoint());
        SetOperandFormat(Instr.Location, OperandIdx, OperandFormat::Octal);
    });

    auto* ShortcutB = new QShortcut(QKeySequence(Qt::Key_B), TreeView);
    connect(ShortcutB, &QShortcut::activated, this, [this]() {
        QModelIndex Idx = TreeView->currentIndex();
        if (!Idx.isValid()) return;
        DisasmInstruction Instr = Model->GetInstruction(Idx.row());
        int OperandIdx = DetectOperandIndexAtColumn(Idx, QPoint());
        SetOperandFormat(Instr.Location, OperandIdx, OperandFormat::Binary);
    });
}

DisasmWidget::~DisasmWidget() {
    delete Engine;
}

void DisasmWidget::SetCore(ICore* Core) {
    CorePtr = Core;
}

void DisasmWidget::SetAnalysisDatabase(AnalysisDatabase* Db) {
    AnalysisDb = Db;
}

void DisasmWidget::NavigateTo(Address Addr) {
    if (CurrentAddress != 0) {
        HistoryBack.append(CurrentAddress);
    }
    HistoryForward.clear();

    CurrentAddress = Addr;
    AddressInput->setText(QString("%1").arg(Addr, 16, 16, QChar('0')).toUpper());

    BackButton->setEnabled(!HistoryBack.isEmpty());
    ForwardButton->setEnabled(false);

    DisassembleAt(Addr);

    if (AnalysisDb) {
        AnalyzedFunction Func = AnalysisDb->GetFunctionContaining(Addr);
        if (Func.Start != 0) {
            ResolveStackVariables(Func.Start);
            Model->SetStackVarMap(&StackVarNames, Func.Start);
        } else {
            Model->SetStackVarMap(&StackVarNames, 0);
        }
    }
}

void DisasmWidget::GoBack() {
    if (HistoryBack.isEmpty())
        return;

    HistoryForward.append(CurrentAddress);
    CurrentAddress = HistoryBack.takeLast();
    AddressInput->setText(QString("%1").arg(CurrentAddress, 16, 16, QChar('0')).toUpper());

    BackButton->setEnabled(!HistoryBack.isEmpty());
    ForwardButton->setEnabled(!HistoryForward.isEmpty());

    DisassembleAt(CurrentAddress);
}

void DisasmWidget::GoForward() {
    if (HistoryForward.isEmpty())
        return;

    HistoryBack.append(CurrentAddress);
    CurrentAddress = HistoryForward.takeLast();
    AddressInput->setText(QString("%1").arg(CurrentAddress, 16, 16, QChar('0')).toUpper());

    BackButton->setEnabled(!HistoryBack.isEmpty());
    ForwardButton->setEnabled(!HistoryForward.isEmpty());

    DisassembleAt(CurrentAddress);
}

void DisasmWidget::Refresh() {
    if (CurrentAddress != 0)
        DisassembleAt(CurrentAddress);
}

void DisasmWidget::OnProcessAttached(const ProcessInfo& Info) {
    NavigateTo(Info.BaseAddress);
}

void DisasmWidget::OnProcessDetached() {
    Model->Clear();
    HistoryBack.clear();
    HistoryForward.clear();
    CurrentAddress = 0;
    AddressInput->clear();
    BackButton->setEnabled(false);
    ForwardButton->setEnabled(false);

    delete Engine;
    Engine = nullptr;
}

void DisasmWidget::DisassembleAt(Address Addr, size_t NumBytes) {
    if (AnalysisDb && AnalysisDb->HasInstruction(Addr)) {
        DisassembleFromDatabase(Addr);
        return;
    }

    if (!CorePtr || !CorePtr->IsAttached()) {
        if (AnalysisDb) {
            DisassembleFromDatabase(Addr);
        }
        return;
    }

    QByteArray Buffer(static_cast<int>(NumBytes), 0);
    if (!CorePtr->ReadMemory(Addr, Buffer.data(), NumBytes)) {
        if (AnalysisDb) {
            DisassembleFromDatabase(Addr);
            return;
        }
        CorePtr->Log(QString("Failed to read memory at 0x%1").arg(Addr, 16, 16, QChar('0')), LogLevel::Error);
        return;
    }

    if (!Engine) {
        Engine = new Disassembler();
    }

    Architecture Arch = CorePtr->CurrentProcess().Arch;
    Engine->SetArchitecture(Arch);

    QList<DisasmInstruction> Results = Engine->Disassemble(Buffer, Addr);

    Model->SetInstructions(Results);
}

void DisasmWidget::DisassembleFromDatabase(Address Addr, size_t NumInsns) {
    if (!AnalysisDb) return;

    QList<AnalyzedInstruction> AnalyzedInsns = AnalysisDb->GetInstructions(Addr, Addr + 0x10000);

    QList<DisasmInstruction> Results;
    size_t Count = 0;

    for (const auto& Ai : AnalyzedInsns) {
        if (Count >= NumInsns) break;

        DisasmInstruction Di;
        Di.Location = Ai.Addr;
        Di.Bytes = QByteArray(reinterpret_cast<const char*>(Ai.Bytes), Ai.Size);
        Di.Mnemonic = Ai.Mnemonic;
        Di.Operands = Ai.Operands;
        Di.Comment = Ai.Comment;

        QString Name = AnalysisDb->GetName(Ai.Addr);
        if (!Name.isEmpty() && Di.Comment.isEmpty()) {
            Di.Comment = Name;
        }

        if (Ai.IsCall && Ai.BranchTarget != 0) {
            QString TargetName = AnalysisDb->GetName(Ai.BranchTarget);
            if (!TargetName.isEmpty()) {
                Di.Comment = TargetName;
            }
        }

        if (Ai.IsJump && Ai.BranchTarget != 0) {
            QString TargetName = AnalysisDb->GetName(Ai.BranchTarget);
            if (!TargetName.isEmpty() && Di.Comment.isEmpty()) {
                Di.Comment = TargetName;
            }
        }

        Results.append(Di);
        Count++;
    }

    AnalyzedFunction Func = AnalysisDb->GetFunctionContaining(Addr);
    if (Func.Start != 0) {
        ResolveStackVariables(Func.Start);
        Model->SetStackVarMap(&StackVarNames, Func.Start);
    } else {
        Model->SetStackVarMap(&StackVarNames, 0);
    }

    Model->SetInstructions(Results);
}

void DisasmWidget::OnItemDoubleClicked(const QModelIndex& Index) {
    if (!Index.isValid())
        return;

    DisasmInstruction Instr = Model->GetInstruction(Index.row());
    QString MnemonicLower = Instr.Mnemonic.toLower().trimmed();

    bool IsJump = MnemonicLower.startsWith("j") || MnemonicLower == "call" ||
                  MnemonicLower == "loop" || MnemonicLower == "loope" ||
                  MnemonicLower == "loopne";

    if (!IsJump)
        return;

    QString OperandStr = Instr.Operands.trimmed();

    if (OperandStr.startsWith("0x") || OperandStr.startsWith("0X")) {
        OperandStr = OperandStr.mid(2);
    }

    bool Ok = false;
    Address Target = OperandStr.toULongLong(&Ok, 16);

    if (Ok && Target != 0) {
        NavigateTo(Target);
    }
}

void DisasmWidget::OnGoClicked() {
    QString Text = AddressInput->text().trimmed();
    if (Text.isEmpty())
        return;

    if (Text.startsWith("0x") || Text.startsWith("0X"))
        Text = Text.mid(2);

    bool Ok = false;
    Address Addr = Text.toULongLong(&Ok, 16);

    if (Ok) {
        NavigateTo(Addr);
    }
}

void DisasmWidget::SetOperandFormat(Address Addr, int OperandIdx, OperandFormat Fmt) {
    if (Fmt == OperandFormat::Default) {
        if (OperandFormats.contains(Addr)) {
            OperandFormats[Addr].remove(OperandIdx);
            if (OperandFormats[Addr].isEmpty())
                OperandFormats.remove(Addr);
        }
    } else {
        OperandFormats[Addr][OperandIdx] = Fmt;
    }

    Refresh();
}

QString DisasmWidget::FormatImmediate(int64_t Value, OperandFormat Fmt) const {
    switch (Fmt) {
    case OperandFormat::Hex:
        return QString("0x%1").arg(static_cast<uint64_t>(Value), 0, 16).toUpper();
    case OperandFormat::Decimal:
        return QString::number(Value);
    case OperandFormat::Octal:
        return QString("0%1").arg(static_cast<uint64_t>(Value), 0, 8);
    case OperandFormat::Binary:
        return QString("%1b").arg(static_cast<uint64_t>(Value), 0, 2);
    case OperandFormat::Char: {
        uint64_t UVal = static_cast<uint64_t>(Value);
        QString CharRepr;
        bool AllPrintable = true;
        if (UVal == 0) {
            return QString("'\\0'");
        }
        while (UVal > 0) {
            char Ch = static_cast<char>(UVal & 0xFF);
            if (Ch >= 0x20 && Ch <= 0x7E) {
                CharRepr.prepend(QChar(Ch));
            } else {
                AllPrintable = false;
                break;
            }
            UVal >>= 8;
        }
        if (AllPrintable && !CharRepr.isEmpty())
            return QString("'%1'").arg(CharRepr);
        return QString("0x%1").arg(static_cast<uint64_t>(Value), 0, 16).toUpper();
    }
    case OperandFormat::Offset: {
        if (AnalysisDb) {
            Address Target = static_cast<Address>(Value);
            QString Name = AnalysisDb->GetName(Target);
            if (!Name.isEmpty())
                return Name;

            AnalyzedFunction Func = AnalysisDb->GetFunctionContaining(Target);
            if (Func.Start != 0) {
                QString FuncName = Func.Name.isEmpty() ?
                    QString("sub_%1").arg(Func.Start, 0, 16).toUpper() : Func.Name;
                int64_t Delta = static_cast<int64_t>(Target - Func.Start);
                if (Delta > 0)
                    return QString("%1+0x%2").arg(FuncName).arg(static_cast<uint64_t>(Delta), 0, 16).toUpper();
                return FuncName;
            }

            const Segment* Seg = AnalysisDb->GetSegmentAt(Target);
            if (Seg) {
                uint64_t SegOffset = Target - Seg->VirtualAddress;
                return QString("%1:0x%2").arg(Seg->Name).arg(SegOffset, 0, 16).toUpper();
            }
        }
        return QString("0x%1").arg(static_cast<uint64_t>(Value), 0, 16).toUpper();
    }
    default:
        return QString("0x%1").arg(static_cast<uint64_t>(Value), 0, 16).toUpper();
    }
}

void DisasmWidget::ResolveStackVariables(Address FuncAddr) {
    if (!AnalysisDb) return;

    AnalyzedFunction Func = AnalysisDb->GetFunctionContaining(FuncAddr);
    if (Func.Start == 0) return;

    if (StackVarNames.contains(Func.Start)) return;

    QList<AnalyzedInstruction> FuncInsns = AnalysisDb->GetInstructions(Func.Start, Func.End);

    QMap<int, QString> VarMap;
    int FrameSize = 0;
    bool UsesFramePointer = false;

    static QRegularExpression SubRspRe(
        "rsp,\\s*0x([0-9a-fA-F]+)",
        QRegularExpression::CaseInsensitiveOption);
    static QRegularExpression RbpNegRe(
        "\\[rbp\\s*-\\s*0x([0-9a-fA-F]+)\\]",
        QRegularExpression::CaseInsensitiveOption);
    static QRegularExpression RbpPosRe(
        "\\[rbp\\s*\\+\\s*0x([0-9a-fA-F]+)\\]",
        QRegularExpression::CaseInsensitiveOption);
    static QRegularExpression RspPosRe(
        "\\[rsp\\s*\\+\\s*0x([0-9a-fA-F]+)\\]",
        QRegularExpression::CaseInsensitiveOption);

    QSet<int> RbpNegOffsets;
    QSet<int> RbpPosOffsets;
    QSet<int> RspPosOffsets;

    for (const auto& Insn : FuncInsns) {
        QString Mn = Insn.Mnemonic.toLower().trimmed();
        QString Ops = Insn.Operands.toLower().trimmed();

        if (Mn == "mov" && Ops == "rbp, rsp")
            UsesFramePointer = true;

        if (Mn == "sub") {
            QRegularExpressionMatch M = SubRspRe.match(Ops);
            if (M.hasMatch()) {
                bool Ok = false;
                int Val = M.captured(1).toInt(&Ok, 16);
                if (Ok && Val > FrameSize)
                    FrameSize = Val;
            }
        }

        {
            QRegularExpressionMatchIterator It = RbpNegRe.globalMatch(Insn.Operands);
            while (It.hasNext()) {
                QRegularExpressionMatch M = It.next();
                bool Ok = false;
                int Off = M.captured(1).toInt(&Ok, 16);
                if (Ok) RbpNegOffsets.insert(Off);
            }
        }

        {
            QRegularExpressionMatchIterator It = RbpPosRe.globalMatch(Insn.Operands);
            while (It.hasNext()) {
                QRegularExpressionMatch M = It.next();
                bool Ok = false;
                int Off = M.captured(1).toInt(&Ok, 16);
                if (Ok) RbpPosOffsets.insert(Off);
            }
        }

        {
            QRegularExpressionMatchIterator It = RspPosRe.globalMatch(Insn.Operands);
            while (It.hasNext()) {
                QRegularExpressionMatch M = It.next();
                bool Ok = false;
                int Off = M.captured(1).toInt(&Ok, 16);
                if (Ok) RspPosOffsets.insert(Off);
            }
        }
    }

    Q_UNUSED(UsesFramePointer);

    for (int Off : RbpNegOffsets) {
        int Key = -Off;
        VarMap[Key] = QString("var_%1").arg(Off, 0, 16).toUpper();
    }

    int ArgIdx = 0;
    QList<int> SortedRbpPos(RbpPosOffsets.begin(), RbpPosOffsets.end());
    std::sort(SortedRbpPos.begin(), SortedRbpPos.end());
    for (int Off : SortedRbpPos) {
        if (Off > 0x8) {
            VarMap[Off] = QString("arg_%1").arg(ArgIdx);
            ArgIdx++;
        } else if (Off > 0) {
            VarMap[Off] = QString("var_%1").arg(Off, 0, 16).toUpper();
        }
    }

    ArgIdx = 0;
    QList<int> SortedRspPos(RspPosOffsets.begin(), RspPosOffsets.end());
    std::sort(SortedRspPos.begin(), SortedRspPos.end());
    for (int Off : SortedRspPos) {
        int Key = 0x10000 + Off;
        if (FrameSize > 0 && Off >= FrameSize) {
            VarMap[Key] = QString("arg_%1").arg(ArgIdx);
            ArgIdx++;
        } else {
            VarMap[Key] = QString("var_%1").arg(Off, 0, 16).toUpper();
        }
    }

    StackVarNames[Func.Start] = VarMap;
}

QString DisasmWidget::SubstituteStackVars(const QString& Operands, Address InstrAddr) const {
    if (StackVarNames.isEmpty() || !AnalysisDb)
        return Operands;

    Address FuncAddr = 0;
    for (auto It = StackVarNames.constBegin(); It != StackVarNames.constEnd(); ++It) {
        AnalyzedFunction Func = AnalysisDb->GetFunction(It.key());
        if (Func.Start != 0 && InstrAddr >= Func.Start && InstrAddr < Func.End) {
            FuncAddr = It.key();
            break;
        }
    }
    if (FuncAddr == 0)
        return Operands;

    const QMap<int, QString>& VarMap = StackVarNames[FuncAddr];
    if (VarMap.isEmpty())
        return Operands;

    static QRegularExpression StackRefRe(
        "\\[(rbp|rsp)\\s*([+-])\\s*0x([0-9a-fA-F]+)\\]",
        QRegularExpression::CaseInsensitiveOption);

    QString Result = Operands;
    QRegularExpressionMatchIterator It = StackRefRe.globalMatch(Result);
    QList<QPair<int, int>> MatchPositions;
    QList<QString> Replacements;

    while (It.hasNext()) {
        QRegularExpressionMatch M = It.next();
        QString Reg = M.captured(1).toLower();
        QString Sign = M.captured(2);
        bool Ok = false;
        int Off = M.captured(3).toInt(&Ok, 16);
        if (!Ok) continue;

        int Key = 0;
        if (Reg == "rbp") {
            Key = (Sign == "-") ? -Off : Off;
        } else {
            Key = 0x10000 + Off;
        }

        if (VarMap.contains(Key)) {
            QString VarName = VarMap[Key];
            QString Replacement = QString("[%1 + %2]").arg(Reg, VarName);
            MatchPositions.append({M.capturedStart(), M.capturedLength()});
            Replacements.append(Replacement);
        }
    }

    for (int I = MatchPositions.size() - 1; I >= 0; --I) {
        Result.replace(MatchPositions[I].first, MatchPositions[I].second, Replacements[I]);
    }

    return Result;
}

void DisasmWidget::ShowContextMenu(const QPoint& Pos) {
    QModelIndex Index = TreeView->indexAt(Pos);
    if (!Index.isValid())
        return;

    DisasmInstruction Instr = Model->GetInstruction(Index.row());

    QMenu ContextMenu(this);

    QAction* CopyAddress = ContextMenu.addAction("Copy Address");
    connect(CopyAddress, &QAction::triggered, this, [Instr]() {
        QString AddrStr = QString("0x%1").arg(Instr.Location, 16, 16, QChar('0')).toUpper();
        QApplication::clipboard()->setText(AddrStr);
    });

    QAction* CopyInstruction = ContextMenu.addAction("Copy Instruction");
    connect(CopyInstruction, &QAction::triggered, this, [Instr]() {
        QString Full = QString("%1 %2").arg(Instr.Mnemonic, Instr.Operands);
        QApplication::clipboard()->setText(Full.trimmed());
    });

    ContextMenu.addSeparator();

    int OperandIdx = DetectOperandIndexAtColumn(Index, Pos);
    QMenu* NumberFormatMenu = ContextMenu.addMenu("Number Format");
    BuildNumberFormatMenu(NumberFormatMenu, Instr.Location, OperandIdx);

    ContextMenu.addSeparator();

    QAction* AddCommentAction = ContextMenu.addAction("Add Comment");
    connect(AddCommentAction, &QAction::triggered, this, [this, Instr]() {
        if (!AnalysisDb) return;
        AnalysisDb->SetComment(Instr.Location, "");
        Refresh();
    });

    QAction* GoToRef = ContextMenu.addAction("Go to Reference");
    connect(GoToRef, &QAction::triggered, this, [this, Instr]() {
        QString OperandStr = Instr.Operands.trimmed();
        if (OperandStr.startsWith("0x") || OperandStr.startsWith("0X"))
            OperandStr = OperandStr.mid(2);
        bool Ok = false;
        Address Target = OperandStr.toULongLong(&Ok, 16);
        if (Ok && Target != 0)
            NavigateTo(Target);
    });

    ContextMenu.exec(TreeView->viewport()->mapToGlobal(Pos));
}

void DisasmWidget::BuildNumberFormatMenu(QMenu* ParentMenu, Address Addr, int OperandIdx) {
    OperandFormat CurrentFmt = OperandFormat::Default;
    if (OperandFormats.contains(Addr) && OperandFormats[Addr].contains(OperandIdx))
        CurrentFmt = OperandFormats[Addr][OperandIdx];

    auto AddFormatAction = [&](const QString& Label, OperandFormat Fmt) {
        QAction* Action = ParentMenu->addAction(Label);
        Action->setCheckable(true);
        Action->setChecked(CurrentFmt == Fmt);
        connect(Action, &QAction::triggered, this, [this, Addr, OperandIdx, Fmt]() {
            SetOperandFormat(Addr, OperandIdx, Fmt);
        });
    };

    AddFormatAction("Default", OperandFormat::Default);
    ParentMenu->addSeparator();
    AddFormatAction("Hex (H)", OperandFormat::Hex);
    AddFormatAction("Decimal (D)", OperandFormat::Decimal);
    AddFormatAction("Octal (O)", OperandFormat::Octal);
    AddFormatAction("Binary (B)", OperandFormat::Binary);
    AddFormatAction("Char", OperandFormat::Char);
    AddFormatAction("Offset", OperandFormat::Offset);
}

int DisasmWidget::DetectOperandIndexAtColumn(const QModelIndex& Index, const QPoint& Pos) const {
    Q_UNUSED(Pos);
    if (!Index.isValid())
        return 0;

    if (Index.column() != DisasmModel::ColOperands)
        return 0;

    return 0;
}

}
