#include "RegisterWidget.h"
#include <QHeaderView>
#include <QLineEdit>
#include <QInputDialog>
#include <QFont>

namespace Fidra {

RegisterWidget::RegisterWidget(QWidget* Parent)
    : QWidget(Parent)
    , EngineRef(nullptr)
    , Layout(new QVBoxLayout(this))
    , Tree(new QTreeWidget(this))
    , GpGroup(nullptr)
    , FlagsGroup(nullptr)
    , SegmentGroup(nullptr)
    , XmmGroup(nullptr)
    , PreviousRegisters{}
    , HasPrevious(false)
{
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(0);

    Tree->setColumnCount(2);
    Tree->setHeaderLabels({"Register", "Value"});
    Tree->setAlternatingRowColors(true);
    Tree->setRootIsDecorated(true);
    Tree->setSelectionMode(QAbstractItemView::SingleSelection);
    Tree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    Tree->header()->setStretchLastSection(true);
    Tree->header()->resizeSection(0, 100);

    QFont MonoFont("Consolas", 9);
    MonoFont.setStyleHint(QFont::Monospace);
    Tree->setFont(MonoFont);

    Layout->addWidget(Tree);

    BuildTree();

    connect(Tree, &QTreeWidget::itemDoubleClicked, this, &RegisterWidget::OnItemDoubleClicked);
}

void RegisterWidget::SetEngine(DebugEngine* Engine) {
    if (EngineRef) {
        disconnect(EngineRef, nullptr, this, nullptr);
    }

    EngineRef = Engine;

    if (EngineRef) {
        connect(EngineRef, &DebugEngine::RegistersChanged, this, &RegisterWidget::UpdateRegisters);
        connect(EngineRef, &DebugEngine::StateChanged, this, &RegisterWidget::OnStateChanged);
    }
}

void RegisterWidget::BuildTree() {
    Tree->clear();
    RegisterItems.clear();

    GpGroup = new QTreeWidgetItem(Tree, {"General Purpose", ""});
    GpGroup->setExpanded(true);

    QStringList GpNames = {"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
                           "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP"};
    for (const auto& Name : GpNames) {
        auto* Item = new QTreeWidgetItem(GpGroup, {Name, "0x0000000000000000"});
        RegisterItems[Name] = Item;
    }

    FlagsGroup = new QTreeWidgetItem(Tree, {"Flags", ""});
    FlagsGroup->setExpanded(false);

    auto* RflagsItem = new QTreeWidgetItem(FlagsGroup, {"RFLAGS", "0x0000000000000000"});
    RegisterItems["RFLAGS"] = RflagsItem;

    QStringList FlagBitNames = {"CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF"};
    for (const auto& Name : FlagBitNames) {
        auto* Item = new QTreeWidgetItem(RflagsItem, {Name, "0"});
        RegisterItems["FLAG_" + Name] = Item;
    }

    SegmentGroup = new QTreeWidgetItem(Tree, {"Segment", ""});
    SegmentGroup->setExpanded(false);

    QStringList SegNames = {"CS", "DS", "ES", "FS", "GS", "SS"};
    for (const auto& Name : SegNames) {
        auto* Item = new QTreeWidgetItem(SegmentGroup, {Name, "0x0000"});
        RegisterItems[Name] = Item;
    }

    XmmGroup = new QTreeWidgetItem(Tree, {"XMM", ""});
    XmmGroup->setExpanded(false);

    for (int I = 0; I < 16; ++I) {
        QString Name = QString("XMM%1").arg(I);
        auto* Item = new QTreeWidgetItem(XmmGroup, {Name, "0x00000000000000000000000000000000"});
        RegisterItems[Name] = Item;
    }
}

void RegisterWidget::SetRegisterValue(QTreeWidgetItem* Item, const QString& Name, uint64_t Value, uint64_t PrevValue, bool Is16Bit) {
    Q_UNUSED(Name);
    QString HexStr;
    if (Is16Bit) {
        HexStr = QString("0x%1").arg(Value, 4, 16, QChar('0')).toUpper();
    } else {
        HexStr = QString("0x%1").arg(Value, 16, 16, QChar('0')).toUpper();
    }

    Item->setText(1, HexStr);

    if (HasPrevious && Value != PrevValue) {
        Item->setForeground(1, QBrush(QColor(255, 50, 50)));
    } else {
        Item->setForeground(1, QBrush(Tree->palette().color(QPalette::Text)));
    }
}

void RegisterWidget::UpdateFlagBits(QTreeWidgetItem* FlagsItem, uint64_t Rflags, uint64_t PrevRflags) {
    struct FlagBit {
        QString Name;
        int Bit;
    };

    QList<FlagBit> Flags = {
        {"CF", 0}, {"PF", 2}, {"AF", 4}, {"ZF", 6},
        {"SF", 7}, {"TF", 8}, {"IF", 9}, {"DF", 10}, {"OF", 11}
    };

    for (const auto& Flag : Flags) {
        auto* Item = RegisterItems.value("FLAG_" + Flag.Name, nullptr);
        if (!Item) continue;

        uint64_t CurrentBit = (Rflags >> Flag.Bit) & 1;
        uint64_t PrevBit = (PrevRflags >> Flag.Bit) & 1;

        Item->setText(1, QString::number(CurrentBit));

        if (HasPrevious && CurrentBit != PrevBit) {
            Item->setForeground(1, QBrush(QColor(255, 50, 50)));
        } else {
            Item->setForeground(1, QBrush(Tree->palette().color(QPalette::Text)));
        }
    }

    Q_UNUSED(FlagsItem);
}

void RegisterWidget::UpdateRegisters() {
    if (!EngineRef) return;
    if (EngineRef->CurrentState() != DebugState::Paused) return;

    RegisterSet Regs = EngineRef->GetRegisters();

    auto SetGp = [&](const QString& Name, uint64_t Val, uint64_t Prev) {
        if (auto* Item = RegisterItems.value(Name, nullptr))
            SetRegisterValue(Item, Name, Val, Prev);
    };

    SetGp("RAX", Regs.Rax, PreviousRegisters.Rax);
    SetGp("RBX", Regs.Rbx, PreviousRegisters.Rbx);
    SetGp("RCX", Regs.Rcx, PreviousRegisters.Rcx);
    SetGp("RDX", Regs.Rdx, PreviousRegisters.Rdx);
    SetGp("RSI", Regs.Rsi, PreviousRegisters.Rsi);
    SetGp("RDI", Regs.Rdi, PreviousRegisters.Rdi);
    SetGp("RBP", Regs.Rbp, PreviousRegisters.Rbp);
    SetGp("RSP", Regs.Rsp, PreviousRegisters.Rsp);
    SetGp("R8",  Regs.R8,  PreviousRegisters.R8);
    SetGp("R9",  Regs.R9,  PreviousRegisters.R9);
    SetGp("R10", Regs.R10, PreviousRegisters.R10);
    SetGp("R11", Regs.R11, PreviousRegisters.R11);
    SetGp("R12", Regs.R12, PreviousRegisters.R12);
    SetGp("R13", Regs.R13, PreviousRegisters.R13);
    SetGp("R14", Regs.R14, PreviousRegisters.R14);
    SetGp("R15", Regs.R15, PreviousRegisters.R15);
    SetGp("RIP", Regs.Rip, PreviousRegisters.Rip);

    SetGp("RFLAGS", Regs.Rflags, PreviousRegisters.Rflags);
    if (auto* RflagsItem = RegisterItems.value("RFLAGS", nullptr)) {
        UpdateFlagBits(RflagsItem, Regs.Rflags, PreviousRegisters.Rflags);
    }

    auto SetSeg = [&](const QString& Name, uint16_t Val, uint16_t Prev) {
        if (auto* Item = RegisterItems.value(Name, nullptr))
            SetRegisterValue(Item, Name, Val, Prev, true);
    };

    SetSeg("CS", Regs.Cs, PreviousRegisters.Cs);
    SetSeg("DS", Regs.Ds, PreviousRegisters.Ds);
    SetSeg("ES", Regs.Es, PreviousRegisters.Es);
    SetSeg("FS", Regs.Fs, PreviousRegisters.Fs);
    SetSeg("GS", Regs.Gs, PreviousRegisters.Gs);
    SetSeg("SS", Regs.Ss, PreviousRegisters.Ss);

    for (int I = 0; I < 16; ++I) {
        QString Name = QString("XMM%1").arg(I);
        auto* Item = RegisterItems.value(Name, nullptr);
        if (!Item) continue;

        auto& Xmm = Regs.XmmRegs[I];
        auto& PrevXmm = PreviousRegisters.XmmRegs[I];

        QString Val = QString("0x%1%2")
            .arg(Xmm.High, 16, 16, QChar('0'))
            .arg(Xmm.Low, 16, 16, QChar('0'))
            .toUpper();

        Item->setText(1, Val);

        if (HasPrevious && (Xmm.Low != PrevXmm.Low || Xmm.High != PrevXmm.High)) {
            Item->setForeground(1, QBrush(QColor(255, 50, 50)));
        } else {
            Item->setForeground(1, QBrush(Tree->palette().color(QPalette::Text)));
        }
    }

    PreviousRegisters = Regs;
    HasPrevious = true;
}

void RegisterWidget::OnStateChanged(DebugState NewState) {
    if (NewState == DebugState::Paused) {
        UpdateRegisters();
    } else if (NewState == DebugState::Idle || NewState == DebugState::Stopped) {
        ClearAll();
    }
}

void RegisterWidget::ClearAll() {
    for (auto It = RegisterItems.begin(); It != RegisterItems.end(); ++It) {
        if (It.key().startsWith("FLAG_")) {
            It.value()->setText(1, "0");
        } else if (It.key().length() == 2 && It.key() != "R8" && It.key() != "R9" &&
                   (It.key() == "CS" || It.key() == "DS" || It.key() == "ES" ||
                    It.key() == "FS" || It.key() == "GS" || It.key() == "SS")) {
            It.value()->setText(1, "0x0000");
        } else if (It.key().startsWith("XMM")) {
            It.value()->setText(1, "0x00000000000000000000000000000000");
        } else {
            It.value()->setText(1, "0x0000000000000000");
        }
        It.value()->setForeground(1, QBrush(Tree->palette().color(QPalette::Text)));
    }

    PreviousRegisters = {};
    HasPrevious = false;
}

void RegisterWidget::OnItemDoubleClicked(QTreeWidgetItem* Item, int Column) {
    if (Column != 1) return;
    if (!EngineRef) return;
    if (EngineRef->CurrentState() != DebugState::Paused) return;

    QString RegName = Item->text(0);

    if (RegName.isEmpty() || RegName == "General Purpose" || RegName == "Flags" ||
        RegName == "Segment" || RegName == "XMM") {
        return;
    }

    if (RegName.startsWith("FLAG_") || Item->parent() == RegisterItems.value("RFLAGS", nullptr)) {
        return;
    }

    if (RegName.startsWith("XMM")) {
        return;
    }

    QString CurrentVal = Item->text(1);
    bool Ok = false;

    QString Input = QInputDialog::getText(this, "Edit Register",
        QString("New value for %1:").arg(RegName), QLineEdit::Normal, CurrentVal, &Ok);

    if (!Ok || Input.isEmpty()) return;

    QString Cleaned = Input.trimmed();
    if (Cleaned.startsWith("0x", Qt::CaseInsensitive) || Cleaned.startsWith("0X")) {
        Cleaned = Cleaned.mid(2);
    }

    uint64_t NewValue = Cleaned.toULongLong(&Ok, 16);
    if (!Ok) return;

    EngineRef->SetRegister(RegName, NewValue);
    UpdateRegisters();
}

}
