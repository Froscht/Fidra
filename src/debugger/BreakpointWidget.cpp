#include "BreakpointWidget.h"
#include <QHeaderView>
#include <QMenu>
#include <QAction>
#include <QInputDialog>
#include <QMessageBox>
#include <QDialog>
#include <QFormLayout>
#include <QLineEdit>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QCheckBox>

namespace Fidra {

BreakpointWidget::BreakpointWidget(QWidget* Parent)
    : QWidget(Parent)
    , EngineRef(nullptr)
    , Layout(new QVBoxLayout(this))
    , ToolBar(nullptr)
    , Table(nullptr)
{
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(0);
    SetupToolBar();
    SetupTable();
    SetupContextMenu();
}

void BreakpointWidget::SetEngine(DebugEngine* Engine) {
    if (EngineRef) {
        disconnect(EngineRef, nullptr, this, nullptr);
    }
    EngineRef = Engine;
    if (EngineRef) {
        connect(EngineRef, &DebugEngine::BreakpointsChanged, this, &BreakpointWidget::UpdateBreakpoints);
        UpdateBreakpoints();
    }
}

void BreakpointWidget::SetupToolBar() {
    ToolBar = new QToolBar(this);
    ToolBar->setIconSize(QSize(16, 16));

    auto* AddAction = ToolBar->addAction("Add");
    AddAction->setIcon(style()->standardIcon(QStyle::SP_FileDialogNewFolder));
    connect(AddAction, &QAction::triggered, this, &BreakpointWidget::OnAddBreakpoint);

    auto* RemoveAction = ToolBar->addAction("Remove");
    RemoveAction->setIcon(style()->standardIcon(QStyle::SP_TrashIcon));
    connect(RemoveAction, &QAction::triggered, this, &BreakpointWidget::OnRemoveBreakpoint);

    ToolBar->addSeparator();

    auto* EnableAllAction = ToolBar->addAction("Enable All");
    connect(EnableAllAction, &QAction::triggered, this, &BreakpointWidget::OnEnableAll);

    auto* DisableAllAction = ToolBar->addAction("Disable All");
    connect(DisableAllAction, &QAction::triggered, this, &BreakpointWidget::OnDisableAll);

    ToolBar->addSeparator();

    auto* ClearAction = ToolBar->addAction("Clear All");
    ClearAction->setIcon(style()->standardIcon(QStyle::SP_DialogResetButton));
    connect(ClearAction, &QAction::triggered, this, &BreakpointWidget::OnClearAll);

    Layout->addWidget(ToolBar);
}

void BreakpointWidget::SetupTable() {
    Table = new QTableWidget(this);
    Table->setColumnCount(5);
    Table->setHorizontalHeaderLabels({"Enabled", "Address", "Type", "Hit Count", "Condition"});
    Table->horizontalHeader()->setStretchLastSection(true);
    Table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Interactive);
    Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    Table->setSelectionBehavior(QAbstractItemView::SelectRows);
    Table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    Table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    Table->verticalHeader()->hide();
    Table->setContextMenuPolicy(Qt::CustomContextMenu);
    Table->setAlternatingRowColors(true);
    Table->setColumnWidth(1, 160);

    Layout->addWidget(Table);
}

void BreakpointWidget::SetupContextMenu() {
    connect(Table, &QTableWidget::customContextMenuRequested, this, &BreakpointWidget::OnContextMenu);

    connect(Table, &QTableWidget::itemChanged, this, [this](QTableWidgetItem* Item) {
        if (!EngineRef || Item->column() != 0) return;
        auto Addr = static_cast<Address>(Item->data(Qt::UserRole).toULongLong());
        bool Enabled = (Item->checkState() == Qt::Checked);
        EngineRef->EnableBreakpoint(Addr, Enabled);
    });
}

void BreakpointWidget::UpdateBreakpoints() {
    if (!EngineRef) return;

    Table->blockSignals(true);

    auto Breakpoints = EngineRef->GetBreakpoints();

    Table->setRowCount(Breakpoints.size());

    for (int Row = 0; Row < Breakpoints.size(); ++Row) {
        auto& Bp = Breakpoints[Row];

        auto* CheckItem = new QTableWidgetItem();
        CheckItem->setFlags(CheckItem->flags() | Qt::ItemIsUserCheckable);
        CheckItem->setCheckState(Bp.Enabled ? Qt::Checked : Qt::Unchecked);
        CheckItem->setData(Qt::UserRole, static_cast<qulonglong>(Bp.Location));
        Table->setItem(Row, 0, CheckItem);

        auto* AddrItem = new QTableWidgetItem(QString("0x%1").arg(Bp.Location, 16, 16, QChar('0')));
        Table->setItem(Row, 1, AddrItem);

        auto* TypeItem = new QTableWidgetItem(Bp.IsHardware ? "Hardware" : "Software");
        Table->setItem(Row, 2, TypeItem);

        auto* HitItem = new QTableWidgetItem(QString::number(Bp.HitCount));
        Table->setItem(Row, 3, HitItem);

        auto* CondItem = new QTableWidgetItem(Bp.Condition);
        Table->setItem(Row, 4, CondItem);
    }

    Table->blockSignals(false);
}

void BreakpointWidget::OnAddBreakpoint() {
    if (!EngineRef) return;

    auto* Dialog = new QDialog(this);
    Dialog->setWindowTitle("Add Breakpoint");
    Dialog->setMinimumWidth(350);

    auto* FormLayout = new QFormLayout(Dialog);

    auto* AddrEdit = new QLineEdit(Dialog);
    AddrEdit->setPlaceholderText("0x00007FF...");
    FormLayout->addRow("Address:", AddrEdit);

    auto* TypeCombo = new QComboBox(Dialog);
    TypeCombo->addItem("Software");
    TypeCombo->addItem("Hardware");
    FormLayout->addRow("Type:", TypeCombo);

    auto* CondEdit = new QLineEdit(Dialog);
    CondEdit->setPlaceholderText("Optional condition...");
    FormLayout->addRow("Condition:", CondEdit);

    auto* Buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, Dialog);
    FormLayout->addRow(Buttons);

    connect(Buttons, &QDialogButtonBox::accepted, Dialog, &QDialog::accept);
    connect(Buttons, &QDialogButtonBox::rejected, Dialog, &QDialog::reject);

    if (Dialog->exec() == QDialog::Accepted) {
        QString AddrText = AddrEdit->text().trimmed();
        if (AddrText.startsWith("0x", Qt::CaseInsensitive)) {
            AddrText = AddrText.mid(2);
        }
        bool Ok = false;
        Address Addr = AddrText.toULongLong(&Ok, 16);
        if (Ok && Addr != 0) {
            bool IsHw = (TypeCombo->currentIndex() == 1);
            EngineRef->AddBreakpoint(Addr, IsHw);
        }
    }

    delete Dialog;
}

void BreakpointWidget::OnRemoveBreakpoint() {
    if (!EngineRef) return;

    auto Selected = Table->selectedItems();
    QSet<Address> ToRemove;

    for (auto* Item : Selected) {
        int Row = Item->row();
        auto* CheckItem = Table->item(Row, 0);
        if (CheckItem) {
            Address Addr = static_cast<Address>(CheckItem->data(Qt::UserRole).toULongLong());
            ToRemove.insert(Addr);
        }
    }

    for (Address Addr : ToRemove) {
        EngineRef->RemoveBreakpoint(Addr);
    }
}

void BreakpointWidget::OnEnableAll() {
    if (!EngineRef) return;
    auto Breakpoints = EngineRef->GetBreakpoints();
    for (auto& Bp : Breakpoints) {
        if (!Bp.Enabled) {
            EngineRef->EnableBreakpoint(Bp.Location, true);
        }
    }
}

void BreakpointWidget::OnDisableAll() {
    if (!EngineRef) return;
    auto Breakpoints = EngineRef->GetBreakpoints();
    for (auto& Bp : Breakpoints) {
        if (Bp.Enabled) {
            EngineRef->EnableBreakpoint(Bp.Location, false);
        }
    }
}

void BreakpointWidget::OnClearAll() {
    if (!EngineRef) return;
    auto Breakpoints = EngineRef->GetBreakpoints();
    for (auto& Bp : Breakpoints) {
        EngineRef->RemoveBreakpoint(Bp.Location);
    }
}

void BreakpointWidget::OnEditCondition() {
    if (!EngineRef) return;

    auto Selected = Table->selectedItems();
    if (Selected.isEmpty()) return;

    int Row = Selected.first()->row();
    auto* CheckItem = Table->item(Row, 0);
    if (!CheckItem) return;

    Address Addr = static_cast<Address>(CheckItem->data(Qt::UserRole).toULongLong());

    auto* CondItem = Table->item(Row, 4);
    QString CurrentCond = CondItem ? CondItem->text() : QString();

    bool Ok = false;
    QString NewCond = QInputDialog::getText(this, "Edit Condition",
        "Condition expression:", QLineEdit::Normal, CurrentCond, &Ok);

    if (Ok) {
        auto Breakpoints = EngineRef->GetBreakpoints();
        for (auto& Bp : Breakpoints) {
            if (Bp.Location == Addr) {
                EngineRef->RemoveBreakpoint(Addr);
                EngineRef->AddBreakpoint(Addr, Bp.IsHardware);
                break;
            }
        }
    }
}

void BreakpointWidget::OnToggleSelected() {
    if (!EngineRef) return;

    auto Selected = Table->selectedItems();
    QSet<Address> Toggled;

    for (auto* Item : Selected) {
        int Row = Item->row();
        auto* CheckItem = Table->item(Row, 0);
        if (CheckItem) {
            Address Addr = static_cast<Address>(CheckItem->data(Qt::UserRole).toULongLong());
            if (!Toggled.contains(Addr)) {
                Toggled.insert(Addr);
                bool CurrentlyEnabled = (CheckItem->checkState() == Qt::Checked);
                EngineRef->EnableBreakpoint(Addr, !CurrentlyEnabled);
            }
        }
    }
}

void BreakpointWidget::OnContextMenu(const QPoint& Pos) {
    auto* Item = Table->itemAt(Pos);
    if (!Item) return;

    QMenu Menu(this);

    auto* EnableAction = Menu.addAction("Enable");
    connect(EnableAction, &QAction::triggered, this, [this]() {
        auto Selected = Table->selectedItems();
        for (auto* Sel : Selected) {
            auto* CheckItem = Table->item(Sel->row(), 0);
            if (CheckItem && EngineRef) {
                Address Addr = static_cast<Address>(CheckItem->data(Qt::UserRole).toULongLong());
                EngineRef->EnableBreakpoint(Addr, true);
            }
        }
    });

    auto* DisableAction = Menu.addAction("Disable");
    connect(DisableAction, &QAction::triggered, this, [this]() {
        auto Selected = Table->selectedItems();
        for (auto* Sel : Selected) {
            auto* CheckItem = Table->item(Sel->row(), 0);
            if (CheckItem && EngineRef) {
                Address Addr = static_cast<Address>(CheckItem->data(Qt::UserRole).toULongLong());
                EngineRef->EnableBreakpoint(Addr, false);
            }
        }
    });

    Menu.addSeparator();

    auto* EditCondAction = Menu.addAction("Edit Condition...");
    connect(EditCondAction, &QAction::triggered, this, &BreakpointWidget::OnEditCondition);

    Menu.addSeparator();

    auto* RemoveAction = Menu.addAction("Remove");
    connect(RemoveAction, &QAction::triggered, this, &BreakpointWidget::OnRemoveBreakpoint);

    Menu.exec(Table->viewport()->mapToGlobal(Pos));
}

}
