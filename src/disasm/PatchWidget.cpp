#include "PatchWidget.h"
#include "PatchEngine.h"
#include "../analysis/AnalysisDatabase.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMenu>
#include <QClipboard>
#include <QApplication>
#include <QFileDialog>
#include <QMessageBox>
#include <QFormLayout>
#include <QPushButton>
#include <QAction>

namespace Fidra {

PatchBytesDialog::PatchBytesDialog(QWidget* Parent)
    : QDialog(Parent)
{
    setWindowTitle("Patch Bytes");
    setMinimumWidth(450);

    auto* Layout = new QFormLayout(this);

    AddressEdit = new QLineEdit(this);
    AddressEdit->setPlaceholderText("0x00000001400010A0");
    AddressEdit->setFont(QFont("Monospace"));
    Layout->addRow("Address:", AddressEdit);

    BytesEdit = new QLineEdit(this);
    BytesEdit->setPlaceholderText("90 90 90 C3");
    BytesEdit->setFont(QFont("Monospace"));
    Layout->addRow("Hex Bytes:", BytesEdit);

    DescEdit = new QLineEdit(this);
    DescEdit->setPlaceholderText("Optional description");
    Layout->addRow("Description:", DescEdit);

    auto* Buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(Buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(Buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    Layout->addRow(Buttons);
}

Address PatchBytesDialog::GetAddress() const {
    return AddressEdit->text().toULongLong(nullptr, 0);
}

QByteArray PatchBytesDialog::GetBytes() const {
    QString Hex = BytesEdit->text().remove(' ').remove('\t');
    return QByteArray::fromHex(Hex.toLatin1());
}

QString PatchBytesDialog::GetDescription() const {
    return DescEdit->text();
}

void PatchBytesDialog::SetAddress(Address Addr) {
    AddressEdit->setText(QString("0x%1").arg(Addr, 16, 16, QChar('0')).toUpper());
}

NopOutDialog::NopOutDialog(QWidget* Parent)
    : QDialog(Parent)
{
    setWindowTitle("NOP Out");
    setMinimumWidth(350);

    auto* Layout = new QFormLayout(this);

    AddressEdit = new QLineEdit(this);
    AddressEdit->setPlaceholderText("0x00000001400010A0");
    AddressEdit->setFont(QFont("Monospace"));
    Layout->addRow("Address:", AddressEdit);

    SizeBox = new QSpinBox(this);
    SizeBox->setRange(1, 65536);
    SizeBox->setValue(1);
    Layout->addRow("Size (bytes):", SizeBox);

    auto* Buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(Buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(Buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    Layout->addRow(Buttons);
}

Address NopOutDialog::GetAddress() const {
    return AddressEdit->text().toULongLong(nullptr, 0);
}

int NopOutDialog::GetSize() const {
    return SizeBox->value();
}

void NopOutDialog::SetAddress(Address Addr) {
    AddressEdit->setText(QString("0x%1").arg(Addr, 16, 16, QChar('0')).toUpper());
}

AssembleDialog::AssembleDialog(PatchEngine* Engine, QWidget* Parent)
    : QDialog(Parent)
    , EnginePtr(Engine)
{
    setWindowTitle("Assemble");
    setMinimumWidth(500);
    setMinimumHeight(350);

    auto* Layout = new QVBoxLayout(this);

    auto* FormLayout = new QFormLayout();

    AddressEdit = new QLineEdit(this);
    AddressEdit->setPlaceholderText("0x00000001400010A0");
    AddressEdit->setFont(QFont("Monospace"));
    FormLayout->addRow("Address:", AddressEdit);

    Layout->addLayout(FormLayout);

    auto* AsmLabel = new QLabel("Assembly:", this);
    Layout->addWidget(AsmLabel);

    AsmEdit = new QTextEdit(this);
    AsmEdit->setFont(QFont("Monospace"));
    AsmEdit->setPlaceholderText("xor rax, rax\nret");
    AsmEdit->setMinimumHeight(120);
    Layout->addWidget(AsmEdit);

    auto* AssembleBtn = new QPushButton("Assemble", this);
    connect(AssembleBtn, &QPushButton::clicked, this, &AssembleDialog::OnAssemble);
    Layout->addWidget(AssembleBtn);

    PreviewLabel = new QLabel(this);
    PreviewLabel->setFont(QFont("Monospace"));
    PreviewLabel->setWordWrap(true);
    PreviewLabel->setStyleSheet("QLabel { padding: 6px; border: 1px solid #555; border-radius: 3px; }");
    PreviewLabel->setText("Assembled bytes will appear here");
    Layout->addWidget(PreviewLabel);

    auto* DescFormLayout = new QFormLayout();
    DescEdit = new QLineEdit(this);
    DescEdit->setPlaceholderText("Optional description");
    DescFormLayout->addRow("Description:", DescEdit);
    Layout->addLayout(DescFormLayout);

    auto* Buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(Buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(Buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    Layout->addWidget(Buttons);
}

Address AssembleDialog::GetAddress() const {
    return AddressEdit->text().toULongLong(nullptr, 0);
}

QByteArray AssembleDialog::GetAssembledBytes() const {
    return AssembledBytes;
}

QString AssembleDialog::GetDescription() const {
    return DescEdit->text();
}

void AssembleDialog::SetAddress(Address Addr) {
    AddressEdit->setText(QString("0x%1").arg(Addr, 16, 16, QChar('0')).toUpper());
}

void AssembleDialog::OnAssemble() {
    Address Addr = GetAddress();
    QString AsmText = AsmEdit->toPlainText();
    QString Error;

    AssembledBytes.clear();

    if (EnginePtr->Assemble(AsmText, Addr, AssembledBytes, Error)) {
        QString HexStr = AssembledBytes.toHex(' ').toUpper();
        PreviewLabel->setText(QString("Bytes (%1): %2").arg(AssembledBytes.size()).arg(HexStr));
        PreviewLabel->setStyleSheet("QLabel { padding: 6px; border: 1px solid #4a4; border-radius: 3px; color: #4a4; }");
    } else {
        PreviewLabel->setText("Error: " + Error);
        PreviewLabel->setStyleSheet("QLabel { padding: 6px; border: 1px solid #a44; border-radius: 3px; color: #a44; }");
    }
}

PatchWidget::PatchWidget(QWidget* Parent)
    : QWidget(Parent)
    , AnalysisDb(nullptr)
{
    Engine = new PatchEngine(this);

    auto* Layout = new QVBoxLayout(this);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(2);

    ToolBar = new QToolBar(this);
    ToolBar->setIconSize(QSize(16, 16));
    ToolBar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);

    QAction* PatchBytesAction = ToolBar->addAction("Patch Bytes");
    PatchBytesAction->setToolTip("Patch bytes at address");
    connect(PatchBytesAction, &QAction::triggered, this, &PatchWidget::OnPatchBytes);

    QAction* NopOutAction = ToolBar->addAction("NOP Out");
    NopOutAction->setToolTip("NOP out bytes at address");
    connect(NopOutAction, &QAction::triggered, this, &PatchWidget::OnNopOut);

    QAction* AssembleAction = ToolBar->addAction("Assemble");
    AssembleAction->setToolTip("Assemble instructions and patch");
    connect(AssembleAction, &QAction::triggered, this, &PatchWidget::OnAssemble);

    ToolBar->addSeparator();

    QAction* RevertAction = ToolBar->addAction("Revert");
    RevertAction->setToolTip("Revert selected patch");
    connect(RevertAction, &QAction::triggered, this, &PatchWidget::OnRevert);

    QAction* RevertAllAction = ToolBar->addAction("Revert All");
    RevertAllAction->setToolTip("Revert all patches");
    connect(RevertAllAction, &QAction::triggered, this, &PatchWidget::OnRevertAll);

    ToolBar->addSeparator();

    QAction* SaveAction = ToolBar->addAction("Save Binary");
    SaveAction->setToolTip("Save patched binary to file");
    connect(SaveAction, &QAction::triggered, this, &PatchWidget::OnSaveBinary);

    QAction* ExportAction = ToolBar->addAction("Export");
    ExportAction->setToolTip("Export patches to JSON");
    connect(ExportAction, &QAction::triggered, this, &PatchWidget::OnExport);

    QAction* ImportAction = ToolBar->addAction("Import");
    ImportAction->setToolTip("Import patches from JSON");
    connect(ImportAction, &QAction::triggered, this, &PatchWidget::OnImport);

    Layout->addWidget(ToolBar);

    TreeWidget = new QTreeWidget(this);
    TreeWidget->setHeaderLabels({"Address", "Size", "Original", "Patched", "Description", "Status"});
    TreeWidget->setAlternatingRowColors(true);
    TreeWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    TreeWidget->setRootIsDecorated(false);
    TreeWidget->setSortingEnabled(false);
    TreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    TreeWidget->header()->setStretchLastSection(true);
    TreeWidget->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(2, QHeaderView::Interactive);
    TreeWidget->header()->setSectionResizeMode(3, QHeaderView::Interactive);
    TreeWidget->header()->setSectionResizeMode(4, QHeaderView::Stretch);
    TreeWidget->header()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    Layout->addWidget(TreeWidget);

    connect(TreeWidget, &QTreeWidget::itemDoubleClicked, this, &PatchWidget::OnItemDoubleClicked);
    connect(TreeWidget, &QTreeWidget::customContextMenuRequested, this, &PatchWidget::OnContextMenu);
    connect(Engine, &PatchEngine::PatchApplied, this, &PatchWidget::OnPatchApplied);
    connect(Engine, &PatchEngine::PatchReverted, this, &PatchWidget::OnPatchReverted);
}

PatchWidget::~PatchWidget() = default;

void PatchWidget::SetAnalysisDatabase(AnalysisDatabase* Db) {
    AnalysisDb = Db;
}

PatchEngine* PatchWidget::GetPatchEngine() const {
    return Engine;
}

void PatchWidget::OnPatchBytes() {
    if (!AnalysisDb) {
        QMessageBox::warning(this, "Patch Bytes", "No binary loaded.");
        return;
    }

    PatchBytesDialog Dlg(this);
    if (Dlg.exec() != QDialog::Accepted) return;

    Address Addr = Dlg.GetAddress();
    QByteArray Bytes = Dlg.GetBytes();
    QString Desc = Dlg.GetDescription();

    if (Bytes.isEmpty()) {
        QMessageBox::warning(this, "Patch Bytes", "No valid hex bytes entered.");
        return;
    }

    if (!Engine->PatchBytes(AnalysisDb, Addr, Bytes, Desc)) {
        QMessageBox::warning(this, "Patch Bytes", "Failed to apply patch. Check the address is valid.");
    }
}

void PatchWidget::OnNopOut() {
    if (!AnalysisDb) {
        QMessageBox::warning(this, "NOP Out", "No binary loaded.");
        return;
    }

    NopOutDialog Dlg(this);
    if (Dlg.exec() != QDialog::Accepted) return;

    Address Addr = Dlg.GetAddress();
    int Size = Dlg.GetSize();

    if (!Engine->NopOut(AnalysisDb, Addr, Size)) {
        QMessageBox::warning(this, "NOP Out", "Failed to NOP out bytes. Check the address is valid.");
    }
}

void PatchWidget::OnAssemble() {
    if (!AnalysisDb) {
        QMessageBox::warning(this, "Assemble", "No binary loaded.");
        return;
    }

    AssembleDialog Dlg(Engine, this);
    if (Dlg.exec() != QDialog::Accepted) return;

    QByteArray Bytes = Dlg.GetAssembledBytes();
    if (Bytes.isEmpty()) {
        QMessageBox::warning(this, "Assemble", "No bytes assembled. Click 'Assemble' first.");
        return;
    }

    Address Addr = Dlg.GetAddress();
    QString Desc = Dlg.GetDescription();
    if (Desc.isEmpty()) Desc = "Assembled patch";

    if (!Engine->PatchBytes(AnalysisDb, Addr, Bytes, Desc)) {
        QMessageBox::warning(this, "Assemble", "Failed to apply assembled bytes.");
    }
}

void PatchWidget::OnRevert() {
    QTreeWidgetItem* Item = TreeWidget->currentItem();
    if (!Item) {
        QMessageBox::information(this, "Revert", "No patch selected.");
        return;
    }

    int Index = TreeWidget->indexOfTopLevelItem(Item);
    if (!Engine->RevertPatch(Index)) {
        QMessageBox::warning(this, "Revert", "Failed to revert patch.");
    }
}

void PatchWidget::OnRevertAll() {
    if (Engine->PatchCount() == 0) return;

    int Ret = QMessageBox::question(this, "Revert All",
        QString("Revert all %1 patches?").arg(Engine->PatchCount()),
        QMessageBox::Yes | QMessageBox::No);

    if (Ret == QMessageBox::Yes) {
        Engine->RevertAll();
    }
}

void PatchWidget::OnSaveBinary() {
    if (!AnalysisDb) {
        QMessageBox::warning(this, "Save Binary", "No binary loaded.");
        return;
    }

    BinaryInfo Info = AnalysisDb->GetBinaryInfo();
    QString DefaultName = Info.FileName;
    if (DefaultName.contains('.')) {
        int DotPos = DefaultName.lastIndexOf('.');
        DefaultName.insert(DotPos, "_patched");
    } else {
        DefaultName += "_patched";
    }

    QString OutputPath = QFileDialog::getSaveFileName(this, "Save Patched Binary",
        DefaultName, "All Files (*)");

    if (OutputPath.isEmpty()) return;

    if (Engine->SavePatchedBinary(AnalysisDb, OutputPath)) {
        QMessageBox::information(this, "Save Binary",
            QString("Patched binary saved to:\n%1").arg(OutputPath));
    } else {
        QMessageBox::warning(this, "Save Binary", "Failed to save patched binary.");
    }
}

void PatchWidget::OnExport() {
    if (Engine->PatchCount() == 0) {
        QMessageBox::information(this, "Export", "No patches to export.");
        return;
    }

    QString Path = QFileDialog::getSaveFileName(this, "Export Patches",
        "patches.json", "JSON Files (*.json);;All Files (*)");

    if (Path.isEmpty()) return;

    if (Engine->ExportPatches(Path)) {
        QMessageBox::information(this, "Export",
            QString("Exported %1 patches to:\n%2").arg(Engine->PatchCount()).arg(Path));
    } else {
        QMessageBox::warning(this, "Export", "Failed to export patches.");
    }
}

void PatchWidget::OnImport() {
    QString Path = QFileDialog::getOpenFileName(this, "Import Patches",
        QString(), "JSON Files (*.json);;All Files (*)");

    if (Path.isEmpty()) return;

    if (Engine->ImportPatches(Path)) {
        RefreshList();
        QMessageBox::information(this, "Import",
            QString("Imported patches. Total: %1").arg(Engine->PatchCount()));
    } else {
        QMessageBox::warning(this, "Import", "Failed to import patches.");
    }
}

void PatchWidget::OnItemDoubleClicked(QTreeWidgetItem* Item, int Column) {
    Q_UNUSED(Column);
    if (!Item) return;
    Address Addr = Item->data(0, Qt::UserRole).toULongLong();
    emit NavigateToAddress(Addr);
}

void PatchWidget::OnContextMenu(const QPoint& Pos) {
    QTreeWidgetItem* Item = TreeWidget->itemAt(Pos);
    if (!Item) return;

    int Index = TreeWidget->indexOfTopLevelItem(Item);
    Address Addr = Item->data(0, Qt::UserRole).toULongLong();

    QMenu Menu(this);

    QAction* RevertAction = Menu.addAction("Revert This Patch");
    QAction* CopyAddrAction = Menu.addAction("Copy Address");
    QAction* CopyOrigAction = Menu.addAction("Copy Original Bytes");
    QAction* CopyPatchAction = Menu.addAction("Copy Patched Bytes");
    Menu.addSeparator();
    QAction* GoToAction = Menu.addAction("Go to Address");

    QAction* Selected = Menu.exec(TreeWidget->viewport()->mapToGlobal(Pos));

    if (Selected == RevertAction) {
        Engine->RevertPatch(Index);
    } else if (Selected == CopyAddrAction) {
        QApplication::clipboard()->setText(FormatAddress(Addr));
    } else if (Selected == CopyOrigAction) {
        QApplication::clipboard()->setText(Item->text(2));
    } else if (Selected == CopyPatchAction) {
        QApplication::clipboard()->setText(Item->text(3));
    } else if (Selected == GoToAction) {
        emit NavigateToAddress(Addr);
    }
}

void PatchWidget::OnPatchApplied(Address Addr, const QString& Desc) {
    Q_UNUSED(Addr);
    Q_UNUSED(Desc);
    RefreshList();
}

void PatchWidget::OnPatchReverted(int Index) {
    Q_UNUSED(Index);
    RefreshList();
}

void PatchWidget::RefreshList() {
    TreeWidget->clear();

    QList<PatchEntry> AllPatches = Engine->GetPatches();

    for (int I = 0; I < AllPatches.size(); ++I) {
        const PatchEntry& Entry = AllPatches[I];
        auto* Item = new QTreeWidgetItem();

        Item->setText(0, FormatAddress(Entry.Addr));
        Item->setText(1, QString::number(Entry.PatchedBytes.size()));
        Item->setText(2, FormatBytes(Entry.OriginalBytes));
        Item->setText(3, FormatBytes(Entry.PatchedBytes));
        Item->setText(4, Entry.Description);
        Item->setText(5, Entry.IsApplied ? "Applied" : "Reverted");

        Item->setData(0, Qt::UserRole, QVariant::fromValue(Entry.Addr));

        Item->setFont(0, QFont("Monospace"));
        Item->setFont(2, QFont("Monospace"));
        Item->setFont(3, QFont("Monospace"));

        if (Entry.IsApplied) {
            Item->setForeground(5, QColor(0x40, 0xA0, 0x40));
        } else {
            Item->setForeground(5, QColor(0x80, 0x80, 0x80));
        }

        TreeWidget->addTopLevelItem(Item);
    }
}

QString PatchWidget::FormatAddress(Address Addr) const {
    return QString("0x%1").arg(Addr, 16, 16, QChar('0')).toUpper();
}

QString PatchWidget::FormatBytes(const QByteArray& Bytes) const {
    return Bytes.toHex(' ').toUpper();
}

}
