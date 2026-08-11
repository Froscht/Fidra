#include "TraceWidget.h"
#include <QHeaderView>
#include <QMenu>
#include <QAction>
#include <QFileDialog>
#include <QMessageBox>
#include <QDialog>
#include <QFormLayout>
#include <QDialogButtonBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QInputDialog>
#include <QApplication>
#include <QClipboard>
#include <algorithm>

namespace Fidra {

TraceTableModel::TraceTableModel(QObject* Parent)
    : QAbstractTableModel(Parent)
    , SourceEntries(nullptr)
    , HighlightRow(-1)
{
}

int TraceTableModel::rowCount(const QModelIndex& Parent) const {
    if (Parent.isValid() || !SourceEntries) return 0;
    return SourceEntries->size();
}

int TraceTableModel::columnCount(const QModelIndex& Parent) const {
    if (Parent.isValid()) return 0;
    return 10;
}

QVariant TraceTableModel::data(const QModelIndex& Index, int Role) const {
    if (!Index.isValid() || !SourceEntries || Index.row() >= SourceEntries->size()) {
        return {};
    }

    const auto& Entry = (*SourceEntries)[Index.row()];

    if (Role == Qt::DisplayRole) {
        switch (Index.column()) {
        case 0: return static_cast<qulonglong>(Entry.Index);
        case 1: return QString("0x%1").arg(Entry.InstructionAddr, 16, 16, QChar('0'));
        case 2: return Entry.Mnemonic;
        case 3: return Entry.Operands;
        case 4: return QString("0x%1").arg(Entry.Rax, 16, 16, QChar('0'));
        case 5: return QString("0x%1").arg(Entry.Rcx, 16, 16, QChar('0'));
        case 6: return QString("0x%1").arg(Entry.Rdx, 16, 16, QChar('0'));
        case 7: return QString("0x%1").arg(Entry.Rsp, 16, 16, QChar('0'));
        case 8: return QString("0x%1").arg(Entry.Rip, 16, 16, QChar('0'));
        case 9: return QString("0x%1").arg(Entry.Rflags, 8, 16, QChar('0'));
        }
    }

    if (Role == Qt::BackgroundRole && Index.row() > 0 && SourceEntries->size() > Index.row()) {
        const auto& PrevEntry = (*SourceEntries)[Index.row() - 1];
        bool Changed = false;
        switch (Index.column()) {
        case 4: Changed = (Entry.Rax != PrevEntry.Rax); break;
        case 5: Changed = (Entry.Rcx != PrevEntry.Rcx); break;
        case 6: Changed = (Entry.Rdx != PrevEntry.Rdx); break;
        case 7: Changed = (Entry.Rsp != PrevEntry.Rsp); break;
        case 8: Changed = (Entry.Rip != PrevEntry.Rip); break;
        case 9: Changed = (Entry.Rflags != PrevEntry.Rflags); break;
        }
        if (Changed) {
            return QColor(255, 255, 0, 80);
        }
    }

    if (Role == Qt::FontRole) {
        QFont MonoFont("Monospace", 9);
        MonoFont.setStyleHint(QFont::Monospace);
        return MonoFont;
    }

    return {};
}

QVariant TraceTableModel::headerData(int Section, Qt::Orientation Orientation, int Role) const {
    if (Orientation != Qt::Horizontal || Role != Qt::DisplayRole) {
        return {};
    }

    switch (Section) {
    case 0: return "#";
    case 1: return "Address";
    case 2: return "Mnemonic";
    case 3: return "Operands";
    case 4: return "RAX";
    case 5: return "RCX";
    case 6: return "RDX";
    case 7: return "RSP";
    case 8: return "RIP";
    case 9: return "Flags";
    }
    return {};
}

void TraceTableModel::SetEntries(const QVector<TraceEntry>* EntriesPtr) {
    beginResetModel();
    SourceEntries = EntriesPtr;
    endResetModel();
}

void TraceTableModel::Refresh() {
    beginResetModel();
    endResetModel();
}

void TraceTableModel::SetHighlightIndex(int Index) {
    HighlightRow = Index;
}

TraceWidget::TraceWidget(QWidget* Parent)
    : QWidget(Parent)
    , EngineRef(nullptr)
    , MainLayout(new QVBoxLayout(this))
    , ToolBar(nullptr)
    , MainSplitter(nullptr)
    , TraceTable(nullptr)
    , TableModel(nullptr)
    , SearchPanel(nullptr)
    , SearchLayout(nullptr)
    , SearchTypeCombo(nullptr)
    , SearchEdit(nullptr)
    , TimelineSlider(nullptr)
    , TimelineLabel(nullptr)
    , StatsTree(nullptr)
    , StatusLabel(nullptr)
    , TargetPid(0)
{
    MainLayout->setContentsMargins(0, 0, 0, 0);
    MainLayout->setSpacing(0);

    SetupToolBar();
    SetupSearchBar();

    MainSplitter = new QSplitter(Qt::Horizontal, this);

    auto* LeftPanel = new QWidget(this);
    auto* LeftLayout = new QVBoxLayout(LeftPanel);
    LeftLayout->setContentsMargins(0, 0, 0, 0);
    LeftLayout->setSpacing(0);

    SetupTraceView();
    LeftLayout->addWidget(TraceTable);

    SetupTimeline();
    auto* TimelinePanel = new QWidget(this);
    auto* TimelineLayout = new QHBoxLayout(TimelinePanel);
    TimelineLayout->setContentsMargins(4, 2, 4, 2);
    TimelineLayout->addWidget(TimelineSlider);
    TimelineLayout->addWidget(TimelineLabel);
    LeftLayout->addWidget(TimelinePanel);

    MainSplitter->addWidget(LeftPanel);

    auto* RightPanel = new QWidget(this);
    auto* RightLayout = new QVBoxLayout(RightPanel);
    RightLayout->setContentsMargins(0, 0, 0, 0);

    SetupStatistics();
    RightLayout->addWidget(StatsTree);
    MainSplitter->addWidget(RightPanel);

    MainSplitter->setStretchFactor(0, 3);
    MainSplitter->setStretchFactor(1, 1);
    MainLayout->addWidget(MainSplitter);

    StatusLabel = new QLabel("Ready", this);
    StatusLabel->setFrameStyle(QFrame::StyledPanel | QFrame::Sunken);
    MainLayout->addWidget(StatusLabel);

    SetupContextMenu();
}

void TraceWidget::SetEngine(TraceEngine* Engine) {
    if (EngineRef) {
        disconnect(EngineRef, nullptr, this, nullptr);
    }
    EngineRef = Engine;
    if (EngineRef) {
        connect(EngineRef, &TraceEngine::TraceProgress, this, &TraceWidget::OnTraceProgress);
        connect(EngineRef, &TraceEngine::TraceStopped, this, &TraceWidget::OnTraceStopped);
        connect(EngineRef, &TraceEngine::TraceError, this, &TraceWidget::OnTraceError);
    }
}

void TraceWidget::SetupToolBar() {
    ToolBar = new QToolBar(this);
    ToolBar->setIconSize(QSize(16, 16));

    auto* StartAction = ToolBar->addAction("Start Trace");
    StartAction->setIcon(style()->standardIcon(QStyle::SP_MediaPlay));
    connect(StartAction, &QAction::triggered, this, &TraceWidget::OnStartTrace);

    auto* StopAction = ToolBar->addAction("Stop");
    StopAction->setIcon(style()->standardIcon(QStyle::SP_MediaStop));
    connect(StopAction, &QAction::triggered, this, &TraceWidget::OnStopTrace);

    auto* ClearAction = ToolBar->addAction("Clear");
    ClearAction->setIcon(style()->standardIcon(QStyle::SP_DialogResetButton));
    connect(ClearAction, &QAction::triggered, this, &TraceWidget::OnClearTrace);

    ToolBar->addSeparator();

    auto* SaveAction = ToolBar->addAction("Save");
    SaveAction->setIcon(style()->standardIcon(QStyle::SP_DialogSaveButton));
    connect(SaveAction, &QAction::triggered, this, &TraceWidget::OnSaveTrace);

    auto* LoadAction = ToolBar->addAction("Load");
    LoadAction->setIcon(style()->standardIcon(QStyle::SP_DialogOpenButton));
    connect(LoadAction, &QAction::triggered, this, &TraceWidget::OnLoadTrace);

    ToolBar->addSeparator();

    auto* FilterAction = ToolBar->addAction("Filter...");
    FilterAction->setIcon(style()->standardIcon(QStyle::SP_FileDialogDetailedView));
    connect(FilterAction, &QAction::triggered, this, &TraceWidget::ShowFilterDialog);

    MainLayout->addWidget(ToolBar);
}

void TraceWidget::SetupTraceView() {
    TraceTable = new QTableView(this);
    TableModel = new TraceTableModel(this);
    TraceTable->setModel(TableModel);

    TraceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    TraceTable->setSelectionMode(QAbstractItemView::SingleSelection);
    TraceTable->setAlternatingRowColors(true);
    TraceTable->verticalHeader()->hide();
    TraceTable->verticalHeader()->setDefaultSectionSize(20);
    TraceTable->horizontalHeader()->setStretchLastSection(true);
    TraceTable->setContextMenuPolicy(Qt::CustomContextMenu);
    TraceTable->setShowGrid(false);

    QFont MonoFont("Monospace", 9);
    MonoFont.setStyleHint(QFont::Monospace);
    TraceTable->setFont(MonoFont);

    connect(TraceTable, &QTableView::doubleClicked, this, &TraceWidget::OnDoubleClicked);
}

void TraceWidget::SetupSearchBar() {
    SearchPanel = new QWidget(this);
    SearchLayout = new QHBoxLayout(SearchPanel);
    SearchLayout->setContentsMargins(4, 2, 4, 2);

    auto* SearchLabel = new QLabel("Search:", SearchPanel);
    SearchLayout->addWidget(SearchLabel);

    SearchTypeCombo = new QComboBox(SearchPanel);
    SearchTypeCombo->addItem("Mnemonic");
    SearchTypeCombo->addItem("Address");
    SearchTypeCombo->addItem("Register Value");
    SearchLayout->addWidget(SearchTypeCombo);

    SearchEdit = new QLineEdit(SearchPanel);
    SearchEdit->setPlaceholderText("Enter search term...");
    connect(SearchEdit, &QLineEdit::returnPressed, this, &TraceWidget::OnSearch);
    SearchLayout->addWidget(SearchEdit);

    auto* SearchBtn = new QPushButton("Search", SearchPanel);
    connect(SearchBtn, &QPushButton::clicked, this, &TraceWidget::OnSearch);
    SearchLayout->addWidget(SearchBtn);

    MainLayout->addWidget(SearchPanel);
}

void TraceWidget::SetupTimeline() {
    TimelineSlider = new QSlider(Qt::Horizontal, this);
    TimelineSlider->setMinimum(0);
    TimelineSlider->setMaximum(0);
    connect(TimelineSlider, &QSlider::valueChanged, this, &TraceWidget::OnTimelineChanged);

    TimelineLabel = new QLabel("0 / 0", this);
    TimelineLabel->setMinimumWidth(120);
}

void TraceWidget::SetupStatistics() {
    StatsTree = new QTreeWidget(this);
    StatsTree->setHeaderLabels({"Property", "Value"});
    StatsTree->setAlternatingRowColors(true);
    StatsTree->header()->setStretchLastSection(true);
    StatsTree->setRootIsDecorated(true);
}

void TraceWidget::SetupContextMenu() {
    connect(TraceTable, &QTableView::customContextMenuRequested, this, &TraceWidget::OnContextMenu);
}

void TraceWidget::OnStartTrace() {
    if (!EngineRef) return;

    if (EngineRef->IsTracing()) {
        return;
    }

    bool Ok = false;
    int Pid = QInputDialog::getInt(this, "Start Trace", "Process ID:", TargetPid, 1, INT_MAX, 1, &Ok);
    if (!Ok) return;

    TargetPid = Pid;

    if (!EngineRef->StartTrace(Pid, CurrentFilter)) {
        QMessageBox::warning(this, "Trace Error", "Failed to start trace recording.");
        return;
    }

    StatusLabel->setText(QString("Tracing PID %1...").arg(Pid));
}

void TraceWidget::OnStopTrace() {
    if (EngineRef) {
        EngineRef->StopTrace();
    }
}

void TraceWidget::OnClearTrace() {
    if (EngineRef) {
        EngineRef->ClearTrace();
    }
    DisplayEntries.clear();
    TableModel->SetEntries(nullptr);
    TimelineSlider->setMaximum(0);
    TimelineLabel->setText("0 / 0");
    StatsTree->clear();
    StatusLabel->setText("Cleared");
}

void TraceWidget::OnSaveTrace() {
    if (!EngineRef) return;

    QString Path = QFileDialog::getSaveFileName(this, "Save Trace", QString(), "Trace Files (*.atrace);;All Files (*)");
    if (Path.isEmpty()) return;

    if (EngineRef->SaveTrace(Path)) {
        StatusLabel->setText(QString("Trace saved to %1").arg(Path));
    } else {
        QMessageBox::warning(this, "Save Error", "Failed to save trace file.");
    }
}

void TraceWidget::OnLoadTrace() {
    if (!EngineRef) return;

    QString Path = QFileDialog::getOpenFileName(this, "Load Trace", QString(), "Trace Files (*.atrace);;All Files (*)");
    if (Path.isEmpty()) return;

    if (EngineRef->LoadTrace(Path)) {
        RefreshView();
        StatusLabel->setText(QString("Loaded %1 entries from %2").arg(EngineRef->EntryCount()).arg(Path));
    } else {
        QMessageBox::warning(this, "Load Error", "Failed to load trace file.");
    }
}

void TraceWidget::OnSearch() {
    if (!EngineRef) return;

    QString Term = SearchEdit->text().trimmed();
    if (Term.isEmpty()) {
        RefreshView();
        return;
    }

    int SearchType = SearchTypeCombo->currentIndex();
    QVector<TraceEntry> Results;

    switch (SearchType) {
    case 0:
        Results = EngineRef->Search(Term);
        break;
    case 1: {
        QString AddrText = Term;
        if (AddrText.startsWith("0x", Qt::CaseInsensitive)) {
            AddrText = AddrText.mid(2);
        }
        bool Ok = false;
        Address Addr = AddrText.toULongLong(&Ok, 16);
        if (Ok) {
            Results = EngineRef->SearchByAddress(Addr);
        }
        break;
    }
    case 2: {
        QStringList Parts = Term.split('=', Qt::SkipEmptyParts);
        if (Parts.size() == 2) {
            QString RegName = Parts[0].trimmed();
            QString ValStr = Parts[1].trimmed();
            if (ValStr.startsWith("0x", Qt::CaseInsensitive)) {
                ValStr = ValStr.mid(2);
            }
            bool Ok = false;
            uint64_t Value = ValStr.toULongLong(&Ok, 16);
            if (Ok) {
                Results = EngineRef->SearchByRegValue(RegName, Value);
            }
        }
        break;
    }
    }

    DisplayEntries = Results;
    TableModel->SetEntries(&DisplayEntries);
    TimelineSlider->setMaximum(qMax(0, DisplayEntries.size() - 1));
    StatusLabel->setText(QString("Found %1 results").arg(Results.size()));
}

void TraceWidget::OnTimelineChanged(int Value) {
    if (DisplayEntries.isEmpty()) return;

    if (Value >= 0 && Value < DisplayEntries.size()) {
        TraceTable->scrollTo(TableModel->index(Value, 0), QAbstractItemView::PositionAtCenter);
        TraceTable->selectRow(Value);
        TimelineLabel->setText(QString("%1 / %2").arg(Value + 1).arg(DisplayEntries.size()));
    }
}

void TraceWidget::OnDoubleClicked(const QModelIndex& Index) {
    if (!Index.isValid() || DisplayEntries.isEmpty()) return;

    int Row = Index.row();
    if (Row >= 0 && Row < DisplayEntries.size()) {
        emit NavigateToAddress(DisplayEntries[Row].InstructionAddr);
    }
}

void TraceWidget::OnContextMenu(const QPoint& Pos) {
    auto Index = TraceTable->indexAt(Pos);
    if (!Index.isValid() || DisplayEntries.isEmpty()) return;

    int Row = Index.row();
    if (Row < 0 || Row >= DisplayEntries.size()) return;

    const auto& Entry = DisplayEntries[Row];

    QMenu Menu(this);

    auto* GoToAction = Menu.addAction("Go to Address");
    connect(GoToAction, &QAction::triggered, this, [this, Entry]() {
        emit NavigateToAddress(Entry.InstructionAddr);
    });

    auto* CopyAddrAction = Menu.addAction("Copy Address");
    connect(CopyAddrAction, &QAction::triggered, this, [Entry]() {
        QApplication::clipboard()->setText(QString("0x%1").arg(Entry.InstructionAddr, 16, 16, QChar('0')));
    });

    Menu.addSeparator();

    auto* FilterAddrAction = Menu.addAction("Filter by this Address");
    connect(FilterAddrAction, &QAction::triggered, this, [this, Entry]() {
        SearchTypeCombo->setCurrentIndex(1);
        SearchEdit->setText(QString("0x%1").arg(Entry.InstructionAddr, 16, 16, QChar('0')));
        OnSearch();
    });

    auto* FilterMnemAction = Menu.addAction("Filter by this Mnemonic");
    connect(FilterMnemAction, &QAction::triggered, this, [this, Entry]() {
        SearchTypeCombo->setCurrentIndex(0);
        SearchEdit->setText(Entry.Mnemonic);
        OnSearch();
    });

    Menu.addSeparator();

    auto* ShowAllAction = Menu.addAction("Show All Entries");
    connect(ShowAllAction, &QAction::triggered, this, [this]() {
        SearchEdit->clear();
        RefreshView();
    });

    Menu.exec(TraceTable->viewport()->mapToGlobal(Pos));
}

void TraceWidget::ShowFilterDialog() {
    auto* Dialog = new QDialog(this);
    Dialog->setWindowTitle("Trace Filter");
    Dialog->setMinimumWidth(400);

    auto* FormLayout = new QFormLayout(Dialog);

    auto* StartAddrEdit = new QLineEdit(Dialog);
    StartAddrEdit->setPlaceholderText("0x0000000000000000");
    if (CurrentFilter.StartAddr != 0) {
        StartAddrEdit->setText(QString("0x%1").arg(CurrentFilter.StartAddr, 16, 16, QChar('0')));
    }
    FormLayout->addRow("Start Address:", StartAddrEdit);

    auto* EndAddrEdit = new QLineEdit(Dialog);
    EndAddrEdit->setPlaceholderText("0xFFFFFFFFFFFFFFFF");
    if (CurrentFilter.EndAddr != UINT64_MAX) {
        EndAddrEdit->setText(QString("0x%1").arg(CurrentFilter.EndAddr, 16, 16, QChar('0')));
    }
    FormLayout->addRow("End Address:", EndAddrEdit);

    auto* MaxEntriesSpin = new QSpinBox(Dialog);
    MaxEntriesSpin->setRange(1000, 100000000);
    MaxEntriesSpin->setValue(CurrentFilter.MaxEntries);
    MaxEntriesSpin->setSingleStep(100000);
    FormLayout->addRow("Max Entries:", MaxEntriesSpin);

    auto* ModuleEdit = new QLineEdit(Dialog);
    ModuleEdit->setText(CurrentFilter.ModuleFilter);
    ModuleEdit->setPlaceholderText("e.g. libfoo.so");
    FormLayout->addRow("Module Filter:", ModuleEdit);

    auto* TraceLibsCheck = new QCheckBox("Trace into libraries", Dialog);
    TraceLibsCheck->setChecked(CurrentFilter.TraceIntoLibraries);
    FormLayout->addRow(TraceLibsCheck);

    auto* ConditionEdit = new QLineEdit(Dialog);
    ConditionEdit->setText(CurrentFilter.Condition);
    ConditionEdit->setPlaceholderText("Optional condition expression");
    FormLayout->addRow("Condition:", ConditionEdit);

    auto* PidSpin = new QSpinBox(Dialog);
    PidSpin->setRange(1, INT_MAX);
    PidSpin->setValue(TargetPid > 0 ? TargetPid : 1);
    FormLayout->addRow("Target PID:", PidSpin);

    auto* Buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, Dialog);
    FormLayout->addRow(Buttons);

    connect(Buttons, &QDialogButtonBox::accepted, Dialog, &QDialog::accept);
    connect(Buttons, &QDialogButtonBox::rejected, Dialog, &QDialog::reject);

    if (Dialog->exec() == QDialog::Accepted) {
        QString StartText = StartAddrEdit->text().trimmed();
        if (!StartText.isEmpty()) {
            if (StartText.startsWith("0x", Qt::CaseInsensitive)) StartText = StartText.mid(2);
            bool Ok = false;
            CurrentFilter.StartAddr = StartText.toULongLong(&Ok, 16);
            if (!Ok) CurrentFilter.StartAddr = 0;
        } else {
            CurrentFilter.StartAddr = 0;
        }

        QString EndText = EndAddrEdit->text().trimmed();
        if (!EndText.isEmpty()) {
            if (EndText.startsWith("0x", Qt::CaseInsensitive)) EndText = EndText.mid(2);
            bool Ok = false;
            CurrentFilter.EndAddr = EndText.toULongLong(&Ok, 16);
            if (!Ok) CurrentFilter.EndAddr = UINT64_MAX;
        } else {
            CurrentFilter.EndAddr = UINT64_MAX;
        }

        CurrentFilter.MaxEntries = MaxEntriesSpin->value();
        CurrentFilter.ModuleFilter = ModuleEdit->text().trimmed();
        CurrentFilter.TraceIntoLibraries = TraceLibsCheck->isChecked();
        CurrentFilter.Condition = ConditionEdit->text().trimmed();
        TargetPid = PidSpin->value();
    }

    delete Dialog;
}

void TraceWidget::RefreshView() {
    if (!EngineRef) return;

    DisplayEntries = EngineRef->GetEntries();
    TableModel->SetEntries(&DisplayEntries);
    TimelineSlider->setMaximum(qMax(0, DisplayEntries.size() - 1));
    TimelineLabel->setText(QString("0 / %1").arg(DisplayEntries.size()));
    UpdateStatistics();
}

void TraceWidget::UpdateStatistics() {
    StatsTree->clear();

    if (DisplayEntries.isEmpty()) return;

    auto* SummaryItem = new QTreeWidgetItem(StatsTree, {"Summary"});
    new QTreeWidgetItem(SummaryItem, {"Total Entries", QString::number(DisplayEntries.size())});

    QSet<Address> UniqueAddresses;
    QMap<QString, int> MnemonicCounts;
    QMap<Address, int> AddressCounts;

    for (const auto& Entry : DisplayEntries) {
        UniqueAddresses.insert(Entry.InstructionAddr);
        MnemonicCounts[Entry.Mnemonic]++;
        AddressCounts[Entry.InstructionAddr]++;
    }

    new QTreeWidgetItem(SummaryItem, {"Unique Addresses", QString::number(UniqueAddresses.size())});
    new QTreeWidgetItem(SummaryItem, {"Address Range",
        QString("0x%1 - 0x%2")
            .arg(DisplayEntries.first().InstructionAddr, 16, 16, QChar('0'))
            .arg(DisplayEntries.last().InstructionAddr, 16, 16, QChar('0'))});

    auto* MnemItem = new QTreeWidgetItem(StatsTree, {"Instruction Counts"});
    QList<QPair<QString, int>> SortedMnemonics;
    for (auto It = MnemonicCounts.constBegin(); It != MnemonicCounts.constEnd(); ++It) {
        SortedMnemonics.append({It.key(), It.value()});
    }
    std::sort(SortedMnemonics.begin(), SortedMnemonics.end(),
              [](const QPair<QString, int>& A, const QPair<QString, int>& B) { return A.second > B.second; });

    int MnemCount = 0;
    for (const auto& Pair : SortedMnemonics) {
        new QTreeWidgetItem(MnemItem, {Pair.first, QString::number(Pair.second)});
        if (++MnemCount >= 20) break;
    }

    auto* HotItem = new QTreeWidgetItem(StatsTree, {"Hottest Addresses"});
    QList<QPair<Address, int>> SortedAddresses;
    for (auto It = AddressCounts.constBegin(); It != AddressCounts.constEnd(); ++It) {
        SortedAddresses.append({It.key(), It.value()});
    }
    std::sort(SortedAddresses.begin(), SortedAddresses.end(),
              [](const QPair<Address, int>& A, const QPair<Address, int>& B) { return A.second > B.second; });

    int AddrCount = 0;
    for (const auto& Pair : SortedAddresses) {
        new QTreeWidgetItem(HotItem, {
            QString("0x%1").arg(Pair.first, 16, 16, QChar('0')),
            QString::number(Pair.second)
        });
        if (++AddrCount >= 20) break;
    }

    StatsTree->expandAll();
}

void TraceWidget::OnTraceProgress(uint64_t Count) {
    StatusLabel->setText(QString("Tracing... %1 entries recorded").arg(Count));
}

void TraceWidget::OnTraceStopped(uint64_t TotalEntries) {
    StatusLabel->setText(QString("Trace complete: %1 entries").arg(TotalEntries));
    RefreshView();
}

void TraceWidget::OnTraceError(const QString& Error) {
    StatusLabel->setText(QString("Error: %1").arg(Error));
    QMessageBox::warning(this, "Trace Error", Error);
}

}
