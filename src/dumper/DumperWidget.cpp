#include "DumperWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QMessageBox>
#include <QHeaderView>
#include <QDialog>
#include <QApplication>
#include <QStyle>
#include <QDir>
#include <QDateTime>
#include <QtConcurrent>

namespace Fidra {

DumperWidget::DumperWidget(QWidget* Parent, ICore* Core)
    : QWidget(Parent)
    , CoreRef(Core)
    , Dumper(new ProcessDumper(this))
    , DumpRunning(false)
{
    SetupUi();

    connect(SelectProcessBtn, &QPushButton::clicked, this, &DumperWidget::OnSelectProcess);
    connect(RefreshModulesBtn, &QPushButton::clicked, this, &DumperWidget::OnRefreshModules);
    connect(DumpBtn, &QPushButton::clicked, this, &DumperWidget::OnDumpSelected);
    connect(CancelBtn, &QPushButton::clicked, this, &DumperWidget::OnCancelDump);
    connect(BrowseBtn, &QPushButton::clicked, this, &DumperWidget::OnBrowseOutput);
    connect(DumpAllBtn, &QPushButton::clicked, this, &DumperWidget::OnDumpAll);
    connect(MergeBtn, &QPushButton::clicked, this, &DumperWidget::OnMergeDump);
    connect(LoadBaselineBtn, &QPushButton::clicked, this, &DumperWidget::OnLoadBaseline);
    connect(ModuleTable, &QTableWidget::cellDoubleClicked, this, &DumperWidget::OnModuleDoubleClicked);

    connect(Dumper, &ProcessDumper::ProgressChanged, this, &DumperWidget::OnProgressUpdate, Qt::QueuedConnection);
    connect(Dumper, &ProcessDumper::LogMessage, this, &DumperWidget::OnDumperLog, Qt::QueuedConnection);
    connect(Dumper, &ProcessDumper::DumpComplete, this, &DumperWidget::OnDumpFinished, Qt::QueuedConnection);

    SetDumpControlsEnabled(false);
    CancelBtn->setEnabled(false);
}

DumperWidget::~DumperWidget()
{
    if (DumpRunning) {
        Dumper->Cancel();
    }
}

void DumperWidget::SetupUi()
{
    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(6, 6, 6, 6);
    MainLayout->setSpacing(6);

    auto* ProcessGroup = new QGroupBox("Process", this);
    auto* ProcessLayout = new QHBoxLayout(ProcessGroup);
    SelectProcessBtn = new QPushButton("Select Process", ProcessGroup);
    SelectProcessBtn->setIcon(qApp->style()->standardIcon(QStyle::SP_ComputerIcon));
    ProcessInfoLabel = new QLabel("No process selected", ProcessGroup);
    ProcessInfoLabel->setMinimumWidth(300);
    RefreshModulesBtn = new QPushButton("Refresh Modules", ProcessGroup);
    RefreshModulesBtn->setIcon(qApp->style()->standardIcon(QStyle::SP_BrowserReload));
    RefreshModulesBtn->setEnabled(false);
    ProcessLayout->addWidget(SelectProcessBtn);
    ProcessLayout->addWidget(ProcessInfoLabel, 1);
    ProcessLayout->addWidget(RefreshModulesBtn);
    MainLayout->addWidget(ProcessGroup);

    auto* ModuleGroup = new QGroupBox("Loaded Modules", this);
    auto* ModuleLayout = new QVBoxLayout(ModuleGroup);
    ModuleTable = new QTableWidget(0, 5, ModuleGroup);
    ModuleTable->setHorizontalHeaderLabels({"Name", "Base Address", "Size", "Type", "Path"});
    ModuleTable->horizontalHeader()->setStretchLastSection(true);
    ModuleTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ModuleTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ModuleTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ModuleTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    ModuleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ModuleTable->setSelectionMode(QAbstractItemView::SingleSelection);
    ModuleTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ModuleTable->verticalHeader()->hide();
    ModuleTable->setSortingEnabled(true);
    ModuleTable->setAlternatingRowColors(true);
    ModuleLayout->addWidget(ModuleTable);
    MainLayout->addWidget(ModuleGroup);

    auto* ControlGroup = new QGroupBox("Dump Settings", this);
    auto* ControlLayout = new QVBoxLayout(ControlGroup);

    auto* Row1 = new QHBoxLayout();
    ProgressiveCheck = new QCheckBox("Progressive scan", ControlGroup);
    ProgressiveCheck->setChecked(true);
    FixPeCheck = new QCheckBox("Fix PE headers", ControlGroup);
    FixPeCheck->setChecked(true);
    OpenAfterCheck = new QCheckBox("Open in Fidra after dump", ControlGroup);
    OpenAfterCheck->setChecked(true);
    ScatterReadCheck = new QCheckBox("Use scatter-gather reads", ControlGroup);
    ScatterReadCheck->setChecked(true);
    Row1->addWidget(ProgressiveCheck);
    Row1->addWidget(FixPeCheck);
    Row1->addWidget(OpenAfterCheck);
    Row1->addWidget(ScatterReadCheck);
    Row1->addStretch();
    ControlLayout->addLayout(Row1);

    auto* Row2 = new QHBoxLayout();
    Row2->addWidget(new QLabel("Coverage target:", ControlGroup));
    CoverageSpin = new QDoubleSpinBox(ControlGroup);
    CoverageSpin->setRange(1.0, 100.0);
    CoverageSpin->setValue(99.0);
    CoverageSpin->setSuffix("%");
    CoverageSpin->setDecimals(1);
    Row2->addWidget(CoverageSpin);
    Row2->addSpacing(20);
    Row2->addWidget(new QLabel("Max passes:", ControlGroup));
    MaxPassesSpin = new QSpinBox(ControlGroup);
    MaxPassesSpin->setRange(1, 1000);
    MaxPassesSpin->setValue(100);
    Row2->addWidget(MaxPassesSpin);
    Row2->addStretch();
    ControlLayout->addLayout(Row2);

    auto* Row3 = new QHBoxLayout();
    Row3->addWidget(new QLabel("Output:", ControlGroup));
    OutputPathEdit = new QLineEdit(ControlGroup);
    OutputPathEdit->setPlaceholderText("Auto-generated if empty");
    Row3->addWidget(OutputPathEdit, 1);
    BrowseBtn = new QPushButton("Browse...", ControlGroup);
    Row3->addWidget(BrowseBtn);
    ControlLayout->addLayout(Row3);

    auto* Row4 = new QHBoxLayout();
    DumpBtn = new QPushButton("Dump Selected", ControlGroup);
    DumpBtn->setIcon(qApp->style()->standardIcon(QStyle::SP_ArrowDown));
    CancelBtn = new QPushButton("Cancel", ControlGroup);
    CancelBtn->setIcon(qApp->style()->standardIcon(QStyle::SP_DialogCancelButton));
    Row4->addWidget(DumpBtn);
    Row4->addWidget(CancelBtn);
    Row4->addStretch();
    ControlLayout->addLayout(Row4);

    auto* Row5 = new QHBoxLayout();
    DumpAllBtn = new QPushButton("Dump All Modules", ControlGroup);
    DumpAllBtn->setIcon(qApp->style()->standardIcon(QStyle::SP_DirIcon));
    MergeBtn = new QPushButton("Merge Dump", ControlGroup);
    MergeBtn->setIcon(qApp->style()->standardIcon(QStyle::SP_FileDialogContentsView));
    LoadBaselineBtn = new QPushButton("Load Baseline", ControlGroup);
    LoadBaselineBtn->setIcon(qApp->style()->standardIcon(QStyle::SP_FileDialogStart));
    Row5->addWidget(DumpAllBtn);
    Row5->addWidget(MergeBtn);
    Row5->addWidget(LoadBaselineBtn);
    Row5->addStretch();
    ControlLayout->addLayout(Row5);

    MainLayout->addWidget(ControlGroup);

    auto* ProgressGroup = new QGroupBox("Progress", this);
    auto* ProgressLayout = new QVBoxLayout(ProgressGroup);
    CoverageBar = new QProgressBar(ProgressGroup);
    CoverageBar->setRange(0, 1000);
    CoverageBar->setValue(0);
    CoverageBar->setFormat("%v / %m pages (%p%)");
    ProgressLayout->addWidget(CoverageBar);
    StatusLabel = new QLabel("Idle", ProgressGroup);
    ProgressLayout->addWidget(StatusLabel);

    BottomTabs = new QTabWidget(ProgressGroup);
    LogOutput = new QTextEdit(BottomTabs);
    LogOutput->setReadOnly(true);
    LogOutput->setFont(QFont("Monospace", 9));
    BottomTabs->addTab(LogOutput, "Log");

    Heatmap = new HeatmapWidget(BottomTabs);
    BottomTabs->addTab(Heatmap, "Heatmap");
    BottomTabs->setMinimumHeight(200);
    ProgressLayout->addWidget(BottomTabs);
    MainLayout->addWidget(ProgressGroup);
}

void DumperWidget::OnSelectProcess()
{
    auto* Dialog = new QDialog(this);
    Dialog->setWindowTitle("Select Process to Dump");
    Dialog->resize(650, 500);
    Dialog->setModal(true);

    auto* Layout = new QVBoxLayout(Dialog);

    auto* FilterEdit = new QLineEdit(Dialog);
    FilterEdit->setPlaceholderText("Filter processes...");
    Layout->addWidget(FilterEdit);

    auto* Table = new QTableWidget(Dialog);
    Table->setColumnCount(4);
    Table->setHorizontalHeaderLabels({"PID", "Name", "Architecture", "Path"});
    Table->horizontalHeader()->setStretchLastSection(true);
    Table->setSelectionBehavior(QAbstractItemView::SelectRows);
    Table->setSelectionMode(QAbstractItemView::SingleSelection);
    Table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    Table->verticalHeader()->hide();
    Table->setSortingEnabled(true);
    Table->setAlternatingRowColors(true);
    Layout->addWidget(Table);

    auto PopulateTable = [this, Table]() {
        QList<ProcessInfo> Processes;
        if (CoreRef) {
            Processes = CoreRef->GetProcessList();
        }
        Table->setSortingEnabled(false);
        Table->setRowCount(Processes.size());
        for (int Row = 0; Row < Processes.size(); ++Row) {
            auto& Info = Processes[Row];
            auto* PidItem = new QTableWidgetItem();
            PidItem->setData(Qt::DisplayRole, static_cast<int>(Info.Pid));
            Table->setItem(Row, 0, PidItem);
            Table->setItem(Row, 1, new QTableWidgetItem(Info.Name));
            QString ArchStr;
            switch (Info.Arch) {
                case Architecture::X86: ArchStr = "x86"; break;
                case Architecture::X64: ArchStr = "x64"; break;
                case Architecture::ARM: ArchStr = "ARM"; break;
                case Architecture::ARM64: ArchStr = "ARM64"; break;
                default: ArchStr = "?"; break;
            }
            Table->setItem(Row, 2, new QTableWidgetItem(ArchStr));
            Table->setItem(Row, 3, new QTableWidgetItem(Info.Path));
        }
        Table->setSortingEnabled(true);
    };

    PopulateTable();

    connect(FilterEdit, &QLineEdit::textChanged, [Table](const QString& Text) {
        for (int Row = 0; Row < Table->rowCount(); ++Row) {
            bool Visible = Text.isEmpty();
            for (int Col = 0; Col < Table->columnCount() && !Visible; ++Col) {
                auto* Item = Table->item(Row, Col);
                if (Item && Item->text().contains(Text, Qt::CaseInsensitive)) {
                    Visible = true;
                }
            }
            Table->setRowHidden(Row, !Visible);
        }
    });

    auto* BtnLayout = new QHBoxLayout();
    auto* RefreshBtn = new QPushButton("Refresh", Dialog);
    auto* AttachBtn = new QPushButton("Select", Dialog);
    auto* CancelDialogBtn = new QPushButton("Cancel", Dialog);
    BtnLayout->addWidget(RefreshBtn);
    BtnLayout->addStretch();
    BtnLayout->addWidget(AttachBtn);
    BtnLayout->addWidget(CancelDialogBtn);
    Layout->addLayout(BtnLayout);

    connect(CancelDialogBtn, &QPushButton::clicked, Dialog, &QDialog::reject);
    connect(RefreshBtn, &QPushButton::clicked, PopulateTable);

    auto DoAttach = [this, Table, Dialog]() {
        auto Selected = Table->selectedItems();
        if (Selected.isEmpty()) return;
        int Row = Selected.first()->row();
        uint32_t Pid = Table->item(Row, 0)->data(Qt::DisplayRole).toUInt();
        QString Name = Table->item(Row, 1)->text();

        if (Dumper->IsAttached()) {
            Dumper->Detach();
        }

        if (Dumper->AttachToProcess(Pid)) {
            ProcessInfoLabel->setText(QString("PID: %1 - %2").arg(Pid).arg(Name));
            RefreshModulesBtn->setEnabled(true);
            SetDumpControlsEnabled(true);
            AppendLog(QString("Attached to %1 (PID %2)").arg(Name).arg(Pid));
            OnRefreshModules();
            Dialog->accept();
        } else {
            QMessageBox::warning(this, "Attach Failed",
                QString("Failed to attach to PID %1.\nCheck permissions (may need root/ptrace).").arg(Pid));
        }
    };

    connect(AttachBtn, &QPushButton::clicked, DoAttach);
    connect(Table, &QTableWidget::doubleClicked, [DoAttach](const QModelIndex&) { DoAttach(); });

    Dialog->exec();
    delete Dialog;
}

void DumperWidget::OnRefreshModules()
{
    if (!Dumper->IsAttached()) return;

    AppendLog("Enumerating modules...");
    CurrentModules = Dumper->EnumerateModules();
    PopulateModuleTable(CurrentModules);
    AppendLog(QString("Found %1 module(s)").arg(CurrentModules.size()));
}

void DumperWidget::PopulateModuleTable(const QVector<ModuleInfo>& Modules)
{
    ModuleTable->setSortingEnabled(false);
    ModuleTable->setRowCount(Modules.size());

    for (int Row = 0; Row < Modules.size(); ++Row) {
        auto& Mod = Modules[Row];

        auto* NameItem = new QTableWidgetItem(Mod.Name);
        if (Mod.IsMainModule) {
            QFont BoldFont = NameItem->font();
            BoldFont.setBold(true);
            NameItem->setFont(BoldFont);
        }
        ModuleTable->setItem(Row, 0, NameItem);
        ModuleTable->setItem(Row, 1, new QTableWidgetItem(QString("0x%1").arg(Mod.Base, 0, 16)));
        ModuleTable->setItem(Row, 2, new QTableWidgetItem(FormatSize(Mod.Size)));

        QString TypeStr;
        if (Mod.Name.endsWith(".exe", Qt::CaseInsensitive) || Mod.IsMainModule) {
            TypeStr = "PE";
        } else if (Mod.Name.endsWith(".dll", Qt::CaseInsensitive)) {
            TypeStr = "PE/DLL";
        } else if (Mod.Name.endsWith(".so", Qt::CaseInsensitive) || Mod.Name.contains(".so.")) {
            TypeStr = "ELF/SO";
        } else {
            TypeStr = "ELF";
        }
        ModuleTable->setItem(Row, 3, new QTableWidgetItem(TypeStr));
        ModuleTable->setItem(Row, 4, new QTableWidgetItem(Mod.Path));
    }

    ModuleTable->setSortingEnabled(true);
    ModuleTable->resizeColumnsToContents();
}

void DumperWidget::OnDumpSelected()
{
    if (DumpRunning) return;

    ModuleInfo SelectedMod = GetSelectedModule();
    if (SelectedMod.Base == 0) {
        QMessageBox::information(this, "No Module", "Select a module to dump.");
        return;
    }

    QString OutputPath = OutputPathEdit->text().trimmed();
    if (OutputPath.isEmpty()) {
        QString Timestamp = QDateTime::currentDateTime().toString("yyyy_MM_dd__HH_mm");
        QString SafeName = SelectedMod.Name;
        SafeName.replace(QRegularExpression("[^a-zA-Z0-9._-]"), "_");
        OutputPath = QDir::homePath() + "/" + SafeName + "_" + Timestamp + "_dump";
        if (SelectedMod.Name.endsWith(".dll", Qt::CaseInsensitive)) {
            OutputPath += ".dll";
        } else if (SelectedMod.Name.endsWith(".so", Qt::CaseInsensitive) || SelectedMod.Name.contains(".so.")) {
            OutputPath += ".so";
        } else {
            OutputPath += ".exe";
        }
        OutputPathEdit->setText(OutputPath);
    }

    DumpRunning = true;
    SetDumpControlsEnabled(false);
    CancelBtn->setEnabled(true);
    CoverageBar->setValue(0);
    StatusLabel->setText("Starting dump...");
    LogOutput->clear();
    AppendLog(QString("Dumping %1 @ 0x%2 (%3)")
        .arg(SelectedMod.Name)
        .arg(SelectedMod.Base, 0, 16)
        .arg(FormatSize(SelectedMod.Size)));

    bool Progressive = ProgressiveCheck->isChecked();
    double TargetCoverage = CoverageSpin->value();
    int MaxPasses = MaxPassesSpin->value();
    QString CurrentBaseline = BaselinePath;
    bool UseScatter = ScatterReadCheck->isChecked();

    Dumper->SetScatterGatherEnabled(UseScatter);

    if (!CurrentBaseline.isEmpty()) {
        AppendLog(QString("Using baseline: %1").arg(CurrentBaseline));
        (void)QtConcurrent::run([this, SelectedMod, OutputPath, CurrentBaseline]() {
            Dumper->DumpWithBaseline(SelectedMod, OutputPath, CurrentBaseline);
        });
    } else {
        (void)QtConcurrent::run([this, SelectedMod, OutputPath, Progressive, TargetCoverage, MaxPasses]() {
            if (Progressive) {
                Dumper->DumpModuleProgressive(SelectedMod, OutputPath, TargetCoverage, MaxPasses);
            } else {
                Dumper->DumpModule(SelectedMod, OutputPath);
            }
        });
    }
}

void DumperWidget::OnCancelDump()
{
    if (!DumpRunning) return;
    Dumper->Cancel();
    AppendLog("Dump cancelled by user");
}

void DumperWidget::OnBrowseOutput()
{
    QString Path = QFileDialog::getSaveFileName(this, "Save Dump As", QDir::homePath(),
        "Executables (*.exe *.dll);;ELF (*.so *.elf);;All Files (*)");
    if (!Path.isEmpty()) {
        OutputPathEdit->setText(Path);
    }
}

void DumperWidget::OnProgressUpdate(DumpProgress Progress)
{
    CoverageBar->setMaximum(Progress.TotalPages);
    CoverageBar->setValue(Progress.CapturedPages);
    CoverageBar->setFormat(QString("%1 / %2 pages (%3%)")
        .arg(Progress.CapturedPages)
        .arg(Progress.TotalPages)
        .arg(Progress.CoveragePercent, 0, 'f', 1));

    StatusLabel->setText(QString("Captured: %1 | Encrypted: %2 | Failed: %3 | Coverage: %4%")
        .arg(Progress.CapturedPages)
        .arg(Progress.EncryptedPages)
        .arg(Progress.FailedPages)
        .arg(Progress.CoveragePercent, 0, 'f', 1));
}

void DumperWidget::OnDumperLog(const QString& Message)
{
    AppendLog(Message);
}

void DumperWidget::OnDumpFinished(const QString& OutputPath, double Coverage)
{
    DumpRunning = false;
    SetDumpControlsEnabled(true);
    CancelBtn->setEnabled(false);

    AppendLog(QString("Dump complete: %1 (coverage: %2%)")
        .arg(OutputPath)
        .arg(Coverage, 0, 'f', 1));

    if (Coverage > 0) {
        QByteArray DumpData = Dumper->GetLastDumpBuffer();
        if (!DumpData.isEmpty()) {
            Heatmap->SetData(DumpData, 0);
            BottomTabs->setCurrentWidget(Heatmap);
        }

        if (OpenAfterCheck->isChecked()) {
            emit RequestOpenFile(OutputPath);
            if (CoreRef) {
                CoreRef->Log(QString("Opening dump: %1").arg(OutputPath));
            }
        }

        QMessageBox::information(this, "Dump Complete",
            QString("Module dumped to:\n%1\n\nCoverage: %2%")
                .arg(OutputPath)
                .arg(Coverage, 0, 'f', 1));
    }
}

void DumperWidget::OnModuleDoubleClicked(int Row, int Column)
{
    Q_UNUSED(Column);
    if (Row < 0 || Row >= CurrentModules.size()) return;
    OnDumpSelected();
}

ModuleInfo DumperWidget::GetSelectedModule() const
{
    auto Selected = ModuleTable->selectedItems();
    if (Selected.isEmpty()) return {};

    int Row = Selected.first()->row();
    for (int I = 0; I < CurrentModules.size(); ++I) {
        auto& Mod = CurrentModules[I];
        QString BaseStr = QString("0x%1").arg(Mod.Base, 0, 16);
        auto* BaseItem = ModuleTable->item(Row, 1);
        if (BaseItem && BaseItem->text() == BaseStr) {
            return Mod;
        }
    }
    return {};
}

QString DumperWidget::FormatSize(uint64_t Bytes) const
{
    if (Bytes >= 1024ULL * 1024 * 1024) {
        return QString("%1 GB").arg(static_cast<double>(Bytes) / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
    }
    if (Bytes >= 1024 * 1024) {
        return QString("%1 MB").arg(static_cast<double>(Bytes) / (1024.0 * 1024.0), 0, 'f', 1);
    }
    if (Bytes >= 1024) {
        return QString("%1 KB").arg(static_cast<double>(Bytes) / 1024.0, 0, 'f', 1);
    }
    return QString("%1 B").arg(Bytes);
}

void DumperWidget::SetDumpControlsEnabled(bool Enabled)
{
    DumpBtn->setEnabled(Enabled);
    CoverageSpin->setEnabled(Enabled);
    MaxPassesSpin->setEnabled(Enabled);
    ProgressiveCheck->setEnabled(Enabled);
    FixPeCheck->setEnabled(Enabled);
    OpenAfterCheck->setEnabled(Enabled);
    OutputPathEdit->setEnabled(Enabled);
    BrowseBtn->setEnabled(Enabled);
    DumpAllBtn->setEnabled(Enabled);
    MergeBtn->setEnabled(Enabled);
    LoadBaselineBtn->setEnabled(Enabled);
    ScatterReadCheck->setEnabled(Enabled);
}

void DumperWidget::AppendLog(const QString& Message)
{
    QString Timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    LogOutput->append(QString("[%1] %2").arg(Timestamp, Message));
}

void DumperWidget::OnDumpAll()
{
    if (DumpRunning) return;
    if (!Dumper->IsAttached()) {
        QMessageBox::information(this, "Not Attached", "Attach to a process first.");
        return;
    }

    QString OutputDir = QFileDialog::getExistingDirectory(this, "Select Output Directory", QDir::homePath());
    if (OutputDir.isEmpty()) return;

    DumpRunning = true;
    SetDumpControlsEnabled(false);
    CancelBtn->setEnabled(true);
    CoverageBar->setValue(0);
    StatusLabel->setText("Dumping all modules...");
    AppendLog(QString("Dumping all modules to %1").arg(OutputDir));

    double TargetCoverage = CoverageSpin->value();
    int MaxPasses = MaxPassesSpin->value();
    bool UseScatter = ScatterReadCheck->isChecked();

    Dumper->SetScatterGatherEnabled(UseScatter);

    (void)QtConcurrent::run([this, OutputDir, TargetCoverage, MaxPasses]() {
        Dumper->DumpAllModules(OutputDir, TargetCoverage, MaxPasses);

        QMetaObject::invokeMethod(this, [this]() {
            DumpRunning = false;
            SetDumpControlsEnabled(true);
            CancelBtn->setEnabled(false);
            AppendLog("Batch dump finished");
        }, Qt::QueuedConnection);
    });
}

void DumperWidget::OnMergeDump()
{
    if (DumpRunning) return;

    ModuleInfo SelectedMod = GetSelectedModule();
    if (SelectedMod.Base == 0) {
        QMessageBox::information(this, "No Module", "Select a module to merge dump.");
        return;
    }

    QStringList PreviousDumpPaths = QFileDialog::getOpenFileNames(this, "Select Previous Dumps",
        QDir::homePath(), "Dump Files (*.exe *.dll *.so *.bin);;All Files (*)");
    if (PreviousDumpPaths.isEmpty()) return;

    QString Timestamp = QDateTime::currentDateTime().toString("yyyy_MM_dd__HH_mm");
    QString SafeName = SelectedMod.Name;
    SafeName.replace(QRegularExpression("[^a-zA-Z0-9._-]"), "_");
    QString OutputPath = OutputPathEdit->text().trimmed();
    if (OutputPath.isEmpty()) {
        OutputPath = QDir::homePath() + "/" + SafeName + "_" + Timestamp + "_merged";
        if (SelectedMod.Name.endsWith(".dll", Qt::CaseInsensitive)) {
            OutputPath += ".dll";
        } else if (SelectedMod.Name.endsWith(".so", Qt::CaseInsensitive) || SelectedMod.Name.contains(".so.")) {
            OutputPath += ".so";
        } else {
            OutputPath += ".exe";
        }
        OutputPathEdit->setText(OutputPath);
    }

    DumpRunning = true;
    SetDumpControlsEnabled(false);
    CancelBtn->setEnabled(true);
    CoverageBar->setValue(0);
    StatusLabel->setText("Merge dumping...");
    LogOutput->clear();
    AppendLog(QString("Merge dump: %1 with %2 previous dumps").arg(SelectedMod.Name).arg(PreviousDumpPaths.size()));

    QVector<QString> PrevDumps;
    for (const auto& P : PreviousDumpPaths) {
        PrevDumps.append(P);
    }

    bool UseScatter = ScatterReadCheck->isChecked();
    Dumper->SetScatterGatherEnabled(UseScatter);

    (void)QtConcurrent::run([this, SelectedMod, OutputPath, PrevDumps]() {
        Dumper->DumpWithMerge(SelectedMod, OutputPath, PrevDumps);
    });
}

void DumperWidget::OnLoadBaseline()
{
    QString Path = QFileDialog::getOpenFileName(this, "Load Baseline Dump",
        QDir::homePath(), "Dump Files (*.exe *.dll *.so *.bin);;All Files (*)");
    if (Path.isEmpty()) return;

    BaselinePath = Path;
    AppendLog(QString("Baseline loaded: %1").arg(QFileInfo(Path).fileName()));
    LoadBaselineBtn->setText(QString("Baseline: %1").arg(QFileInfo(Path).fileName()));
}

void DumperWidget::OnProcessAttached(const ProcessInfo& Info)
{
    if (Dumper->IsAttached()) {
        Dumper->Detach();
    }
    if (Dumper->AttachToProcess(Info.Pid)) {
        ProcessInfoLabel->setText(QString("PID: %1 - %2").arg(Info.Pid).arg(Info.Name));
        RefreshModulesBtn->setEnabled(true);
        SetDumpControlsEnabled(true);
        OnRefreshModules();
    }
}

void DumperWidget::OnProcessDetached()
{
    Dumper->Detach();
    ProcessInfoLabel->setText("No process selected");
    RefreshModulesBtn->setEnabled(false);
    SetDumpControlsEnabled(false);
    ModuleTable->setRowCount(0);
    CurrentModules.clear();
}

}
