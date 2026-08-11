#include "CoverageWidget.h"
#include <QHeaderView>
#include <QMenu>
#include <QAction>
#include <QFileDialog>
#include <QMessageBox>
#include <QTextStream>
#include <QFile>
#include <QPainter>
#include <QScrollArea>
#include <QApplication>
#include <QClipboard>
#include <algorithm>
#include <cmath>
#include <cstring>

namespace Fidra {

CoverageWidget::CoverageWidget(QWidget* Parent)
    : QWidget(Parent)
    , MainLayout(new QVBoxLayout(this))
    , ToolBar(nullptr)
    , MainSplitter(nullptr)
    , SummaryPanel(nullptr)
    , FunctionSummaryLabel(nullptr)
    , BlockSummaryLabel(nullptr)
    , FunctionProgressBar(nullptr)
    , BlockProgressBar(nullptr)
    , FunctionTree(nullptr)
    , HeatMapPanel(nullptr)
    , HeatMapLayout(nullptr)
    , DbRef(nullptr)
    , HasCompareData(false)
{
    MainLayout->setContentsMargins(0, 0, 0, 0);
    MainLayout->setSpacing(0);

    SetupToolBar();
    SetupSummary();

    MainSplitter = new QSplitter(Qt::Horizontal, this);

    SetupFunctionTree();
    MainSplitter->addWidget(FunctionTree);

    SetupHeatMap();
    MainSplitter->addWidget(HeatMapPanel);

    MainSplitter->setStretchFactor(0, 2);
    MainSplitter->setStretchFactor(1, 1);

    MainLayout->addWidget(MainSplitter);
    SetupContextMenu();
}

void CoverageWidget::LoadCoverage(const QMap<Address, uint64_t>& Counts, AnalysisDatabase* Db) {
    DbRef = Db;
    RawCounts = Counts;
    BuildCoverageData(Counts, Db);
    RefreshDisplay();
}

void CoverageWidget::LoadFromFile(const QString& Path, AnalysisDatabase* Db) {
    DbRef = Db;
    QMap<Address, uint64_t> Counts;

    Address ImageBase = 0;
    if (Db) {
        ImageBase = Db->GetBinaryInfo().ImageBase;
    }

    bool Ok = false;
    if (Path.endsWith(".log") || Path.endsWith(".drcov")) {
        Ok = ParseDrcov(Path, Counts, ImageBase);
    } else if (Path.endsWith(".lcov") || Path.endsWith(".info")) {
        Ok = ParseLcov(Path, Counts);
    } else {
        Ok = ParseDrcov(Path, Counts, ImageBase);
        if (!Ok) {
            Ok = ParseLcov(Path, Counts);
        }
    }

    if (!Ok || Counts.isEmpty()) {
        QMessageBox::warning(this, "Coverage Error", "Failed to parse coverage file.");
        return;
    }

    RawCounts = Counts;
    BuildCoverageData(Counts, Db);
    RefreshDisplay();
}

void CoverageWidget::LoadFromTrace(TraceEngine* Trace, AnalysisDatabase* Db) {
    if (!Trace) return;
    LoadCoverage(Trace->GetExecutionCounts(), Db);
}

void CoverageWidget::SetupToolBar() {
    ToolBar = new QToolBar(this);
    ToolBar->setIconSize(QSize(16, 16));

    auto* LoadAction = ToolBar->addAction("Load Coverage");
    LoadAction->setIcon(style()->standardIcon(QStyle::SP_DialogOpenButton));
    connect(LoadAction, &QAction::triggered, this, &CoverageWidget::OnLoadFile);

    auto* ExportAction = ToolBar->addAction("Export HTML");
    ExportAction->setIcon(style()->standardIcon(QStyle::SP_DialogSaveButton));
    connect(ExportAction, &QAction::triggered, this, &CoverageWidget::OnExportHtml);

    ToolBar->addSeparator();

    auto* CompareAction = ToolBar->addAction("Compare...");
    CompareAction->setIcon(style()->standardIcon(QStyle::SP_FileDialogContentsView));
    connect(CompareAction, &QAction::triggered, this, &CoverageWidget::OnCompareCoverage);

    MainLayout->addWidget(ToolBar);
}

void CoverageWidget::SetupSummary() {
    SummaryPanel = new QWidget(this);
    auto* SummaryLayout = new QVBoxLayout(SummaryPanel);
    SummaryLayout->setContentsMargins(8, 4, 8, 4);

    auto* FuncRow = new QHBoxLayout();
    FunctionSummaryLabel = new QLabel("Functions: 0/0 (0%)", SummaryPanel);
    FuncRow->addWidget(FunctionSummaryLabel);
    FunctionProgressBar = new QProgressBar(SummaryPanel);
    FunctionProgressBar->setRange(0, 100);
    FunctionProgressBar->setValue(0);
    FunctionProgressBar->setTextVisible(true);
    FuncRow->addWidget(FunctionProgressBar);
    SummaryLayout->addLayout(FuncRow);

    auto* BlockRow = new QHBoxLayout();
    BlockSummaryLabel = new QLabel("Blocks: 0/0 (0%)", SummaryPanel);
    BlockRow->addWidget(BlockSummaryLabel);
    BlockProgressBar = new QProgressBar(SummaryPanel);
    BlockProgressBar->setRange(0, 100);
    BlockProgressBar->setValue(0);
    BlockProgressBar->setTextVisible(true);
    BlockRow->addWidget(BlockProgressBar);
    SummaryLayout->addLayout(BlockRow);

    MainLayout->addWidget(SummaryPanel);
}

void CoverageWidget::SetupFunctionTree() {
    FunctionTree = new QTreeWidget(this);
    FunctionTree->setHeaderLabels({"Function", "Blocks Covered", "%", "Hit Count"});
    FunctionTree->setAlternatingRowColors(true);
    FunctionTree->header()->setStretchLastSection(true);
    FunctionTree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    FunctionTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    FunctionTree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    FunctionTree->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    FunctionTree->setRootIsDecorated(true);
    FunctionTree->setSortingEnabled(true);
    FunctionTree->setContextMenuPolicy(Qt::CustomContextMenu);

    connect(FunctionTree, &QTreeWidget::itemDoubleClicked, this, &CoverageWidget::OnFunctionDoubleClicked);
}

void CoverageWidget::SetupHeatMap() {
    HeatMapPanel = new QWidget(this);
    HeatMapLayout = new QVBoxLayout(HeatMapPanel);
    HeatMapLayout->setContentsMargins(4, 4, 4, 4);

    auto* HeatTitle = new QLabel("Block Heat Map", HeatMapPanel);
    HeatTitle->setAlignment(Qt::AlignCenter);
    QFont TitleFont = HeatTitle->font();
    TitleFont.setBold(true);
    HeatTitle->setFont(TitleFont);
    HeatMapLayout->addWidget(HeatTitle);
}

void CoverageWidget::SetupContextMenu() {
    connect(FunctionTree, &QTreeWidget::customContextMenuRequested, this, &CoverageWidget::OnContextMenu);
}

void CoverageWidget::OnLoadFile() {
    QString Path = QFileDialog::getOpenFileName(this, "Load Coverage Data", QString(),
        "Coverage Files (*.drcov *.log *.lcov *.info);;All Files (*)");
    if (Path.isEmpty()) return;

    LoadFromFile(Path, DbRef);
}

void CoverageWidget::OnExportHtml() {
    QString Path = QFileDialog::getSaveFileName(this, "Export Coverage Report", QString(),
        "HTML Files (*.html);;All Files (*)");
    if (Path.isEmpty()) return;

    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "Export Error", "Failed to create HTML file.");
        return;
    }

    QTextStream Stream(&File);
    Stream << GenerateHtmlReport();
}

void CoverageWidget::OnCompareCoverage() {
    QString Path = QFileDialog::getOpenFileName(this, "Load Comparison Coverage", QString(),
        "Coverage Files (*.drcov *.log *.lcov *.info);;All Files (*)");
    if (Path.isEmpty()) return;

    QMap<Address, uint64_t> CompareCounts;
    Address ImageBase = DbRef ? DbRef->GetBinaryInfo().ImageBase : 0;

    bool Ok = ParseDrcov(Path, CompareCounts, ImageBase);
    if (!Ok) {
        Ok = ParseLcov(Path, CompareCounts);
    }

    if (!Ok || CompareCounts.isEmpty()) {
        QMessageBox::warning(this, "Compare Error", "Failed to parse comparison coverage file.");
        return;
    }

    CompareSnapshot.Name = Path;
    CompareSnapshot.Counts = CompareCounts;
    HasCompareData = true;

    QMap<Address, uint64_t> NewCoverage;
    for (auto It = CompareCounts.constBegin(); It != CompareCounts.constEnd(); ++It) {
        if (!RawCounts.contains(It.key())) {
            NewCoverage[It.key()] = It.value();
        }
    }

    if (NewCoverage.isEmpty()) {
        QMessageBox::information(this, "Coverage Diff", "No new coverage found in comparison file.");
    } else {
        QMessageBox::information(this, "Coverage Diff",
            QString("%1 new addresses covered in comparison file.").arg(NewCoverage.size()));
    }

    RefreshDisplay();
}

void CoverageWidget::OnFunctionDoubleClicked(QTreeWidgetItem* Item, int Column) {
    Q_UNUSED(Column);
    if (!Item) return;

    bool Ok = false;
    Address Addr = Item->data(0, Qt::UserRole).toULongLong(&Ok);
    if (Ok && Addr != 0) {
        emit NavigateToAddress(Addr);
    }
}

void CoverageWidget::OnContextMenu(const QPoint& Pos) {
    auto* Item = FunctionTree->itemAt(Pos);
    if (!Item) return;

    bool Ok = false;
    Address Addr = Item->data(0, Qt::UserRole).toULongLong(&Ok);
    if (!Ok) return;

    QMenu Menu(this);

    auto* GoToAction = Menu.addAction("Go to Function");
    connect(GoToAction, &QAction::triggered, this, [this, Addr]() {
        emit NavigateToAddress(Addr);
    });

    auto* CopyAction = Menu.addAction("Copy Address");
    connect(CopyAction, &QAction::triggered, this, [Addr]() {
        QApplication::clipboard()->setText(QString("0x%1").arg(Addr, 16, 16, QChar('0')));
    });

    Menu.exec(FunctionTree->viewport()->mapToGlobal(Pos));
}

void CoverageWidget::BuildCoverageData(const QMap<Address, uint64_t>& Counts, AnalysisDatabase* Db) {
    CoverageData.clear();

    if (!Db) return;

    auto AllFunctions = Db->GetAllFunctions();

    CurrentSnapshot.TotalFunctions = AllFunctions.size();
    CurrentSnapshot.CoveredFunctions = 0;
    CurrentSnapshot.TotalBlocks = 0;
    CurrentSnapshot.CoveredBlocks = 0;
    CurrentSnapshot.Counts = Counts;

    for (const auto& Func : AllFunctions) {
        FunctionCoverage FuncCov;
        FuncCov.FunctionAddr = Func.Start;
        FuncCov.FunctionName = Func.DemangledName.isEmpty() ? Func.Name : Func.DemangledName;
        FuncCov.TotalBlocks = Func.Blocks.size();
        FuncCov.CoveredBlocks = 0;
        FuncCov.TotalHitCount = 0;

        for (const auto& Block : Func.Blocks) {
            CurrentSnapshot.TotalBlocks++;
            bool BlockCovered = false;

            for (Address Addr = Block.Start; Addr < Block.End; ++Addr) {
                if (Counts.contains(Addr)) {
                    uint64_t Hits = Counts[Addr];
                    FuncCov.BlockHits[Block.Start] += Hits;
                    FuncCov.TotalHitCount += Hits;
                    BlockCovered = true;
                }
            }

            if (BlockCovered) {
                FuncCov.CoveredBlocks++;
                CurrentSnapshot.CoveredBlocks++;
            }
        }

        if (FuncCov.TotalBlocks > 0) {
            FuncCov.CoveragePercent = (static_cast<double>(FuncCov.CoveredBlocks) / FuncCov.TotalBlocks) * 100.0;
        } else {
            FuncCov.CoveragePercent = 0.0;
        }

        if (FuncCov.CoveredBlocks > 0) {
            CurrentSnapshot.CoveredFunctions++;
        }

        CoverageData.append(FuncCov);
    }

    std::sort(CoverageData.begin(), CoverageData.end(),
              [](const FunctionCoverage& A, const FunctionCoverage& B) {
                  return A.CoveragePercent > B.CoveragePercent;
              });
}

void CoverageWidget::RefreshDisplay() {
    UpdateSummary();
    UpdateFunctionTree();
    UpdateHeatMap();
}

void CoverageWidget::UpdateSummary() {
    int TotalFuncs = CurrentSnapshot.TotalFunctions;
    int CoveredFuncs = CurrentSnapshot.CoveredFunctions;
    double FuncPercent = TotalFuncs > 0 ? (static_cast<double>(CoveredFuncs) / TotalFuncs) * 100.0 : 0.0;

    FunctionSummaryLabel->setText(QString("Functions: %1/%2 (%3%)")
        .arg(CoveredFuncs).arg(TotalFuncs).arg(FuncPercent, 0, 'f', 1));
    FunctionProgressBar->setValue(static_cast<int>(FuncPercent));

    int TotalBlocks = CurrentSnapshot.TotalBlocks;
    int CoveredBlocks = CurrentSnapshot.CoveredBlocks;
    double BlockPercent = TotalBlocks > 0 ? (static_cast<double>(CoveredBlocks) / TotalBlocks) * 100.0 : 0.0;

    BlockSummaryLabel->setText(QString("Blocks: %1/%2 (%3%)")
        .arg(CoveredBlocks).arg(TotalBlocks).arg(BlockPercent, 0, 'f', 1));
    BlockProgressBar->setValue(static_cast<int>(BlockPercent));
}

void CoverageWidget::UpdateFunctionTree() {
    FunctionTree->clear();

    for (const auto& FuncCov : CoverageData) {
        auto* Item = new QTreeWidgetItem(FunctionTree);
        Item->setText(0, FuncCov.FunctionName);
        Item->setText(1, QString("%1/%2").arg(FuncCov.CoveredBlocks).arg(FuncCov.TotalBlocks));
        Item->setText(2, QString("%1%").arg(FuncCov.CoveragePercent, 0, 'f', 1));
        Item->setText(3, QString::number(FuncCov.TotalHitCount));
        Item->setData(0, Qt::UserRole, static_cast<qulonglong>(FuncCov.FunctionAddr));

        Item->setForeground(2, QBrush(CoverageColor(FuncCov.CoveragePercent)));

        QFont BoldFont = Item->font(2);
        BoldFont.setBold(true);
        Item->setFont(2, BoldFont);

        if (HasCompareData) {
            bool WasUncovered = (FuncCov.CoveredBlocks == 0);
            bool NowCoveredInCompare = false;

            for (auto It = FuncCov.BlockHits.constBegin(); It != FuncCov.BlockHits.constEnd(); ++It) {
                if (CompareSnapshot.Counts.contains(It.key()) && !RawCounts.contains(It.key())) {
                    NowCoveredInCompare = true;
                    break;
                }
            }

            if (NowCoveredInCompare && WasUncovered) {
                Item->setBackground(0, QColor(0, 255, 0, 40));
            }
        }

        for (auto It = FuncCov.BlockHits.constBegin(); It != FuncCov.BlockHits.constEnd(); ++It) {
            auto* BlockItem = new QTreeWidgetItem(Item);
            BlockItem->setText(0, QString("0x%1").arg(It.key(), 16, 16, QChar('0')));
            BlockItem->setText(1, "1/1");
            BlockItem->setText(2, "100%");
            BlockItem->setText(3, QString::number(It.value()));
            BlockItem->setData(0, Qt::UserRole, static_cast<qulonglong>(It.key()));
        }
    }
}

void CoverageWidget::UpdateHeatMap() {
    while (HeatMapLayout->count() > 1) {
        auto* Item = HeatMapLayout->takeAt(1);
        if (Item->widget()) {
            delete Item->widget();
        }
        delete Item;
    }

    if (CoverageData.isEmpty()) return;

    uint64_t MaxHits = 0;
    for (const auto& FuncCov : CoverageData) {
        for (auto It = FuncCov.BlockHits.constBegin(); It != FuncCov.BlockHits.constEnd(); ++It) {
            if (It.value() > MaxHits) {
                MaxHits = It.value();
            }
        }
    }

    int DisplayCount = 0;
    for (const auto& FuncCov : CoverageData) {
        if (FuncCov.CoveredBlocks == 0) continue;
        if (DisplayCount >= 25) break;

        auto* FuncLabel = new QLabel(FuncCov.FunctionName, HeatMapPanel);
        FuncLabel->setMaximumHeight(16);
        QFont SmallFont = FuncLabel->font();
        SmallFont.setPointSize(8);
        FuncLabel->setFont(SmallFont);
        HeatMapLayout->addWidget(FuncLabel);

        auto* BarWidget = new QWidget(HeatMapPanel);
        BarWidget->setFixedHeight(12);
        BarWidget->setMinimumWidth(100);

        int TotalBlocks = FuncCov.TotalBlocks;
        if (TotalBlocks == 0) TotalBlocks = 1;

        QString Gradient = "background: qlineargradient(x1:0, y1:0, x2:1, y2:0";
        for (int I = 0; I < FuncCov.TotalBlocks; ++I) {
            double Pos = static_cast<double>(I) / TotalBlocks;
            QColor Color(60, 60, 60);

            auto BlockIt = FuncCov.BlockHits.constBegin();
            int BlockIdx = 0;
            for (; BlockIt != FuncCov.BlockHits.constEnd(); ++BlockIt, ++BlockIdx) {
                if (BlockIdx == I && BlockIt.value() > 0) {
                    Color = HeatColor(BlockIt.value(), MaxHits);
                    break;
                }
            }

            Gradient += QString(", stop:%1 %2").arg(Pos, 0, 'f', 4).arg(Color.name());
        }
        Gradient += ");";

        BarWidget->setStyleSheet(Gradient);
        HeatMapLayout->addWidget(BarWidget);

        DisplayCount++;
    }

    HeatMapLayout->addStretch();
}

bool CoverageWidget::ParseDrcov(const QString& Path, QMap<Address, uint64_t>& OutCounts, Address ImageBase) {
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return false;
    }

    QTextStream Stream(&File);
    QString Line = Stream.readLine();

    if (!Line.startsWith("DRCOV VERSION:")) {
        return false;
    }

    struct ModuleEntry {
        int Id;
        Address Base;
        Address End;
        QString Path;
    };

    QVector<ModuleEntry> Modules;
    bool InModuleTable = false;
    int ModuleCount = 0;
    int BbCount = 0;

    while (!Stream.atEnd()) {
        Line = Stream.readLine();

        if (Line.startsWith("Module Table:")) {
            QStringList Parts = Line.split(' ', Qt::SkipEmptyParts);
            for (const auto& Part : Parts) {
                bool Ok = false;
                int Num = Part.toInt(&Ok);
                if (Ok) {
                    ModuleCount = Num;
                    break;
                }
            }
            InModuleTable = true;
            if (Line.contains("version")) {
                Line = Stream.readLine();
            }
            continue;
        }

        if (Line.startsWith("BB Table:")) {
            InModuleTable = false;
            QStringList Parts = Line.split(' ', Qt::SkipEmptyParts);
            for (const auto& Part : Parts) {
                bool Ok = false;
                int Num = Part.toInt(&Ok);
                if (Ok) {
                    BbCount = Num;
                    break;
                }
            }

            QByteArray BbData = File.read(BbCount * 8);
            if (BbData.size() < BbCount * 8) {
                return false;
            }

            const uint8_t* DataPtr = reinterpret_cast<const uint8_t*>(BbData.constData());
            for (int I = 0; I < BbCount; ++I) {
                uint32_t Start = 0;
                uint16_t Size = 0;
                uint16_t ModId = 0;

                memcpy(&Start, DataPtr + I * 8, 4);
                memcpy(&Size, DataPtr + I * 8 + 4, 2);
                memcpy(&ModId, DataPtr + I * 8 + 6, 2);

                Address ModBase = ImageBase;
                if (ModId < static_cast<uint16_t>(Modules.size())) {
                    ModBase = Modules[ModId].Base;
                }

                Address AbsAddr = ModBase + Start;
                for (uint16_t Off = 0; Off < Size; ++Off) {
                    OutCounts[AbsAddr + Off]++;
                }
            }

            return true;
        }

        if (InModuleTable) {
            QStringList Parts = Line.split(',', Qt::SkipEmptyParts);
            if (Parts.size() >= 4) {
                ModuleEntry Mod;
                bool Ok1 = false;
                Mod.Id = Parts[0].trimmed().toInt();
                Mod.Base = Parts[1].trimmed().toULongLong(&Ok1, 16);
                Mod.End = Parts[2].trimmed().toULongLong(nullptr, 16);
                Mod.Path = Parts.last().trimmed();
                if (Ok1) {
                    Modules.append(Mod);
                }
            }
        }
    }

    return !OutCounts.isEmpty();
}

bool CoverageWidget::ParseLcov(const QString& Path, QMap<Address, uint64_t>& OutCounts) {
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return false;
    }

    QTextStream Stream(&File);

    while (!Stream.atEnd()) {
        QString Line = Stream.readLine().trimmed();

        if (Line.startsWith("DA:")) {
            QStringList Parts = Line.mid(3).split(',');
            if (Parts.size() >= 2) {
                bool Ok1 = false, Ok2 = false;
                Address LineNum = Parts[0].trimmed().toULongLong(&Ok1);
                uint64_t HitCount = Parts[1].trimmed().toULongLong(&Ok2);
                if (Ok1 && Ok2 && HitCount > 0) {
                    OutCounts[LineNum] += HitCount;
                }
            }
        }
    }

    return !OutCounts.isEmpty();
}

QColor CoverageWidget::CoverageColor(double Percent) const {
    if (Percent <= 0.0) return QColor(220, 50, 50);
    if (Percent >= 100.0) return QColor(50, 180, 50);

    int R, G;
    if (Percent < 50.0) {
        R = 220;
        G = static_cast<int>(50 + (Percent / 50.0) * 170);
    } else {
        R = static_cast<int>(220 - ((Percent - 50.0) / 50.0) * 170);
        G = 180;
    }
    return QColor(R, G, 50);
}

QColor CoverageWidget::HeatColor(uint64_t Hits, uint64_t MaxHits) const {
    if (MaxHits == 0) return QColor(50, 50, 200);

    double Ratio = static_cast<double>(Hits) / MaxHits;

    int R = static_cast<int>(50 + Ratio * 205);
    int G = static_cast<int>(50 + (1.0 - std::abs(Ratio - 0.5) * 2.0) * 100);
    int B = static_cast<int>(200 - Ratio * 150);

    return QColor(qBound(0, R, 255), qBound(0, G, 255), qBound(0, B, 255));
}

QString CoverageWidget::GenerateHtmlReport() const {
    QString Html;
    QTextStream Out(&Html);

    Out << "<!DOCTYPE html>\n<html>\n<head>\n<title>Aida Coverage Report</title>\n";
    Out << "<style>\n";
    Out << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 20px; background: #1e1e2e; color: #cdd6f4; }\n";
    Out << "h1 { color: #89b4fa; }\n";
    Out << "table { border-collapse: collapse; width: 100%; margin-top: 16px; }\n";
    Out << "th { background: #313244; color: #cdd6f4; padding: 8px 12px; text-align: left; border-bottom: 2px solid #45475a; }\n";
    Out << "td { padding: 6px 12px; border-bottom: 1px solid #313244; }\n";
    Out << "tr:hover { background: #313244; }\n";
    Out << ".summary { background: #313244; border-radius: 8px; padding: 16px; margin-bottom: 16px; }\n";
    Out << ".bar { height: 16px; border-radius: 4px; background: #45475a; position: relative; }\n";
    Out << ".bar-fill { height: 100%; border-radius: 4px; }\n";
    Out << ".pct-0 { background: #f38ba8; }\n";
    Out << ".pct-50 { background: #f9e2af; }\n";
    Out << ".pct-100 { background: #a6e3a1; }\n";
    Out << "</style>\n</head>\n<body>\n";

    Out << "<h1>Aida Coverage Report</h1>\n";

    Out << "<div class='summary'>\n";
    Out << "<p>Functions covered: " << CurrentSnapshot.CoveredFunctions << " / " << CurrentSnapshot.TotalFunctions;
    if (CurrentSnapshot.TotalFunctions > 0) {
        Out << " (" << QString::number((static_cast<double>(CurrentSnapshot.CoveredFunctions) / CurrentSnapshot.TotalFunctions) * 100.0, 'f', 1) << "%)";
    }
    Out << "</p>\n";

    Out << "<p>Blocks covered: " << CurrentSnapshot.CoveredBlocks << " / " << CurrentSnapshot.TotalBlocks;
    if (CurrentSnapshot.TotalBlocks > 0) {
        Out << " (" << QString::number((static_cast<double>(CurrentSnapshot.CoveredBlocks) / CurrentSnapshot.TotalBlocks) * 100.0, 'f', 1) << "%)";
    }
    Out << "</p>\n</div>\n";

    Out << "<table>\n<tr><th>Function</th><th>Blocks Covered</th><th>Coverage</th><th>Hit Count</th></tr>\n";

    for (const auto& FuncCov : CoverageData) {
        QString PctClass;
        if (FuncCov.CoveragePercent >= 80.0) PctClass = "pct-100";
        else if (FuncCov.CoveragePercent >= 40.0) PctClass = "pct-50";
        else PctClass = "pct-0";

        Out << "<tr><td>" << FuncCov.FunctionName.toHtmlEscaped() << "</td>";
        Out << "<td>" << FuncCov.CoveredBlocks << "/" << FuncCov.TotalBlocks << "</td>";
        Out << "<td><div class='bar'><div class='bar-fill " << PctClass << "' style='width:" << QString::number(FuncCov.CoveragePercent, 'f', 1) << "%'></div></div> " << QString::number(FuncCov.CoveragePercent, 'f', 1) << "%</td>";
        Out << "<td>" << FuncCov.TotalHitCount << "</td></tr>\n";
    }

    Out << "</table>\n</body>\n</html>\n";

    return Html;
}

}
