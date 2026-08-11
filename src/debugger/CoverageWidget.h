#pragma once

#include "TraceEngine.h"
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <fidra/Types.h>
#include <QWidget>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QToolBar>
#include <QLabel>
#include <QSplitter>
#include <QProgressBar>
#include <QPushButton>

namespace Fidra {

struct FunctionCoverage {
    Address FunctionAddr;
    QString FunctionName;
    int TotalBlocks;
    int CoveredBlocks;
    double CoveragePercent;
    uint64_t TotalHitCount;
    QMap<Address, uint64_t> BlockHits;
};

struct CoverageSnapshot {
    QString Name;
    QMap<Address, uint64_t> Counts;
    int TotalFunctions;
    int CoveredFunctions;
    int TotalBlocks;
    int CoveredBlocks;
};

class CoverageWidget : public QWidget {
    Q_OBJECT

public:
    explicit CoverageWidget(QWidget* Parent = nullptr);
    ~CoverageWidget() override = default;

    void LoadCoverage(const QMap<Address, uint64_t>& Counts, AnalysisDatabase* Db);
    void LoadFromFile(const QString& Path, AnalysisDatabase* Db);
    void LoadFromTrace(TraceEngine* Trace, AnalysisDatabase* Db);

signals:
    void NavigateToAddress(Address Addr);

private:
    void SetupToolBar();
    void SetupSummary();
    void SetupFunctionTree();
    void SetupHeatMap();
    void SetupContextMenu();

    void OnLoadFile();
    void OnExportHtml();
    void OnCompareCoverage();
    void OnFunctionDoubleClicked(QTreeWidgetItem* Item, int Column);
    void OnContextMenu(const QPoint& Pos);

    void BuildCoverageData(const QMap<Address, uint64_t>& Counts, AnalysisDatabase* Db);
    void RefreshDisplay();
    void UpdateSummary();
    void UpdateFunctionTree();
    void UpdateHeatMap();

    bool ParseDrcov(const QString& Path, QMap<Address, uint64_t>& OutCounts, Address ImageBase);
    bool ParseLcov(const QString& Path, QMap<Address, uint64_t>& OutCounts);

    QColor CoverageColor(double Percent) const;
    QColor HeatColor(uint64_t Hits, uint64_t MaxHits) const;
    QString GenerateHtmlReport() const;

    QVBoxLayout* MainLayout;
    QToolBar* ToolBar;
    QSplitter* MainSplitter;

    QWidget* SummaryPanel;
    QLabel* FunctionSummaryLabel;
    QLabel* BlockSummaryLabel;
    QProgressBar* FunctionProgressBar;
    QProgressBar* BlockProgressBar;

    QTreeWidget* FunctionTree;

    QWidget* HeatMapPanel;
    QVBoxLayout* HeatMapLayout;

    QVector<FunctionCoverage> CoverageData;
    QMap<Address, uint64_t> RawCounts;
    AnalysisDatabase* DbRef;

    CoverageSnapshot CurrentSnapshot;
    CoverageSnapshot CompareSnapshot;
    bool HasCompareData;
};

}
