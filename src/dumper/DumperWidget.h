#pragma once

#include <fidra/ICore.h>
#include "ProcessDumper.h"
#include "HeatmapWidget.h"
#include <QWidget>
#include <QTableWidget>
#include <QProgressBar>
#include <QLabel>
#include <QPushButton>
#include <QDoubleSpinBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QLineEdit>
#include <QTextEdit>
#include <QVector>
#include <QTabWidget>

namespace Fidra {

class DumperWidget : public QWidget {
    Q_OBJECT

public:
    explicit DumperWidget(QWidget* Parent, ICore* Core);
    ~DumperWidget() override;

    void OnProcessAttached(const ProcessInfo& Info);
    void OnProcessDetached();

signals:
    void RequestOpenFile(const QString& FilePath);

private slots:
    void OnSelectProcess();
    void OnRefreshModules();
    void OnDumpSelected();
    void OnCancelDump();
    void OnBrowseOutput();
    void OnProgressUpdate(DumpProgress Progress);
    void OnDumperLog(const QString& Message);
    void OnDumpFinished(const QString& OutputPath, double Coverage);
    void OnModuleDoubleClicked(int Row, int Column);
    void OnDumpAll();
    void OnMergeDump();
    void OnLoadBaseline();

private:
    void SetupUi();
    void PopulateModuleTable(const QVector<ModuleInfo>& Modules);
    ModuleInfo GetSelectedModule() const;
    QString FormatSize(uint64_t Bytes) const;
    void SetDumpControlsEnabled(bool Enabled);
    void AppendLog(const QString& Message);

    ICore* CoreRef;
    ProcessDumper* Dumper;
    QVector<ModuleInfo> CurrentModules;
    bool DumpRunning;

    QLabel* ProcessInfoLabel;
    QPushButton* SelectProcessBtn;
    QPushButton* RefreshModulesBtn;

    QTableWidget* ModuleTable;

    QDoubleSpinBox* CoverageSpin;
    QSpinBox* MaxPassesSpin;
    QCheckBox* ProgressiveCheck;
    QCheckBox* FixPeCheck;
    QCheckBox* OpenAfterCheck;
    QLineEdit* OutputPathEdit;
    QPushButton* BrowseBtn;
    QPushButton* DumpBtn;
    QPushButton* CancelBtn;

    QPushButton* DumpAllBtn;
    QPushButton* MergeBtn;
    QPushButton* LoadBaselineBtn;
    QCheckBox* ScatterReadCheck;
    QString BaselinePath;

    QProgressBar* CoverageBar;
    QLabel* StatusLabel;
    QTextEdit* LogOutput;

    HeatmapWidget* Heatmap;
    QTabWidget* BottomTabs;
};

}
