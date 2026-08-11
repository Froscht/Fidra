#pragma once

#include "TraceEngine.h"
#include <fidra/Types.h>
#include <QWidget>
#include <QTableView>
#include <QAbstractTableModel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QToolBar>
#include <QLineEdit>
#include <QSlider>
#include <QLabel>
#include <QSplitter>
#include <QTreeWidget>
#include <QComboBox>
#include <QPushButton>

namespace Fidra {

class TraceTableModel : public QAbstractTableModel {
    Q_OBJECT

public:
    explicit TraceTableModel(QObject* Parent = nullptr);

    int rowCount(const QModelIndex& Parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& Parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& Index, int Role = Qt::DisplayRole) const override;
    QVariant headerData(int Section, Qt::Orientation Orientation, int Role = Qt::DisplayRole) const override;

    void SetEntries(const QVector<TraceEntry>* EntriesPtr);
    void Refresh();
    void SetHighlightIndex(int Index);

private:
    const QVector<TraceEntry>* SourceEntries;
    int HighlightRow;
};

class TraceWidget : public QWidget {
    Q_OBJECT

public:
    explicit TraceWidget(QWidget* Parent = nullptr);
    ~TraceWidget() override = default;

    void SetEngine(TraceEngine* Engine);

signals:
    void NavigateToAddress(Address Addr);

public slots:
    void OnTraceProgress(uint64_t Count);
    void OnTraceStopped(uint64_t TotalEntries);
    void OnTraceError(const QString& Error);

private:
    void SetupToolBar();
    void SetupTraceView();
    void SetupSearchBar();
    void SetupTimeline();
    void SetupStatistics();
    void SetupContextMenu();

    void OnStartTrace();
    void OnStopTrace();
    void OnClearTrace();
    void OnSaveTrace();
    void OnLoadTrace();
    void OnSearch();
    void OnTimelineChanged(int Value);
    void OnDoubleClicked(const QModelIndex& Index);
    void OnContextMenu(const QPoint& Pos);

    void ShowFilterDialog();
    void RefreshView();
    void UpdateStatistics();

    TraceEngine* EngineRef;
    QVector<TraceEntry> DisplayEntries;

    QVBoxLayout* MainLayout;
    QToolBar* ToolBar;
    QSplitter* MainSplitter;

    QTableView* TraceTable;
    TraceTableModel* TableModel;

    QWidget* SearchPanel;
    QHBoxLayout* SearchLayout;
    QComboBox* SearchTypeCombo;
    QLineEdit* SearchEdit;

    QSlider* TimelineSlider;
    QLabel* TimelineLabel;

    QTreeWidget* StatsTree;
    QLabel* StatusLabel;

    TraceFilter CurrentFilter;
    int TargetPid;
};

}
