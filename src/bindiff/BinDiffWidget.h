#pragma once

#include "BinDiffEngine.h"
#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QScrollBar>
#include <QLabel>
#include <QTableWidget>
#include <QSplitter>

namespace Fidra {

class HexDiffView : public QWidget {
    Q_OBJECT
public:
    explicit HexDiffView(QWidget* Parent = nullptr);

    void SetData(const QByteArray& FileData, const QVector<DiffRegion>& Regions, bool IsLeftSide);
    void SetScrollValue(int Value);
    int TotalRows() const;
    int VisibleRows() const;
    void ScrollToOffset(uint64_t Offset);
    int CurrentScroll() const;

signals:
    void ScrollChanged(int Value);

protected:
    void paintEvent(QPaintEvent* Event) override;
    void resizeEvent(QResizeEvent* Event) override;
    void wheelEvent(QWheelEvent* Event) override;

private:
    QColor ColorForOffset(uint64_t Offset) const;
    void UpdateScrollBar();

    QByteArray Data;
    QVector<DiffRegion> DiffRegions;
    bool LeftSide;
    QScrollBar* VerticalScroll;
    int BytesPerRow;
    int RowHeight;
    int HeaderWidth;
    int CellWidth;
    int AsciiCellWidth;
};

class BinDiffWidget : public QWidget {
    Q_OBJECT
public:
    explicit BinDiffWidget(QWidget* Parent = nullptr);

    void SetDatabases(AnalysisDatabase* Db1, AnalysisDatabase* Db2);

private:
    void OnBrowseFile1();
    void OnBrowseFile2();
    void OnCompare();
    void OnNextDiff();
    void OnPrevDiff();
    void OnLeftScrollChanged(int Value);
    void OnRightScrollChanged(int Value);
    void UpdateSummary();
    void PopulateFunctionTable();
    int FindNextDiffOffset(uint64_t CurrentOffset, bool Forward) const;

    QLineEdit* File1Path;
    QLineEdit* File2Path;
    QPushButton* BrowseBtn1;
    QPushButton* BrowseBtn2;
    QPushButton* CompareBtn;
    QPushButton* NextDiffBtn;
    QPushButton* PrevDiffBtn;

    HexDiffView* LeftView;
    HexDiffView* RightView;

    QLabel* SummaryLabel;
    QTableWidget* FunctionTable;
    QSplitter* MainSplitter;

    BinDiffEngine* Engine;
    DiffResult CurrentResult;
    bool SyncingScroll;

    AnalysisDatabase* Db1Ref;
    AnalysisDatabase* Db2Ref;
};

}
