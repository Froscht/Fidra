#pragma once

#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <QWidget>
#include <QLineEdit>
#include <QSpinBox>
#include <QAction>

namespace Fidra {

struct GraphNode {
    Address Addr;
    QString Name;
    QPointF Pos;
    QSizeF Size;
    bool Selected;
    int Layer;
    bool IsImported;
    bool IsExported;
    bool IsThunk;
};

struct GraphEdge {
    int FromIdx;
    int ToIdx;
};

class CallGraphCanvas : public QWidget {
    Q_OBJECT
public:
    explicit CallGraphCanvas(QWidget* Parent = nullptr);

    void SetGraph(const QList<GraphNode>& NodeList, const QList<GraphEdge>& EdgeList);
    void CenterOnNode(int Index);
    void FitToWindow();
    void ResetZoom();
    void SetShowLabels(bool Show);
    QPixmap ExportAsPng();

signals:
    void NodeClicked(int Index);
    void NodeDoubleClicked(int Index);
    void ContextMenuRequested(int Index, const QPoint& GlobalPos);

protected:
    void paintEvent(QPaintEvent* Event) override;
    void mousePressEvent(QMouseEvent* Event) override;
    void mouseReleaseEvent(QMouseEvent* Event) override;
    void mouseMoveEvent(QMouseEvent* Event) override;
    void mouseDoubleClickEvent(QMouseEvent* Event) override;
    void wheelEvent(QWheelEvent* Event) override;

private:
    int NodeAtPoint(const QPointF& ScenePos) const;
    QPointF MapToScene(const QPoint& WidgetPos) const;

    QList<GraphNode> NodeList;
    QList<GraphEdge> EdgeList;
    double ZoomLevel;
    QPointF PanOffset;
    bool IsPanning;
    QPoint LastMousePos;
    bool ShowLabels;
    int SelectedNodeIndex;
};

class CallGraphWidget : public QWidget {
    Q_OBJECT
public:
    explicit CallGraphWidget(QWidget* Parent = nullptr);

    void SetDatabase(AnalysisDatabase* Db);
    void BuildGraph(Address CenterFunction, int Depth);
    void BuildFullGraph();

private:
    void OnSearchTextChanged(const QString& Text);
    void OnDepthChanged(int Depth);
    void OnFitToWindow();
    void OnResetZoom();
    void OnExportPng();
    void OnToggleLabels();
    void OnNodeClicked(int Index);
    void OnNodeDoubleClicked(int Index);
    void OnContextMenu(int Index, const QPoint& GlobalPos);
    void PerformLayout();
    int FindNodeByAddress(Address Addr) const;

    AnalysisDatabase* Database;
    CallGraphCanvas* Canvas;
    QLineEdit* SearchBox;
    QSpinBox* DepthSpinner;
    QAction* ToggleLabelsAction;

    QList<GraphNode> Nodes;
    QList<GraphEdge> Edges;
    Address RootAddress;
    int CurrentDepth;
};

}
