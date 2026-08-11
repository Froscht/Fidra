#include "CallGraphWidget.h"

#include <QPainter>
#include <QPainterPath>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QToolBar>
#include <QMenu>
#include <QFileDialog>
#include <QMouseEvent>
#include <QWheelEvent>
#include <QFontMetrics>
#include <QApplication>
#include <QStyle>
#include <QQueue>
#include <QLabel>
#include <QtMath>
#include <algorithm>
#include <limits>

namespace Fidra {

CallGraphCanvas::CallGraphCanvas(QWidget* Parent)
    : QWidget(Parent)
    , ZoomLevel(1.0)
    , IsPanning(false)
    , ShowLabels(true)
    , SelectedNodeIndex(-1) {
    setMouseTracking(true);
    setFocusPolicy(Qt::StrongFocus);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setMinimumSize(200, 200);
}

void CallGraphCanvas::SetGraph(const QList<GraphNode>& Nodes, const QList<GraphEdge>& Edges) {
    NodeList = Nodes;
    EdgeList = Edges;
    SelectedNodeIndex = -1;
    update();
}

void CallGraphCanvas::CenterOnNode(int Index) {
    if (Index < 0 || Index >= NodeList.size())
        return;

    const GraphNode& Node = NodeList[Index];
    QPointF NodeCenter = Node.Pos + QPointF(Node.Size.width() / 2.0, Node.Size.height() / 2.0);
    PanOffset = QPointF(width() / 2.0, height() / 2.0) - NodeCenter * ZoomLevel;

    if (SelectedNodeIndex >= 0 && SelectedNodeIndex < NodeList.size())
        NodeList[SelectedNodeIndex].Selected = false;

    SelectedNodeIndex = Index;
    NodeList[Index].Selected = true;
    update();
}

void CallGraphCanvas::FitToWindow() {
    if (NodeList.isEmpty())
        return;

    double MinX = std::numeric_limits<double>::max();
    double MinY = std::numeric_limits<double>::max();
    double MaxX = std::numeric_limits<double>::lowest();
    double MaxY = std::numeric_limits<double>::lowest();

    for (const auto& Node : NodeList) {
        MinX = qMin(MinX, Node.Pos.x());
        MinY = qMin(MinY, Node.Pos.y());
        MaxX = qMax(MaxX, Node.Pos.x() + Node.Size.width());
        MaxY = qMax(MaxY, Node.Pos.y() + Node.Size.height());
    }

    double GraphWidth = MaxX - MinX + 60.0;
    double GraphHeight = MaxY - MinY + 60.0;

    if (GraphWidth <= 0 || GraphHeight <= 0)
        return;

    double ScaleX = width() / GraphWidth;
    double ScaleY = height() / GraphHeight;
    ZoomLevel = qMin(ScaleX, ScaleY);
    ZoomLevel = qBound(0.05, ZoomLevel, 5.0);

    double CenterX = (MinX + MaxX) / 2.0;
    double CenterY = (MinY + MaxY) / 2.0;
    PanOffset = QPointF(width() / 2.0, height() / 2.0) - QPointF(CenterX, CenterY) * ZoomLevel;

    update();
}

void CallGraphCanvas::ResetZoom() {
    ZoomLevel = 1.0;
    PanOffset = QPointF(0, 0);
    update();
}

void CallGraphCanvas::SetShowLabels(bool Show) {
    ShowLabels = Show;
    update();
}

QPixmap CallGraphCanvas::ExportAsPng() {
    if (NodeList.isEmpty())
        return QPixmap();

    double MinX = std::numeric_limits<double>::max();
    double MinY = std::numeric_limits<double>::max();
    double MaxX = std::numeric_limits<double>::lowest();
    double MaxY = std::numeric_limits<double>::lowest();

    for (const auto& Node : NodeList) {
        MinX = qMin(MinX, Node.Pos.x());
        MinY = qMin(MinY, Node.Pos.y());
        MaxX = qMax(MaxX, Node.Pos.x() + Node.Size.width());
        MaxY = qMax(MaxY, Node.Pos.y() + Node.Size.height());
    }

    int PngWidth = qMax(static_cast<int>(MaxX - MinX + 80), 100);
    int PngHeight = qMax(static_cast<int>(MaxY - MinY + 80), 100);

    QPixmap Pixmap(PngWidth, PngHeight);
    Pixmap.fill(QColor(30, 30, 30));

    QPainter Painter(&Pixmap);
    Painter.setRenderHint(QPainter::Antialiasing);
    Painter.translate(-MinX + 40, -MinY + 40);

    QPen EdgePen(QColor(100, 100, 100), 1.5);
    Painter.setPen(EdgePen);

    for (const auto& Edge : EdgeList) {
        if (Edge.FromIdx < 0 || Edge.FromIdx >= NodeList.size() ||
            Edge.ToIdx < 0 || Edge.ToIdx >= NodeList.size())
            continue;

        const GraphNode& From = NodeList[Edge.FromIdx];
        const GraphNode& To = NodeList[Edge.ToIdx];

        QPointF Start(From.Pos.x() + From.Size.width() / 2.0,
                      From.Pos.y() + From.Size.height());
        QPointF End(To.Pos.x() + To.Size.width() / 2.0,
                    To.Pos.y());

        double Dist = qMax(qAbs(End.y() - Start.y()), 20.0);
        QPointF Ctrl1(Start.x(), Start.y() + Dist / 3.0);
        QPointF Ctrl2(End.x(), End.y() - Dist / 3.0);

        QPainterPath CurvePath;
        CurvePath.moveTo(Start);
        CurvePath.cubicTo(Ctrl1, Ctrl2, End);
        Painter.drawPath(CurvePath);

        double Angle = qAtan2(End.y() - Ctrl2.y(), End.x() - Ctrl2.x());
        double ArrowLen = 8.0;
        QPointF ArrowP1 = End - QPointF(qCos(Angle - M_PI / 6.0) * ArrowLen,
                                         qSin(Angle - M_PI / 6.0) * ArrowLen);
        QPointF ArrowP2 = End - QPointF(qCos(Angle + M_PI / 6.0) * ArrowLen,
                                         qSin(Angle + M_PI / 6.0) * ArrowLen);

        QPainterPath ArrowPath;
        ArrowPath.moveTo(End);
        ArrowPath.lineTo(ArrowP1);
        ArrowPath.lineTo(ArrowP2);
        ArrowPath.closeSubpath();
        Painter.fillPath(ArrowPath, QColor(100, 100, 100));
    }

    QFont NodeFont = font();
    NodeFont.setPointSize(9);
    Painter.setFont(NodeFont);

    for (int I = 0; I < NodeList.size(); ++I) {
        const GraphNode& Node = NodeList[I];

        QColor FillColor;
        if (Node.IsImported)
            FillColor = QColor(70, 130, 220);
        else if (Node.IsExported)
            FillColor = QColor(60, 180, 75);
        else if (Node.IsThunk)
            FillColor = QColor(150, 150, 150);
        else
            FillColor = QColor(60, 63, 65);

        QRectF Rect(Node.Pos, Node.Size);
        Painter.setPen(QPen(FillColor.darker(150), 1.5));
        Painter.setBrush(FillColor);
        Painter.drawRoundedRect(Rect, 4, 4);

        Painter.setPen(Qt::white);
        QFontMetrics Fm(NodeFont);
        QString DisplayName = Fm.elidedText(Node.Name, Qt::ElideRight,
                                             static_cast<int>(Node.Size.width() - 8));
        Painter.drawText(Rect, Qt::AlignCenter, DisplayName);
    }

    return Pixmap;
}

QPointF CallGraphCanvas::MapToScene(const QPoint& WidgetPos) const {
    return (QPointF(WidgetPos) - PanOffset) / ZoomLevel;
}

int CallGraphCanvas::NodeAtPoint(const QPointF& ScenePos) const {
    for (int I = NodeList.size() - 1; I >= 0; --I) {
        QRectF Rect(NodeList[I].Pos, NodeList[I].Size);
        if (Rect.contains(ScenePos))
            return I;
    }
    return -1;
}

void CallGraphCanvas::paintEvent(QPaintEvent*) {
    QPainter Painter(this);
    Painter.setRenderHint(QPainter::Antialiasing);
    Painter.fillRect(rect(), QColor(30, 30, 30));

    QTransform Transform;
    Transform.translate(PanOffset.x(), PanOffset.y());
    Transform.scale(ZoomLevel, ZoomLevel);
    Painter.setTransform(Transform);

    double PenWidth = qMax(0.5, 1.5 / ZoomLevel);
    QPen EdgePen(QColor(100, 100, 100, 180), PenWidth);
    Painter.setPen(EdgePen);

    for (const auto& Edge : EdgeList) {
        if (Edge.FromIdx < 0 || Edge.FromIdx >= NodeList.size() ||
            Edge.ToIdx < 0 || Edge.ToIdx >= NodeList.size())
            continue;

        const GraphNode& From = NodeList[Edge.FromIdx];
        const GraphNode& To = NodeList[Edge.ToIdx];

        QPointF Start(From.Pos.x() + From.Size.width() / 2.0,
                      From.Pos.y() + From.Size.height());
        QPointF End(To.Pos.x() + To.Size.width() / 2.0,
                    To.Pos.y());

        double Dist = qMax(qAbs(End.y() - Start.y()), 20.0);
        QPointF Ctrl1(Start.x(), Start.y() + Dist / 3.0);
        QPointF Ctrl2(End.x(), End.y() - Dist / 3.0);

        QPainterPath CurvePath;
        CurvePath.moveTo(Start);
        CurvePath.cubicTo(Ctrl1, Ctrl2, End);
        Painter.drawPath(CurvePath);

        double Angle = qAtan2(End.y() - Ctrl2.y(), End.x() - Ctrl2.x());
        double ArrowLen = qBound(4.0, 8.0 / ZoomLevel, 12.0);
        QPointF ArrowP1 = End - QPointF(qCos(Angle - M_PI / 6.0) * ArrowLen,
                                         qSin(Angle - M_PI / 6.0) * ArrowLen);
        QPointF ArrowP2 = End - QPointF(qCos(Angle + M_PI / 6.0) * ArrowLen,
                                         qSin(Angle + M_PI / 6.0) * ArrowLen);

        QPainterPath ArrowPath;
        ArrowPath.moveTo(End);
        ArrowPath.lineTo(ArrowP1);
        ArrowPath.lineTo(ArrowP2);
        ArrowPath.closeSubpath();
        Painter.fillPath(ArrowPath, QColor(100, 100, 100));
    }

    QFont NodeFont = font();
    NodeFont.setPointSize(9);
    Painter.setFont(NodeFont);
    QFontMetrics Fm(NodeFont);

    for (int I = 0; I < NodeList.size(); ++I) {
        const GraphNode& Node = NodeList[I];

        QColor FillColor;
        if (Node.IsImported)
            FillColor = QColor(70, 130, 220);
        else if (Node.IsExported)
            FillColor = QColor(60, 180, 75);
        else if (Node.IsThunk)
            FillColor = QColor(150, 150, 150);
        else
            FillColor = QColor(60, 63, 65);

        if (I == SelectedNodeIndex)
            FillColor = QColor(220, 160, 40);

        QRectF Rect(Node.Pos, Node.Size);
        Painter.setPen(QPen(FillColor.darker(150), PenWidth));
        Painter.setBrush(FillColor);
        Painter.drawRoundedRect(Rect, 4, 4);

        if (ShowLabels) {
            Painter.setPen(Qt::white);
            QString DisplayName = Fm.elidedText(Node.Name, Qt::ElideRight,
                                                 static_cast<int>(Node.Size.width() - 8));
            Painter.drawText(Rect, Qt::AlignCenter, DisplayName);
        }
    }
}

void CallGraphCanvas::mousePressEvent(QMouseEvent* Event) {
    if (Event->button() == Qt::MiddleButton) {
        IsPanning = true;
        LastMousePos = Event->pos();
        setCursor(Qt::ClosedHandCursor);
        Event->accept();
        return;
    }

    if (Event->button() == Qt::LeftButton) {
        QPointF ScenePos = MapToScene(Event->pos());
        int HitIndex = NodeAtPoint(ScenePos);

        if (SelectedNodeIndex >= 0 && SelectedNodeIndex < NodeList.size())
            NodeList[SelectedNodeIndex].Selected = false;

        SelectedNodeIndex = HitIndex;
        if (SelectedNodeIndex >= 0)
            NodeList[SelectedNodeIndex].Selected = true;

        emit NodeClicked(HitIndex);
        update();
        Event->accept();
        return;
    }

    if (Event->button() == Qt::RightButton) {
        QPointF ScenePos = MapToScene(Event->pos());
        int HitIndex = NodeAtPoint(ScenePos);
        if (HitIndex >= 0)
            emit ContextMenuRequested(HitIndex, Event->globalPosition().toPoint());
        Event->accept();
        return;
    }
}

void CallGraphCanvas::mouseReleaseEvent(QMouseEvent* Event) {
    if (Event->button() == Qt::MiddleButton && IsPanning) {
        IsPanning = false;
        setCursor(Qt::ArrowCursor);
        Event->accept();
    }
}

void CallGraphCanvas::mouseMoveEvent(QMouseEvent* Event) {
    if (IsPanning) {
        QPoint Delta = Event->pos() - LastMousePos;
        PanOffset += QPointF(Delta);
        LastMousePos = Event->pos();
        update();
        Event->accept();
    }
}

void CallGraphCanvas::mouseDoubleClickEvent(QMouseEvent* Event) {
    if (Event->button() == Qt::LeftButton) {
        QPointF ScenePos = MapToScene(Event->pos());
        int HitIndex = NodeAtPoint(ScenePos);
        if (HitIndex >= 0) {
            CenterOnNode(HitIndex);
            emit NodeDoubleClicked(HitIndex);
        }
        Event->accept();
    }
}

void CallGraphCanvas::wheelEvent(QWheelEvent* Event) {
    double Factor = Event->angleDelta().y() > 0 ? 1.15 : 1.0 / 1.15;
    double NewZoom = ZoomLevel * Factor;
    NewZoom = qBound(0.05, NewZoom, 10.0);

    QPointF MouseScene = MapToScene(Event->position().toPoint());
    ZoomLevel = NewZoom;
    PanOffset = Event->position() - MouseScene * ZoomLevel;

    update();
    Event->accept();
}

CallGraphWidget::CallGraphWidget(QWidget* Parent)
    : QWidget(Parent)
    , Database(nullptr)
    , RootAddress(0)
    , CurrentDepth(3) {

    QVBoxLayout* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(0, 0, 0, 0);
    MainLayout->setSpacing(0);

    QToolBar* ToolBar = new QToolBar(this);
    ToolBar->setIconSize(QSize(16, 16));

    SearchBox = new QLineEdit(this);
    SearchBox->setPlaceholderText(QStringLiteral("Search function..."));
    SearchBox->setMaximumWidth(200);
    ToolBar->addWidget(SearchBox);

    ToolBar->addSeparator();

    QLabel* DepthLabel = new QLabel(QStringLiteral(" Depth: "), this);
    ToolBar->addWidget(DepthLabel);

    DepthSpinner = new QSpinBox(this);
    DepthSpinner->setRange(1, 10);
    DepthSpinner->setValue(3);
    DepthSpinner->setMaximumWidth(60);
    ToolBar->addWidget(DepthSpinner);

    ToolBar->addSeparator();

    QAction* FitAction = ToolBar->addAction(
        QApplication::style()->standardIcon(QStyle::SP_TitleBarMaxButton),
        QStringLiteral("Fit to Window"));

    QAction* ResetAction = ToolBar->addAction(
        QApplication::style()->standardIcon(QStyle::SP_BrowserReload),
        QStringLiteral("Reset Zoom"));

    QAction* ExportAction = ToolBar->addAction(
        QApplication::style()->standardIcon(QStyle::SP_DialogSaveButton),
        QStringLiteral("Export as PNG"));

    ToggleLabelsAction = ToolBar->addAction(QStringLiteral("Labels"));
    ToggleLabelsAction->setCheckable(true);
    ToggleLabelsAction->setChecked(true);

    MainLayout->addWidget(ToolBar);

    Canvas = new CallGraphCanvas(this);
    MainLayout->addWidget(Canvas);

    connect(SearchBox, &QLineEdit::textChanged, this, &CallGraphWidget::OnSearchTextChanged);
    connect(DepthSpinner, QOverload<int>::of(&QSpinBox::valueChanged), this, &CallGraphWidget::OnDepthChanged);
    connect(FitAction, &QAction::triggered, this, &CallGraphWidget::OnFitToWindow);
    connect(ResetAction, &QAction::triggered, this, &CallGraphWidget::OnResetZoom);
    connect(ExportAction, &QAction::triggered, this, &CallGraphWidget::OnExportPng);
    connect(ToggleLabelsAction, &QAction::toggled, this, &CallGraphWidget::OnToggleLabels);
    connect(Canvas, &CallGraphCanvas::NodeClicked, this, &CallGraphWidget::OnNodeClicked);
    connect(Canvas, &CallGraphCanvas::NodeDoubleClicked, this, &CallGraphWidget::OnNodeDoubleClicked);
    connect(Canvas, &CallGraphCanvas::ContextMenuRequested, this, &CallGraphWidget::OnContextMenu);
}

void CallGraphWidget::SetDatabase(AnalysisDatabase* Db) {
    Database = Db;
}

void CallGraphWidget::BuildGraph(Address CenterFunction, int Depth) {
    if (!Database)
        return;

    Nodes.clear();
    Edges.clear();
    RootAddress = CenterFunction;
    CurrentDepth = Depth;
    DepthSpinner->setValue(Depth);

    QMap<Address, int> AddressToIndex;
    QList<AnalyzedFunction> AllFunctions = Database->GetAllFunctions();
    QMap<Address, AnalyzedFunction> FuncMap;

    for (const auto& Func : AllFunctions)
        FuncMap[Func.Start] = Func;

    if (!FuncMap.contains(CenterFunction)) {
        Canvas->SetGraph(Nodes, Edges);
        return;
    }

    QQueue<QPair<Address, int>> Queue;
    QSet<Address> Visited;

    Queue.enqueue({CenterFunction, 0});
    Visited.insert(CenterFunction);

    while (!Queue.isEmpty()) {
        auto Current = Queue.dequeue();
        Address Addr = Current.first;
        int CurrentLevel = Current.second;

        if (!FuncMap.contains(Addr))
            continue;

        const AnalyzedFunction& Func = FuncMap[Addr];

        GraphNode Node;
        Node.Addr = Addr;
        Node.Name = Func.Name;
        Node.Selected = false;
        Node.Layer = CurrentLevel;
        Node.IsImported = Func.IsImported;
        Node.IsExported = Func.IsExported;
        Node.IsThunk = Func.IsThunk;

        QFontMetrics Fm(font());
        int TextWidth = Fm.horizontalAdvance(Func.Name);
        Node.Size = QSizeF(qMax(TextWidth + 24.0, 80.0), 30.0);
        Node.Pos = QPointF(0, 0);

        AddressToIndex[Addr] = Nodes.size();
        Nodes.append(Node);

        if (CurrentLevel < Depth) {
            for (Address CalleeAddr : Func.Callees) {
                if (!Visited.contains(CalleeAddr) && FuncMap.contains(CalleeAddr)) {
                    Visited.insert(CalleeAddr);
                    Queue.enqueue({CalleeAddr, CurrentLevel + 1});
                }
            }

            for (Address CallerAddr : Func.Callers) {
                if (!Visited.contains(CallerAddr) && FuncMap.contains(CallerAddr)) {
                    Visited.insert(CallerAddr);
                    Queue.enqueue({CallerAddr, CurrentLevel + 1});
                }
            }
        }
    }

    for (int I = 0; I < Nodes.size(); ++I) {
        Address Addr = Nodes[I].Addr;
        if (!FuncMap.contains(Addr))
            continue;

        const AnalyzedFunction& Func = FuncMap[Addr];
        for (Address CalleeAddr : Func.Callees) {
            if (AddressToIndex.contains(CalleeAddr)) {
                GraphEdge Edge;
                Edge.FromIdx = I;
                Edge.ToIdx = AddressToIndex[CalleeAddr];
                Edges.append(Edge);
            }
        }
    }

    PerformLayout();
    Canvas->SetGraph(Nodes, Edges);
    Canvas->FitToWindow();
}

void CallGraphWidget::BuildFullGraph() {
    if (!Database)
        return;

    Nodes.clear();
    Edges.clear();

    QList<AnalyzedFunction> AllFunctions = Database->GetAllFunctions();
    QMap<Address, int> AddressToIndex;

    for (const auto& Func : AllFunctions) {
        GraphNode Node;
        Node.Addr = Func.Start;
        Node.Name = Func.Name;
        Node.Selected = false;
        Node.Layer = 0;
        Node.IsImported = Func.IsImported;
        Node.IsExported = Func.IsExported;
        Node.IsThunk = Func.IsThunk;

        QFontMetrics Fm(font());
        int TextWidth = Fm.horizontalAdvance(Func.Name);
        Node.Size = QSizeF(qMax(TextWidth + 24.0, 80.0), 30.0);
        Node.Pos = QPointF(0, 0);

        AddressToIndex[Func.Start] = Nodes.size();
        Nodes.append(Node);
    }

    for (const auto& Func : AllFunctions) {
        int FromIdx = AddressToIndex.value(Func.Start, -1);
        if (FromIdx < 0)
            continue;
        for (Address CalleeAddr : Func.Callees) {
            int ToIdx = AddressToIndex.value(CalleeAddr, -1);
            if (ToIdx >= 0) {
                GraphEdge Edge;
                Edge.FromIdx = FromIdx;
                Edge.ToIdx = ToIdx;
                Edges.append(Edge);
            }
        }
    }

    QSet<int> HasIncoming;
    for (const auto& Edge : Edges)
        HasIncoming.insert(Edge.ToIdx);

    QQueue<int> BfsQueue;
    QSet<int> BfsVisited;
    for (int I = 0; I < Nodes.size(); ++I) {
        if (!HasIncoming.contains(I)) {
            BfsQueue.enqueue(I);
            Nodes[I].Layer = 0;
        }
    }

    if (BfsQueue.isEmpty() && !Nodes.isEmpty()) {
        BfsQueue.enqueue(0);
        Nodes[0].Layer = 0;
    }

    while (!BfsQueue.isEmpty()) {
        int Idx = BfsQueue.dequeue();
        if (BfsVisited.contains(Idx))
            continue;
        BfsVisited.insert(Idx);

        for (const auto& Edge : Edges) {
            if (Edge.FromIdx == Idx && !BfsVisited.contains(Edge.ToIdx)) {
                Nodes[Edge.ToIdx].Layer = qMax(Nodes[Edge.ToIdx].Layer, Nodes[Idx].Layer + 1);
                BfsQueue.enqueue(Edge.ToIdx);
            }
        }
    }

    for (int I = 0; I < Nodes.size(); ++I) {
        if (!BfsVisited.contains(I))
            Nodes[I].Layer = 0;
    }

    RootAddress = Nodes.isEmpty() ? 0 : Nodes[0].Addr;

    PerformLayout();
    Canvas->SetGraph(Nodes, Edges);
    Canvas->FitToWindow();
}

void CallGraphWidget::PerformLayout() {
    if (Nodes.isEmpty())
        return;

    int MaxLayer = 0;
    for (const auto& Node : Nodes)
        MaxLayer = qMax(MaxLayer, Node.Layer);

    QMap<int, QList<int>> LayerNodes;
    for (int I = 0; I < Nodes.size(); ++I)
        LayerNodes[Nodes[I].Layer].append(I);

    QMap<int, QList<int>> Successors;
    QMap<int, QList<int>> Predecessors;
    for (const auto& Edge : Edges) {
        Successors[Edge.FromIdx].append(Edge.ToIdx);
        Predecessors[Edge.ToIdx].append(Edge.FromIdx);
    }

    for (int Iter = 0; Iter < 8; ++Iter) {
        for (int L = 1; L <= MaxLayer; ++L) {
            QList<int>& NodesInLayer = LayerNodes[L];
            if (NodesInLayer.size() <= 1)
                continue;

            QMap<int, double> MedianValues;
            for (int NodeIdx : NodesInLayer) {
                QList<double> Positions;
                for (int PredIdx : Predecessors.value(NodeIdx)) {
                    const QList<int>& PredLayer = LayerNodes[Nodes[PredIdx].Layer];
                    int PosInLayer = PredLayer.indexOf(PredIdx);
                    if (PosInLayer >= 0)
                        Positions.append(static_cast<double>(PosInLayer));
                }
                if (Positions.isEmpty()) {
                    MedianValues[NodeIdx] = static_cast<double>(NodesInLayer.indexOf(NodeIdx));
                } else {
                    std::sort(Positions.begin(), Positions.end());
                    MedianValues[NodeIdx] = Positions[Positions.size() / 2];
                }
            }

            std::sort(NodesInLayer.begin(), NodesInLayer.end(),
                      [&MedianValues](int A, int B) { return MedianValues[A] < MedianValues[B]; });
        }

        for (int L = MaxLayer - 1; L >= 0; --L) {
            QList<int>& NodesInLayer = LayerNodes[L];
            if (NodesInLayer.size() <= 1)
                continue;

            QMap<int, double> MedianValues;
            for (int NodeIdx : NodesInLayer) {
                QList<double> Positions;
                for (int SuccIdx : Successors.value(NodeIdx)) {
                    const QList<int>& SuccLayer = LayerNodes[Nodes[SuccIdx].Layer];
                    int PosInLayer = SuccLayer.indexOf(SuccIdx);
                    if (PosInLayer >= 0)
                        Positions.append(static_cast<double>(PosInLayer));
                }
                if (Positions.isEmpty()) {
                    MedianValues[NodeIdx] = static_cast<double>(NodesInLayer.indexOf(NodeIdx));
                } else {
                    std::sort(Positions.begin(), Positions.end());
                    MedianValues[NodeIdx] = Positions[Positions.size() / 2];
                }
            }

            std::sort(NodesInLayer.begin(), NodesInLayer.end(),
                      [&MedianValues](int A, int B) { return MedianValues[A] < MedianValues[B]; });
        }
    }

    double VerticalSpacing = 80.0;
    double HorizontalSpacing = 40.0;

    for (int L = 0; L <= MaxLayer; ++L) {
        const QList<int>& NodesInLayer = LayerNodes[L];
        double TotalWidth = 0;
        for (int NodeIdx : NodesInLayer)
            TotalWidth += Nodes[NodeIdx].Size.width();
        TotalWidth += HorizontalSpacing * qMax(0, static_cast<int>(NodesInLayer.size()) - 1);

        double X = -TotalWidth / 2.0;
        double Y = L * (30.0 + VerticalSpacing);

        for (int NodeIdx : NodesInLayer) {
            Nodes[NodeIdx].Pos = QPointF(X, Y);
            X += Nodes[NodeIdx].Size.width() + HorizontalSpacing;
        }
    }
}

int CallGraphWidget::FindNodeByAddress(Address Addr) const {
    for (int I = 0; I < Nodes.size(); ++I) {
        if (Nodes[I].Addr == Addr)
            return I;
    }
    return -1;
}

void CallGraphWidget::OnSearchTextChanged(const QString& Text) {
    if (Text.isEmpty())
        return;

    QString Lower = Text.toLower();
    for (int I = 0; I < Nodes.size(); ++I) {
        if (Nodes[I].Name.toLower().contains(Lower)) {
            Canvas->CenterOnNode(I);
            return;
        }
    }
}

void CallGraphWidget::OnDepthChanged(int Depth) {
    CurrentDepth = Depth;
    if (RootAddress != 0)
        BuildGraph(RootAddress, Depth);
}

void CallGraphWidget::OnFitToWindow() {
    Canvas->FitToWindow();
}

void CallGraphWidget::OnResetZoom() {
    Canvas->ResetZoom();
}

void CallGraphWidget::OnExportPng() {
    QString Path = QFileDialog::getSaveFileName(this, QStringLiteral("Export Call Graph"),
                                                 QString(), QStringLiteral("PNG (*.png)"));
    if (!Path.isEmpty()) {
        QPixmap Png = Canvas->ExportAsPng();
        if (!Png.isNull())
            Png.save(Path);
    }
}

void CallGraphWidget::OnToggleLabels() {
    Canvas->SetShowLabels(ToggleLabelsAction->isChecked());
}

void CallGraphWidget::OnNodeClicked(int Index) {
    Q_UNUSED(Index);
}

void CallGraphWidget::OnNodeDoubleClicked(int Index) {
    if (Index >= 0 && Index < Nodes.size()) {
        RootAddress = Nodes[Index].Addr;
        BuildGraph(RootAddress, CurrentDepth);
    }
}

void CallGraphWidget::OnContextMenu(int Index, const QPoint& GlobalPos) {
    if (Index < 0 || Index >= Nodes.size())
        return;

    QMenu Menu(this);

    QAction* GoToAction = Menu.addAction(QStringLiteral("Go to function"));
    QAction* CallersAction = Menu.addAction(QStringLiteral("Show callers only"));
    QAction* CalleesAction = Menu.addAction(QStringLiteral("Show callees only"));
    QAction* ExpandAction = Menu.addAction(QStringLiteral("Expand neighborhood"));

    QAction* Selected = Menu.exec(GlobalPos);

    if (!Selected)
        return;

    Address TargetAddr = Nodes[Index].Addr;

    if (Selected == GoToAction) {
        Canvas->CenterOnNode(Index);
    } else if (Selected == CallersAction) {
        RootAddress = TargetAddr;
        BuildGraph(TargetAddr, 1);
    } else if (Selected == CalleesAction) {
        RootAddress = TargetAddr;
        BuildGraph(TargetAddr, 1);
    } else if (Selected == ExpandAction) {
        RootAddress = TargetAddr;
        BuildGraph(TargetAddr, CurrentDepth + 1);
    }
}

}
