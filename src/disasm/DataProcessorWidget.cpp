#include "DataProcessorWidget.h"
#include "../analysis/AnalysisDatabase.h"
#include <QPainter>
#include <QPainterPath>
#include <QMenu>
#include <QAction>
#include <QFileDialog>
#include <QLineEdit>
#include <QLabel>
#include <QHeaderView>
#include <QWheelEvent>
#include <QGraphicsSceneMouseEvent>
#include <QGraphicsSceneContextMenuEvent>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QApplication>
#include <QMessageBox>
#include <QKeyEvent>
#include <QStyleOptionGraphicsItem>
#include <QScrollBar>
#include <cmath>

namespace Fidra {

NodeGraphicsItem::NodeGraphicsItem(ProcessorNode* Node, QGraphicsItem* Parent)
    : QGraphicsItem(Parent)
    , NodePtr(Node)
    , NodeWidth(150.0)
    , NodeHeight(0.0)
    , TitleHeight(24.0)
    , PortRadius(6.0)
    , PortSpacing(20.0)
{
    setFlag(ItemIsMovable, true);
    setFlag(ItemIsSelectable, true);
    setFlag(ItemSendsGeometryChanges, true);
    setPos(NodePtr->Position);
    UpdateLayout();
}

QRectF NodeGraphicsItem::boundingRect() const {
    return QRectF(0, 0, NodeWidth, NodeHeight);
}

void NodeGraphicsItem::UpdateLayout() {
    int MaxPorts = qMax(NodePtr->InputPorts.size(), NodePtr->OutputPorts.size());
    if (MaxPorts < 1) MaxPorts = 1;
    NodeHeight = TitleHeight + MaxPorts * PortSpacing + 10.0;
    prepareGeometryChange();
}

void NodeGraphicsItem::paint(QPainter* Painter, const QStyleOptionGraphicsItem* Option, QWidget*) {
    Q_UNUSED(Option);
    Painter->setRenderHint(QPainter::Antialiasing, true);

    QPainterPath BodyPath;
    BodyPath.addRoundedRect(QRectF(0, 0, NodeWidth, NodeHeight), 6, 6);
    Painter->fillPath(BodyPath, QBrush(QColor(50, 50, 55)));

    QPainterPath TitlePath;
    TitlePath.addRoundedRect(QRectF(0, 0, NodeWidth, TitleHeight + 4), 6, 6);
    QPainterPath TitleClip;
    TitleClip.addRect(QRectF(0, 0, NodeWidth, TitleHeight));
    TitlePath = TitlePath.intersected(TitleClip);
    QString Category = DataProcessorEngine::NodeCategory(NodePtr->Type);
    QColor TitleColor = CategoryColor(Category);
    Painter->fillPath(TitlePath, QBrush(TitleColor));

    Painter->setPen(QPen(Qt::white));
    QFont TitleFont("Segoe UI", 9, QFont::Bold);
    TitleFont.setStyleHint(QFont::SansSerif);
    Painter->setFont(TitleFont);
    Painter->drawText(QRectF(4, 0, NodeWidth - 8, TitleHeight), Qt::AlignVCenter | Qt::AlignHCenter, NodePtr->Label);

    QFont PortFont("Segoe UI", 7);
    PortFont.setStyleHint(QFont::SansSerif);
    Painter->setFont(PortFont);

    for (int I = 0; I < NodePtr->InputPorts.size(); ++I) {
        qreal Py = TitleHeight + I * PortSpacing + PortSpacing / 2.0;
        QPointF Center(0, Py);
        Painter->setBrush(QBrush(QColor(200, 200, 200)));
        Painter->setPen(QPen(QColor(100, 100, 100), 1));
        Painter->drawEllipse(Center, PortRadius, PortRadius);
        Painter->setPen(QPen(QColor(200, 200, 200)));
        Painter->drawText(QRectF(PortRadius + 4, Py - 8, NodeWidth / 2 - PortRadius - 8, 16), Qt::AlignVCenter | Qt::AlignLeft, NodePtr->InputPorts[I].Name);
    }

    for (int I = 0; I < NodePtr->OutputPorts.size(); ++I) {
        qreal Py = TitleHeight + I * PortSpacing + PortSpacing / 2.0;
        QPointF Center(NodeWidth, Py);
        Painter->setBrush(QBrush(QColor(200, 200, 200)));
        Painter->setPen(QPen(QColor(100, 100, 100), 1));
        Painter->drawEllipse(Center, PortRadius, PortRadius);
        Painter->setPen(QPen(QColor(200, 200, 200)));
        Painter->drawText(QRectF(NodeWidth / 2 + 4, Py - 8, NodeWidth / 2 - PortRadius - 8, 16), Qt::AlignVCenter | Qt::AlignRight, NodePtr->OutputPorts[I].Name);
    }

    if (isSelected()) {
        Painter->setPen(QPen(QColor(66, 133, 244), 2));
        Painter->setBrush(Qt::NoBrush);
        Painter->drawRoundedRect(QRectF(0, 0, NodeWidth, NodeHeight), 6, 6);
    } else {
        Painter->setPen(QPen(QColor(80, 80, 85), 1));
        Painter->setBrush(Qt::NoBrush);
        Painter->drawRoundedRect(QRectF(0, 0, NodeWidth, NodeHeight), 6, 6);
    }
}

ProcessorNode* NodeGraphicsItem::GetNode() const {
    return NodePtr;
}

int NodeGraphicsItem::GetNodeId() const {
    return NodePtr->Id;
}

QPointF NodeGraphicsItem::GetPortScenePos(bool IsInput, int PortIndex) const {
    qreal Px = IsInput ? 0.0 : NodeWidth;
    qreal Py = TitleHeight + PortIndex * PortSpacing + PortSpacing / 2.0;
    return mapToScene(QPointF(Px, Py));
}

int NodeGraphicsItem::PortAt(const QPointF& LocalPos, bool& IsInput) const {
    qreal HitRadius = PortRadius + 4.0;

    for (int I = 0; I < NodePtr->InputPorts.size(); ++I) {
        qreal Py = TitleHeight + I * PortSpacing + PortSpacing / 2.0;
        QPointF Center(0, Py);
        qreal Dist = QLineF(LocalPos, Center).length();
        if (Dist <= HitRadius) {
            IsInput = true;
            return I;
        }
    }

    for (int I = 0; I < NodePtr->OutputPorts.size(); ++I) {
        qreal Py = TitleHeight + I * PortSpacing + PortSpacing / 2.0;
        QPointF Center(NodeWidth, Py);
        qreal Dist = QLineF(LocalPos, Center).length();
        if (Dist <= HitRadius) {
            IsInput = false;
            return I;
        }
    }

    return -1;
}

QColor NodeGraphicsItem::CategoryColor(const QString& Category) {
    if (Category == "Input") return QColor(76, 175, 80);
    if (Category == "Transform") return QColor(66, 133, 244);
    if (Category == "Crypto") return QColor(234, 67, 53);
    if (Category == "Compress") return QColor(156, 39, 176);
    if (Category == "Hash") return QColor(255, 152, 0);
    if (Category == "String") return QColor(0, 188, 212);
    if (Category == "Math") return QColor(255, 235, 59);
    if (Category == "Output") return QColor(255, 87, 34);
    return QColor(158, 158, 158);
}

QVariant NodeGraphicsItem::itemChange(GraphicsItemChange Change, const QVariant& Value) {
    if (Change == ItemPositionHasChanged) {
        NodePtr->Position = Value.toPointF();
        auto* GraphScene = dynamic_cast<NodeGraphScene*>(scene());
        if (GraphScene) {
            GraphScene->UpdateConnections();
            emit GraphScene->NodeMoved(NodePtr->Id, Value.toPointF());
        }
    }
    return QGraphicsItem::itemChange(Change, Value);
}

void NodeGraphicsItem::mousePressEvent(QGraphicsSceneMouseEvent* Event) {
    if (Event->button() == Qt::LeftButton) {
        bool IsInput = false;
        int PortIdx = PortAt(Event->pos(), IsInput);
        if (PortIdx >= 0 && !IsInput) {
            auto* GraphScene = dynamic_cast<NodeGraphScene*>(scene());
            if (GraphScene) {
                Event->accept();
                return;
            }
        }
    }
    QGraphicsItem::mousePressEvent(Event);
}

void NodeGraphicsItem::mouseReleaseEvent(QGraphicsSceneMouseEvent* Event) {
    QGraphicsItem::mouseReleaseEvent(Event);
}

void NodeGraphicsItem::contextMenuEvent(QGraphicsSceneContextMenuEvent* Event) {
    QMenu ContextMenu;
    QAction* DeleteAction = ContextMenu.addAction("Delete");
    QAction* DuplicateAction = ContextMenu.addAction("Duplicate");

    QAction* Selected = ContextMenu.exec(Event->screenPos());

    if (Selected == DeleteAction) {
        auto* GraphScene = dynamic_cast<NodeGraphScene*>(scene());
        if (GraphScene) {
            emit GraphScene->NodeDeleted(NodePtr->Id);
        }
    } else if (Selected == DuplicateAction) {
        auto* GraphScene = dynamic_cast<NodeGraphScene*>(scene());
        if (GraphScene) {
            DataProcessorEngine* Eng = nullptr;
            for (auto It = GraphScene->findChildren<QObject*>().begin(); It != GraphScene->findChildren<QObject*>().end(); ++It) {
                Eng = dynamic_cast<DataProcessorEngine*>(*It);
                if (Eng) break;
            }
            if (!Eng) {
                QObject* Par = GraphScene->parent();
                while (Par) {
                    auto* Widget = dynamic_cast<DataProcessorWidget*>(Par);
                    if (Widget) break;
                    Par = Par->parent();
                }
            }
            QPointF NewPos = NodePtr->Position + QPointF(30, 30);
            int NewId = -1;
            auto AllNodes = GraphScene->items();
            Q_UNUSED(AllNodes);
            emit GraphScene->NodeSelected(-1);
            emit GraphScene->ConnectionRequested(-1, static_cast<int>(NodePtr->Type), static_cast<int>(NewPos.x()), static_cast<int>(NewPos.y()));
        }
    }
}

ConnectionGraphicsItem::ConnectionGraphicsItem(QGraphicsItem* Parent)
    : QGraphicsPathItem(Parent)
    , LineColor(Qt::white)
{
    Conn.SourceNodeId = -1;
    Conn.SourcePortIndex = -1;
    Conn.DestNodeId = -1;
    Conn.DestPortIndex = -1;
    setPen(QPen(LineColor, 2));
    setFlag(ItemIsSelectable, true);
}

void ConnectionGraphicsItem::SetConnection(const NodeConnection& NewConn) {
    Conn = NewConn;
}

NodeConnection ConnectionGraphicsItem::GetConnection() const {
    return Conn;
}

void ConnectionGraphicsItem::UpdatePath(QPointF Start, QPointF End) {
    QPainterPath Path;
    Path.moveTo(Start);
    qreal Dx = std::abs(End.x() - Start.x()) / 2.0;
    if (Dx < 50.0) Dx = 50.0;
    QPointF Ctrl1(Start.x() + Dx, Start.y());
    QPointF Ctrl2(End.x() - Dx, End.y());
    Path.cubicTo(Ctrl1, Ctrl2, End);
    setPath(Path);
}

void ConnectionGraphicsItem::SetColor(const QColor& Color) {
    LineColor = Color;
    setPen(QPen(LineColor, 2));
}

void ConnectionGraphicsItem::paint(QPainter* Painter, const QStyleOptionGraphicsItem* Option, QWidget*) {
    Q_UNUSED(Option);
    Painter->setRenderHint(QPainter::Antialiasing, true);
    QPen DrawPen(LineColor, 2);
    if (isSelected()) {
        DrawPen.setColor(QColor(66, 133, 244));
        DrawPen.setWidth(3);
    }
    Painter->setPen(DrawPen);
    Painter->setBrush(Qt::NoBrush);
    Painter->drawPath(path());
}

NodeGraphScene::NodeGraphScene(QObject* Parent)
    : QGraphicsScene(Parent)
    , EnginePtr(nullptr)
    , DraggingConnection(false)
    , DragSourceNode(-1)
    , DragSourcePort(-1)
    , DragLine(nullptr)
{
}

void NodeGraphScene::SetEngine(DataProcessorEngine* Engine) {
    EnginePtr = Engine;
}

void NodeGraphScene::RebuildScene() {
    clear();
    NodeItems.clear();
    ConnectionItems.clear();
    DragLine = nullptr;
    DraggingConnection = false;

    if (!EnginePtr) return;

    QVector<ProcessorNode> AllNodes = EnginePtr->GetNodes();
    for (int I = 0; I < AllNodes.size(); ++I) {
        ProcessorNode* NodeRef = EnginePtr->FindNode(AllNodes[I].Id);
        if (!NodeRef) continue;
        auto* Item = new NodeGraphicsItem(NodeRef);
        addItem(Item);
        NodeItems[NodeRef->Id] = Item;
    }

    QVector<NodeConnection> AllConns = EnginePtr->GetConnections();
    for (const auto& Conn : AllConns) {
        auto* ConnItem = new ConnectionGraphicsItem();
        ConnItem->SetConnection(Conn);
        addItem(ConnItem);
        ConnectionItems.append(ConnItem);
    }

    UpdateConnections();
}

void NodeGraphScene::UpdateConnections() {
    for (auto* ConnItem : ConnectionItems) {
        NodeConnection Conn = ConnItem->GetConnection();
        auto* SrcItem = FindNodeItem(Conn.SourceNodeId);
        auto* DstItem = FindNodeItem(Conn.DestNodeId);
        if (SrcItem && DstItem) {
            QPointF Start = SrcItem->GetPortScenePos(false, Conn.SourcePortIndex);
            QPointF End = DstItem->GetPortScenePos(true, Conn.DestPortIndex);
            ConnItem->UpdatePath(Start, End);

            QString Category = DataProcessorEngine::NodeCategory(SrcItem->GetNode()->Type);
            ConnItem->SetColor(NodeGraphicsItem::CategoryColor(Category).lighter(130));
        }
    }
}

NodeGraphicsItem* NodeGraphScene::FindNodeItem(int NodeId) const {
    auto It = NodeItems.find(NodeId);
    if (It != NodeItems.end()) return It.value();
    return nullptr;
}

void NodeGraphScene::mousePressEvent(QGraphicsSceneMouseEvent* Event) {
    if (Event->button() == Qt::LeftButton) {
        QList<QGraphicsItem*> ItemsAtPos = items(Event->scenePos());
        for (auto* Item : ItemsAtPos) {
            auto* NodeItem = dynamic_cast<NodeGraphicsItem*>(Item);
            if (NodeItem) {
                QPointF LocalPos = NodeItem->mapFromScene(Event->scenePos());
                bool IsInput = false;
                int PortIdx = NodeItem->PortAt(LocalPos, IsInput);
                if (PortIdx >= 0 && !IsInput) {
                    DraggingConnection = true;
                    DragSourceNode = NodeItem->GetNodeId();
                    DragSourcePort = PortIdx;

                    DragLine = new QGraphicsPathItem();
                    QPen DashPen(QColor(200, 200, 200), 2, Qt::DashLine);
                    DragLine->setPen(DashPen);
                    addItem(DragLine);

                    QPointF Start = NodeItem->GetPortScenePos(false, PortIdx);
                    QPainterPath Path;
                    Path.moveTo(Start);
                    Path.lineTo(Event->scenePos());
                    DragLine->setPath(Path);

                    Event->accept();
                    return;
                }
                emit NodeSelected(NodeItem->GetNodeId());
                break;
            }
        }
    }
    QGraphicsScene::mousePressEvent(Event);
}

void NodeGraphScene::mouseMoveEvent(QGraphicsSceneMouseEvent* Event) {
    if (DraggingConnection && DragLine) {
        auto* SrcItem = FindNodeItem(DragSourceNode);
        if (SrcItem) {
            QPointF Start = SrcItem->GetPortScenePos(false, DragSourcePort);
            QPainterPath Path;
            Path.moveTo(Start);
            qreal Dx = std::abs(Event->scenePos().x() - Start.x()) / 2.0;
            if (Dx < 50.0) Dx = 50.0;
            QPointF Ctrl1(Start.x() + Dx, Start.y());
            QPointF Ctrl2(Event->scenePos().x() - Dx, Event->scenePos().y());
            Path.cubicTo(Ctrl1, Ctrl2, Event->scenePos());
            DragLine->setPath(Path);
        }
        Event->accept();
        return;
    }
    QGraphicsScene::mouseMoveEvent(Event);
    UpdateConnections();
}

void NodeGraphScene::mouseReleaseEvent(QGraphicsSceneMouseEvent* Event) {
    if (DraggingConnection) {
        DraggingConnection = false;

        if (DragLine) {
            removeItem(DragLine);
            delete DragLine;
            DragLine = nullptr;
        }

        QList<QGraphicsItem*> ItemsAtPos = items(Event->scenePos());
        for (auto* Item : ItemsAtPos) {
            auto* NodeItem = dynamic_cast<NodeGraphicsItem*>(Item);
            if (NodeItem && NodeItem->GetNodeId() != DragSourceNode) {
                QPointF LocalPos = NodeItem->mapFromScene(Event->scenePos());
                bool IsInput = false;
                int PortIdx = NodeItem->PortAt(LocalPos, IsInput);
                if (PortIdx >= 0 && IsInput) {
                    emit ConnectionRequested(DragSourceNode, DragSourcePort, NodeItem->GetNodeId(), PortIdx);
                    Event->accept();
                    return;
                }
            }
        }

        Event->accept();
        return;
    }
    QGraphicsScene::mouseReleaseEvent(Event);
}

void NodeGraphScene::contextMenuEvent(QGraphicsSceneContextMenuEvent* Event) {
    QList<QGraphicsItem*> ItemsAtPos = items(Event->scenePos());
    for (auto* Item : ItemsAtPos) {
        if (dynamic_cast<NodeGraphicsItem*>(Item)) {
            QGraphicsScene::contextMenuEvent(Event);
            return;
        }
    }

    if (!EnginePtr) return;

    QMenu ContextMenu;

    struct CategoryEntry {
        QString Name;
        QVector<QPair<QString, NodeType>> Types;
    };

    QVector<CategoryEntry> Categories = {
        {"Input", {
            {"ReadBytes", NodeType::ReadBytes}, {"ReadU8", NodeType::ReadU8},
            {"ReadU16", NodeType::ReadU16}, {"ReadU32", NodeType::ReadU32},
            {"ReadU64", NodeType::ReadU64}, {"ReadString", NodeType::ReadString},
            {"Constant", NodeType::Constant}, {"HexInput", NodeType::HexInput}
        }},
        {"Transform", {
            {"XorKey", NodeType::XorKey}, {"XorRepeating", NodeType::XorRepeating},
            {"Add", NodeType::Add}, {"Sub", NodeType::Sub},
            {"And", NodeType::And}, {"Or", NodeType::Or},
            {"Not", NodeType::Not}, {"Shl", NodeType::Shl},
            {"Shr", NodeType::Shr}, {"Rol", NodeType::Rol},
            {"Ror", NodeType::Ror}
        }},
        {"Crypto", {
            {"Base64 Encode", NodeType::Base64Encode}, {"Base64 Decode", NodeType::Base64Decode},
            {"RC4", NodeType::Rc4}
        }},
        {"Compress", {
            {"Zlib Decompress", NodeType::ZlibDecompress}, {"Zlib Compress", NodeType::ZlibCompress}
        }},
        {"Hash", {
            {"MD5", NodeType::Md5}, {"SHA-1", NodeType::Sha1},
            {"SHA-256", NodeType::Sha256}, {"CRC32", NodeType::Crc32}
        }},
        {"String", {
            {"To Hex", NodeType::ToHex}, {"From Hex", NodeType::FromHex},
            {"To ASCII", NodeType::ToAscii}, {"To UTF-8", NodeType::ToUtf8},
            {"Reverse", NodeType::Reverse}, {"Uppercase", NodeType::Uppercase},
            {"Lowercase", NodeType::Lowercase}
        }},
        {"Math", {
            {"Entropy", NodeType::Entropy}, {"Byte Count", NodeType::ByteCount},
            {"Length", NodeType::Length}
        }},
        {"Output", {
            {"Output Bytes", NodeType::OutputBytes}, {"Output String", NodeType::OutputString},
            {"Output File", NodeType::OutputFile}, {"Visualize", NodeType::Visualize}
        }}
    };

    QPointF SpawnPos = Event->scenePos();

    for (const auto& Cat : Categories) {
        QMenu* SubMenu = ContextMenu.addMenu(Cat.Name);
        for (const auto& Entry : Cat.Types) {
            QAction* Act = SubMenu->addAction(Entry.first);
            Act->setData(static_cast<int>(Entry.second));
        }
    }

    QAction* Chosen = ContextMenu.exec(Event->screenPos());
    if (Chosen) {
        NodeType Type = static_cast<NodeType>(Chosen->data().toInt());
        int NewId = EnginePtr->AddNode(Type, SpawnPos);
        Q_UNUSED(NewId);
        RebuildScene();
    }
}

void NodeGraphScene::keyPressEvent(QKeyEvent* Event) {
    if (Event->key() == Qt::Key_Delete || Event->key() == Qt::Key_Backspace) {
        QList<QGraphicsItem*> SelectedItems = selectedItems();
        for (auto* Item : SelectedItems) {
            auto* NodeItem = dynamic_cast<NodeGraphicsItem*>(Item);
            if (NodeItem) {
                emit NodeDeleted(NodeItem->GetNodeId());
                return;
            }
            auto* ConnItem = dynamic_cast<ConnectionGraphicsItem*>(Item);
            if (ConnItem) {
                NodeConnection Conn = ConnItem->GetConnection();
                emit ConnectionDeleted(Conn.SourceNodeId, Conn.SourcePortIndex, Conn.DestNodeId, Conn.DestPortIndex);
                return;
            }
        }
    }
    QGraphicsScene::keyPressEvent(Event);
}

DataProcessorWidget::DataProcessorWidget(QWidget* Parent)
    : QWidget(Parent)
    , Engine(new DataProcessorEngine(this))
    , Scene(new NodeGraphScene(this))
    , GraphView(nullptr)
    , NodePalette(nullptr)
    , PropertiesPanel(nullptr)
    , PropertiesLayout(nullptr)
    , OutputViewer(nullptr)
    , Toolbar(nullptr)
    , MainSplitter(nullptr)
    , RightSplitter(nullptr)
    , DbPtr(nullptr)
    , SelectedNodeId(-1)
{
    Scene->SetEngine(Engine);

    connect(Engine, &DataProcessorEngine::ExecutionComplete, this, &DataProcessorWidget::OnExecutionComplete);
    connect(Engine, &DataProcessorEngine::ExecutionError, this, &DataProcessorWidget::OnExecutionError);
    connect(Engine, &DataProcessorEngine::NodeOutputReady, this, &DataProcessorWidget::OnNodeOutputReady);

    connect(Scene, &NodeGraphScene::NodeSelected, this, &DataProcessorWidget::OnNodeSelected);
    connect(Scene, &NodeGraphScene::ConnectionRequested, this, &DataProcessorWidget::OnConnectionRequested);
    connect(Scene, &NodeGraphScene::NodeDeleted, this, &DataProcessorWidget::OnNodeDeleted);
    connect(Scene, &NodeGraphScene::ConnectionDeleted, this, &DataProcessorWidget::OnConnectionDeleted);

    SetupUi();
}

DataProcessorWidget::~DataProcessorWidget() = default;

void DataProcessorWidget::SetAnalysisDatabase(AnalysisDatabase* Db) {
    DbPtr = Db;
}

void DataProcessorWidget::SetupUi() {
    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(0, 0, 0, 0);
    MainLayout->setSpacing(0);

    SetupToolbar();
    MainLayout->addWidget(Toolbar);

    MainSplitter = new QSplitter(Qt::Horizontal, this);

    SetupNodePalette();
    MainSplitter->addWidget(NodePalette);

    GraphView = new QGraphicsView(Scene, this);
    GraphView->setRenderHint(QPainter::Antialiasing, true);
    GraphView->setDragMode(QGraphicsView::ScrollHandDrag);
    GraphView->setViewportUpdateMode(QGraphicsView::FullViewportUpdate);
    GraphView->setBackgroundBrush(QBrush(QColor(30, 30, 30)));
    GraphView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    GraphView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    GraphView->setTransformationAnchor(QGraphicsView::AnchorUnderMouse);
    GraphView->setResizeAnchor(QGraphicsView::AnchorUnderMouse);
    GraphView->setSceneRect(-5000, -5000, 10000, 10000);
    MainSplitter->addWidget(GraphView);

    RightSplitter = new QSplitter(Qt::Vertical, this);

    SetupPropertiesPanel();
    RightSplitter->addWidget(PropertiesPanel);

    SetupOutputViewer();
    RightSplitter->addWidget(OutputViewer);

    RightSplitter->setSizes({300, 200});
    MainSplitter->addWidget(RightSplitter);

    MainSplitter->setSizes({180, 600, 250});
    MainLayout->addWidget(MainSplitter);
}

void DataProcessorWidget::SetupToolbar() {
    Toolbar = new QToolBar(this);
    Toolbar->setIconSize(QSize(16, 16));
    Toolbar->setMovable(false);

    QAction* ExecuteAction = Toolbar->addAction("Execute");
    connect(ExecuteAction, &QAction::triggered, this, &DataProcessorWidget::OnExecute);

    Toolbar->addSeparator();

    QAction* ClearAction = Toolbar->addAction("Clear All");
    connect(ClearAction, &QAction::triggered, this, &DataProcessorWidget::OnClearAll);

    Toolbar->addSeparator();

    QAction* SaveAction = Toolbar->addAction("Save Pipeline");
    connect(SaveAction, &QAction::triggered, this, &DataProcessorWidget::OnSavePipeline);

    QAction* LoadAction = Toolbar->addAction("Load Pipeline");
    connect(LoadAction, &QAction::triggered, this, &DataProcessorWidget::OnLoadPipeline);

    Toolbar->addSeparator();

    QAction* LayoutAction = Toolbar->addAction("Auto-Layout");
    connect(LayoutAction, &QAction::triggered, this, &DataProcessorWidget::OnAutoLayout);

    QAction* FitAction = Toolbar->addAction("Zoom Fit");
    connect(FitAction, &QAction::triggered, this, &DataProcessorWidget::OnZoomFit);
}

void DataProcessorWidget::SetupNodePalette() {
    NodePalette = new QTreeWidget(this);
    NodePalette->setHeaderLabel("Nodes");
    NodePalette->setMinimumWidth(160);
    NodePalette->setMaximumWidth(220);
    NodePalette->setIndentation(14);

    QPalette Pal = NodePalette->palette();
    Pal.setColor(QPalette::Base, QColor(40, 40, 42));
    Pal.setColor(QPalette::Text, QColor(200, 200, 200));
    NodePalette->setPalette(Pal);

    struct PaletteCategory {
        QString Name;
        QVector<QPair<QString, NodeType>> Entries;
    };

    QVector<PaletteCategory> Cats = {
        {"Input", {
            {"Read Bytes", NodeType::ReadBytes}, {"Read U8", NodeType::ReadU8},
            {"Read U16", NodeType::ReadU16}, {"Read U32", NodeType::ReadU32},
            {"Read U64", NodeType::ReadU64}, {"Read String", NodeType::ReadString},
            {"Constant", NodeType::Constant}, {"Hex Input", NodeType::HexInput}
        }},
        {"Transform", {
            {"XOR Key", NodeType::XorKey}, {"XOR Repeating", NodeType::XorRepeating},
            {"Add", NodeType::Add}, {"Sub", NodeType::Sub},
            {"AND", NodeType::And}, {"OR", NodeType::Or},
            {"NOT", NodeType::Not}, {"SHL", NodeType::Shl},
            {"SHR", NodeType::Shr}, {"ROL", NodeType::Rol},
            {"ROR", NodeType::Ror}
        }},
        {"Crypto", {
            {"Base64 Encode", NodeType::Base64Encode}, {"Base64 Decode", NodeType::Base64Decode},
            {"RC4", NodeType::Rc4}
        }},
        {"Compress", {
            {"Zlib Decompress", NodeType::ZlibDecompress}, {"Zlib Compress", NodeType::ZlibCompress}
        }},
        {"Hash", {
            {"MD5", NodeType::Md5}, {"SHA-1", NodeType::Sha1},
            {"SHA-256", NodeType::Sha256}, {"CRC32", NodeType::Crc32}
        }},
        {"String", {
            {"To Hex", NodeType::ToHex}, {"From Hex", NodeType::FromHex},
            {"To ASCII", NodeType::ToAscii}, {"To UTF-8", NodeType::ToUtf8},
            {"Reverse", NodeType::Reverse}, {"Uppercase", NodeType::Uppercase},
            {"Lowercase", NodeType::Lowercase}
        }},
        {"Math", {
            {"Entropy", NodeType::Entropy}, {"Byte Count", NodeType::ByteCount},
            {"Length", NodeType::Length}
        }},
        {"Output", {
            {"Output Bytes", NodeType::OutputBytes}, {"Output String", NodeType::OutputString},
            {"Output File", NodeType::OutputFile}, {"Visualize", NodeType::Visualize}
        }}
    };

    for (const auto& Cat : Cats) {
        auto* CatItem = new QTreeWidgetItem(NodePalette);
        CatItem->setText(0, Cat.Name);
        CatItem->setExpanded(true);
        QFont BoldFont = CatItem->font(0);
        BoldFont.setBold(true);
        CatItem->setFont(0, BoldFont);
        QColor CatColor = NodeGraphicsItem::CategoryColor(Cat.Name);
        CatItem->setForeground(0, QBrush(CatColor));

        for (const auto& Entry : Cat.Entries) {
            auto* ChildItem = new QTreeWidgetItem(CatItem);
            ChildItem->setText(0, Entry.first);
            ChildItem->setData(0, Qt::UserRole, static_cast<int>(Entry.second));
        }
    }

    connect(NodePalette, &QTreeWidget::itemDoubleClicked, this, &DataProcessorWidget::AddNodeFromPalette);
}

void DataProcessorWidget::SetupPropertiesPanel() {
    auto* ScrollArea = new QScrollArea(this);
    ScrollArea->setWidgetResizable(true);
    ScrollArea->setMinimumWidth(200);

    PropertiesPanel = new QWidget(this);
    PropertiesLayout = new QFormLayout(PropertiesPanel);
    PropertiesLayout->setContentsMargins(6, 6, 6, 6);
    PropertiesLayout->setSpacing(4);

    QPalette Pal = PropertiesPanel->palette();
    Pal.setColor(QPalette::Window, QColor(40, 40, 42));
    PropertiesPanel->setPalette(Pal);
    PropertiesPanel->setAutoFillBackground(true);

    auto* HeaderLabel = new QLabel("Properties", PropertiesPanel);
    HeaderLabel->setStyleSheet("color: #cccccc; font-weight: bold; padding: 4px;");
    PropertiesLayout->addRow(HeaderLabel);

    ScrollArea->setWidget(PropertiesPanel);
    PropertiesPanel = ScrollArea;
}

void DataProcessorWidget::SetupOutputViewer() {
    OutputViewer = new QTextEdit(this);
    OutputViewer->setReadOnly(true);
    OutputViewer->setMinimumHeight(100);

    QFont MonoFont("Consolas", 9);
    MonoFont.setStyleHint(QFont::Monospace);
    OutputViewer->setFont(MonoFont);

    OutputViewer->setStyleSheet(
        "QTextEdit { background-color: #1e1e1e; color: #d4d4d4; border: none; }"
    );
}

void DataProcessorWidget::OnExecute() {
    OutputViewer->clear();
    OutputViewer->append("Executing pipeline...\n");
    bool Result = Engine->Execute(DbPtr);
    if (!Result) {
        OutputViewer->append("Pipeline execution failed.");
    }
}

void DataProcessorWidget::OnClearAll() {
    QVector<ProcessorNode> AllNodes = Engine->GetNodes();
    for (const auto& Node : AllNodes) {
        Engine->RemoveNode(Node.Id);
    }
    SelectedNodeId = -1;
    Scene->RebuildScene();
    OutputViewer->clear();

    auto* Scroll = qobject_cast<QScrollArea*>(PropertiesPanel);
    if (Scroll) {
        QWidget* Inner = Scroll->widget();
        if (Inner) {
            auto* Layout = qobject_cast<QFormLayout*>(Inner->layout());
            if (Layout) {
                while (Layout->rowCount() > 1) {
                    Layout->removeRow(Layout->rowCount() - 1);
                }
            }
        }
    }
}

void DataProcessorWidget::OnSavePipeline() {
    QString Path = QFileDialog::getSaveFileName(this, "Save Pipeline", QString(), "Pipeline Files (*.json);;All Files (*)");
    if (Path.isEmpty()) return;
    if (!Engine->SavePipeline(Path)) {
        QMessageBox::warning(this, "Save Error", "Failed to save pipeline.");
    }
}

void DataProcessorWidget::OnLoadPipeline() {
    QString Path = QFileDialog::getOpenFileName(this, "Load Pipeline", QString(), "Pipeline Files (*.json);;All Files (*)");
    if (Path.isEmpty()) return;
    if (!Engine->LoadPipeline(Path)) {
        QMessageBox::warning(this, "Load Error", "Failed to load pipeline.");
        return;
    }
    Scene->RebuildScene();
    SelectedNodeId = -1;
    OutputViewer->clear();
}

void DataProcessorWidget::OnAutoLayout() {
    QVector<ProcessorNode> AllNodes = Engine->GetNodes();
    int Columns = 4;
    qreal XSpacing = 200.0;
    qreal YSpacing = 150.0;

    for (int I = 0; I < AllNodes.size(); ++I) {
        int Col = I % Columns;
        int Row = I / Columns;
        QPointF NewPos(Col * XSpacing, Row * YSpacing);
        ProcessorNode* NodeRef = Engine->FindNode(AllNodes[I].Id);
        if (NodeRef) {
            NodeRef->Position = NewPos;
        }
    }
    Scene->RebuildScene();
}

void DataProcessorWidget::OnZoomFit() {
    QRectF BoundingRect = Scene->itemsBoundingRect();
    if (BoundingRect.isEmpty()) return;
    BoundingRect.adjust(-50, -50, 50, 50);
    GraphView->fitInView(BoundingRect, Qt::KeepAspectRatio);
}

void DataProcessorWidget::OnNodeSelected(int NodeId) {
    SelectedNodeId = NodeId;
    UpdatePropertiesPanel(NodeId);
    UpdateOutputViewer(NodeId);
}

void DataProcessorWidget::OnConnectionRequested(int SourceNode, int SourcePort, int DestNode, int DestPort) {
    if (SourceNode == -1) {
        NodeType Type = static_cast<NodeType>(SourcePort);
        QPointF Pos(static_cast<qreal>(DestNode), static_cast<qreal>(DestPort));
        Engine->AddNode(Type, Pos);
        Scene->RebuildScene();
        return;
    }
    Engine->Connect(SourceNode, SourcePort, DestNode, DestPort);
    Scene->RebuildScene();
}

void DataProcessorWidget::OnNodeDeleted(int NodeId) {
    Engine->RemoveNode(NodeId);
    if (SelectedNodeId == NodeId) {
        SelectedNodeId = -1;
    }
    Scene->RebuildScene();
}

void DataProcessorWidget::OnConnectionDeleted(int SourceNode, int SourcePort, int DestNode, int DestPort) {
    Engine->Disconnect(SourceNode, SourcePort, DestNode, DestPort);
    Scene->RebuildScene();
}

void DataProcessorWidget::OnExecutionComplete() {
    OutputViewer->append("\n--- Execution Complete ---\n");
    if (SelectedNodeId >= 0) {
        UpdateOutputViewer(SelectedNodeId);
    }
}

void DataProcessorWidget::OnExecutionError(const QString& NodeLabel, const QString& Error) {
    OutputViewer->append(QString("ERROR [%1]: %2").arg(NodeLabel, Error));
}

void DataProcessorWidget::OnNodeOutputReady(int NodeId, int PortIndex, const QByteArray& Data) {
    Q_UNUSED(PortIndex);
    if (NodeId == SelectedNodeId) {
        UpdateOutputViewer(NodeId);
    }
    Q_UNUSED(Data);
}

void DataProcessorWidget::UpdatePropertiesPanel(int NodeId) {
    auto* Scroll = qobject_cast<QScrollArea*>(PropertiesPanel);
    if (!Scroll) return;
    QWidget* Inner = Scroll->widget();
    if (!Inner) return;
    auto* Layout = qobject_cast<QFormLayout*>(Inner->layout());
    if (!Layout) return;

    while (Layout->rowCount() > 1) {
        Layout->removeRow(Layout->rowCount() - 1);
    }

    const ProcessorNode* Node = Engine->FindNode(NodeId);
    if (!Node) return;

    auto* TypeLabel = new QLabel(DataProcessorEngine::NodeTypeName(Node->Type), Inner);
    TypeLabel->setStyleSheet("color: #aaaaaa;");
    Layout->addRow("Type:", TypeLabel);

    QMap<QString, QVariant> Props = Node->Properties;
    for (auto It = Props.constBegin(); It != Props.constEnd(); ++It) {
        auto* LineEdit = new QLineEdit(It.value().toString(), Inner);
        LineEdit->setStyleSheet("background-color: #2a2a2e; color: #d4d4d4; border: 1px solid #555; padding: 2px;");
        QString Key = It.key();
        int CapturedNodeId = NodeId;
        connect(LineEdit, &QLineEdit::textChanged, this, [this, CapturedNodeId, Key](const QString& Text) {
            Engine->SetNodeProperty(CapturedNodeId, Key, Text);
        });
        Layout->addRow(Key + ":", LineEdit);
    }
}

void DataProcessorWidget::UpdateOutputViewer(int NodeId) {
    const ProcessorNode* Node = Engine->FindNode(NodeId);
    if (!Node) {
        OutputViewer->clear();
        return;
    }

    QString Output;
    Output += QString("Node: %1 (ID: %2)\n").arg(Node->Label).arg(Node->Id);
    Output += QString("Type: %1\n").arg(DataProcessorEngine::NodeTypeName(Node->Type));
    Output += "---\n";

    for (int I = 0; I < Node->OutputPorts.size(); ++I) {
        QByteArray Data = Engine->GetNodeOutput(NodeId, I);
        if (!Data.isEmpty()) {
            Output += QString("Output Port %1 (%2): %3 bytes\n").arg(I).arg(Node->OutputPorts[I].Name).arg(Data.size());
            Output += FormatHexDump(Data);
            Output += "\n";
        } else {
            Output += QString("Output Port %1 (%2): (no data)\n").arg(I).arg(Node->OutputPorts[I].Name);
        }
    }

    OutputViewer->setPlainText(Output);
}

void DataProcessorWidget::AddNodeFromPalette(QTreeWidgetItem* Item, int Column) {
    Q_UNUSED(Column);
    QVariant Data = Item->data(0, Qt::UserRole);
    if (!Data.isValid()) return;

    NodeType Type = static_cast<NodeType>(Data.toInt());
    QPointF Center = GraphView->mapToScene(GraphView->viewport()->rect().center());
    Engine->AddNode(Type, Center);
    Scene->RebuildScene();
}

QString DataProcessorWidget::FormatHexDump(const QByteArray& Data) const {
    QString Result;
    int TotalBytes = Data.size();
    const uint8_t* Ptr = reinterpret_cast<const uint8_t*>(Data.constData());

    for (int Offset = 0; Offset < TotalBytes; Offset += 16) {
        QString Line = QString("%1  | ").arg(Offset, 8, 16, QChar('0'));

        int BytesInLine = qMin(16, TotalBytes - Offset);

        QString HexPart;
        QString AsciiPart;

        for (int I = 0; I < 16; ++I) {
            if (I < BytesInLine) {
                uint8_t Byte = Ptr[Offset + I];
                HexPart += QString("%1 ").arg(Byte, 2, 16, QChar('0'));
                AsciiPart += (Byte >= 0x20 && Byte < 0x7F) ? QChar(Byte) : QChar('.');
            } else {
                HexPart += "   ";
                AsciiPart += " ";
            }
            if (I == 7) HexPart += " ";
        }

        Line += HexPart + "| " + AsciiPart;
        Result += Line + "\n";
    }

    return Result;
}

}
