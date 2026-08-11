#pragma once

#include <fidra/Types.h>
#include "DataProcessorEngine.h"
#include <QWidget>
#include <QGraphicsScene>
#include <QGraphicsView>
#include <QGraphicsItem>
#include <QGraphicsPathItem>
#include <QTreeWidget>
#include <QTextEdit>
#include <QFormLayout>
#include <QScrollArea>
#include <QSplitter>
#include <QToolBar>
#include <QMap>

namespace Fidra {

class AnalysisDatabase;
class NodeGraphicsItem;
class ConnectionGraphicsItem;
class PortGraphicsItem;

class NodeGraphicsItem : public QGraphicsItem {
public:
    NodeGraphicsItem(ProcessorNode* Node, QGraphicsItem* Parent = nullptr);

    QRectF boundingRect() const override;
    void paint(QPainter* Painter, const QStyleOptionGraphicsItem* Option, QWidget* Widget) override;

    ProcessorNode* GetNode() const;
    int GetNodeId() const;

    QPointF GetPortScenePos(bool IsInput, int PortIndex) const;
    int PortAt(const QPointF& LocalPos, bool& IsInput) const;

    void UpdateLayout();

    static QColor CategoryColor(const QString& Category);

protected:
    QVariant itemChange(GraphicsItemChange Change, const QVariant& Value) override;
    void mousePressEvent(QGraphicsSceneMouseEvent* Event) override;
    void mouseReleaseEvent(QGraphicsSceneMouseEvent* Event) override;
    void contextMenuEvent(QGraphicsSceneContextMenuEvent* Event) override;

private:
    ProcessorNode* NodePtr;
    qreal NodeWidth;
    qreal NodeHeight;
    qreal TitleHeight;
    qreal PortRadius;
    qreal PortSpacing;
};

class ConnectionGraphicsItem : public QGraphicsPathItem {
public:
    ConnectionGraphicsItem(QGraphicsItem* Parent = nullptr);

    void SetConnection(const NodeConnection& Conn);
    NodeConnection GetConnection() const;

    void UpdatePath(QPointF Start, QPointF End);
    void SetColor(const QColor& Color);

protected:
    void paint(QPainter* Painter, const QStyleOptionGraphicsItem* Option, QWidget* Widget) override;

private:
    NodeConnection Conn;
    QColor LineColor;
};

class NodeGraphScene : public QGraphicsScene {
    Q_OBJECT

public:
    explicit NodeGraphScene(QObject* Parent = nullptr);

    void SetEngine(DataProcessorEngine* Engine);
    void RebuildScene();
    void UpdateConnections();

    NodeGraphicsItem* FindNodeItem(int NodeId) const;

signals:
    void NodeSelected(int NodeId);
    void ConnectionRequested(int SourceNode, int SourcePort, int DestNode, int DestPort);
    void NodeDeleted(int NodeId);
    void ConnectionDeleted(int SourceNode, int SourcePort, int DestNode, int DestPort);
    void NodeMoved(int NodeId, QPointF NewPos);

protected:
    void mousePressEvent(QGraphicsSceneMouseEvent* Event) override;
    void mouseMoveEvent(QGraphicsSceneMouseEvent* Event) override;
    void mouseReleaseEvent(QGraphicsSceneMouseEvent* Event) override;
    void contextMenuEvent(QGraphicsSceneContextMenuEvent* Event) override;
    void keyPressEvent(QKeyEvent* Event) override;

private:
    DataProcessorEngine* EnginePtr;
    QMap<int, NodeGraphicsItem*> NodeItems;
    QVector<ConnectionGraphicsItem*> ConnectionItems;

    bool DraggingConnection;
    int DragSourceNode;
    int DragSourcePort;
    QGraphicsPathItem* DragLine;
};

class DataProcessorWidget : public QWidget {
    Q_OBJECT

public:
    explicit DataProcessorWidget(QWidget* Parent = nullptr);
    ~DataProcessorWidget() override;

    void SetAnalysisDatabase(AnalysisDatabase* Db);

signals:
    void NavigateToAddress(Address Addr);

private:
    void SetupUi();
    void SetupToolbar();
    void SetupNodePalette();
    void SetupPropertiesPanel();
    void SetupOutputViewer();

    void OnExecute();
    void OnClearAll();
    void OnSavePipeline();
    void OnLoadPipeline();
    void OnAutoLayout();
    void OnZoomFit();

    void OnNodeSelected(int NodeId);
    void OnConnectionRequested(int SourceNode, int SourcePort, int DestNode, int DestPort);
    void OnNodeDeleted(int NodeId);
    void OnConnectionDeleted(int SourceNode, int SourcePort, int DestNode, int DestPort);

    void OnExecutionComplete();
    void OnExecutionError(const QString& NodeLabel, const QString& Error);
    void OnNodeOutputReady(int NodeId, int PortIndex, const QByteArray& Data);

    void UpdatePropertiesPanel(int NodeId);
    void UpdateOutputViewer(int NodeId);
    void AddNodeFromPalette(QTreeWidgetItem* Item, int Column);

    QString FormatHexDump(const QByteArray& Data) const;

    DataProcessorEngine* Engine;
    NodeGraphScene* Scene;
    QGraphicsView* GraphView;
    QTreeWidget* NodePalette;
    QWidget* PropertiesPanel;
    QFormLayout* PropertiesLayout;
    QTextEdit* OutputViewer;
    QToolBar* Toolbar;
    QSplitter* MainSplitter;
    QSplitter* RightSplitter;

    AnalysisDatabase* DbPtr;
    int SelectedNodeId;
};

}
