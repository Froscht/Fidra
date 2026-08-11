#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QGraphicsView>
#include <QGraphicsScene>
#include <QGraphicsItem>
#include <QGraphicsPathItem>
#include <QLineEdit>
#include <QPushButton>
#include <QMap>
#include <QList>
#include <QFont>
#include <QPen>

namespace Fidra {

class AnalysisDatabase;
struct BasicBlock;
struct AnalyzedFunction;
struct AnalyzedInstruction;

class CFGBlockItem : public QGraphicsItem {
public:
    enum BlockType {
        Entry,
        Exit,
        Normal
    };

    CFGBlockItem(Address BlockStart, Address BlockEnd, const QList<AnalyzedInstruction>& Instructions,
                 BlockType Type, QGraphicsItem* Parent = nullptr);

    QRectF boundingRect() const override;
    void paint(QPainter* Painter, const QStyleOptionGraphicsItem* Option, QWidget* Widget) override;

    Address StartAddr() const;
    Address EndAddr() const;
    QPointF TopCenter() const;
    QPointF BottomCenter() const;
    qreal BlockWidth() const;
    qreal BlockHeight() const;
    void SetSelected(bool Selected);

protected:
    void hoverEnterEvent(QGraphicsSceneHoverEvent* Event) override;
    void hoverLeaveEvent(QGraphicsSceneHoverEvent* Event) override;
    void mouseDoubleClickEvent(QGraphicsSceneMouseEvent* Event) override;

private:
    void BuildLayout();
    QColor BackgroundColor() const;
    QColor BorderColor() const;

    Address Start;
    Address End;
    BlockType Type_;
    QList<AnalyzedInstruction> Insns;
    QFont MonoFont;
    QFontMetrics* Metrics;
    qreal Width;
    qreal Height;
    qreal HeaderHeight;
    qreal LineHeight;
    int DisplayedCount;
    bool Hovered;
    bool Selected_;
    bool Truncated;

    static constexpr qreal BlockFixedWidth = 300.0;
    static constexpr qreal Padding = 8.0;
    static constexpr qreal CornerRadius = 6.0;
    static constexpr int MaxDisplayLines = 20;
};

class CFGEdgeItem : public QGraphicsPathItem {
public:
    enum EdgeType {
        Unconditional,
        ConditionalTrue,
        ConditionalFalse
    };

    CFGEdgeItem(CFGBlockItem* Source, CFGBlockItem* Target, EdgeType Type,
                QGraphicsItem* Parent = nullptr);

    void UpdatePath();
    void paint(QPainter* Painter, const QStyleOptionGraphicsItem* Option, QWidget* Widget) override;

private:
    void DrawArrowhead(QPainter* Painter, const QPointF& Tip, const QPointF& From);

    CFGBlockItem* SourceBlock;
    CFGBlockItem* TargetBlock;
    EdgeType Type_;
    QPen EdgePen;
    QColor ArrowColor;
};

class CFGMinimap : public QGraphicsView {
    Q_OBJECT

public:
    explicit CFGMinimap(QGraphicsScene* Scene, QWidget* Parent = nullptr);

    void UpdateViewport(const QRectF& VisibleRect);

protected:
    void paintEvent(QPaintEvent* Event) override;
    void mousePressEvent(QMouseEvent* Event) override;
    void mouseMoveEvent(QMouseEvent* Event) override;

signals:
    void ViewportMoved(const QPointF& Center);

private:
    QRectF VisibleArea;
    bool Dragging;
};

class CFGWidget : public QWidget {
    Q_OBJECT

public:
    explicit CFGWidget(QWidget* Parent = nullptr);
    ~CFGWidget() override;

    void ShowFunction(AnalysisDatabase* Db, Address FuncAddr);
    void Clear();
    void FitToView();

signals:
    void AddressDoubleClicked(Address Addr);

protected:
    bool eventFilter(QObject* Obj, QEvent* Event) override;

private:
    struct LayerInfo {
        QList<Address> Blocks;
    };

    void BuildGraph(AnalysisDatabase* Db, const AnalyzedFunction& Func);
    void LayoutGraph();
    void AssignLayers();
    void MinimizeCrossings();
    void AssignPositions();
    void CreateEdges(const AnalyzedFunction& Func);
    void UpdateMinimap();
    void ShowSearchBar();
    void DoSearch();
    void ExportAsPng();

    QGraphicsView* View;
    QGraphicsScene* Scene;
    CFGMinimap* Minimap;
    QLineEdit* SearchInput;
    QPushButton* FitButton;
    QPushButton* SearchButton;

    QMap<Address, CFGBlockItem*> BlockItems;
    QList<CFGEdgeItem*> EdgeItems;
    QList<LayerInfo> Layers;
    QMap<Address, int> BlockLayerMap;
    QMap<Address, BasicBlock> BlockData;

    AnalysisDatabase* CurrentDb;
    Address CurrentFunction;
    bool SearchVisible;
};

}
