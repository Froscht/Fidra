#include "CFGWidget.h"
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <QPainter>
#include <QPainterPath>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGraphicsSceneMouseEvent>
#include <QWheelEvent>
#include <QKeyEvent>
#include <QMenu>
#include <QFileDialog>
#include <QMessageBox>
#include <QScrollBar>
#include <QImageWriter>
#include <QQueue>
#include <QSet>
#include <QtMath>
#include <algorithm>

namespace Fidra {

CFGBlockItem::CFGBlockItem(Address BlockStart, Address BlockEnd,
                           const QList<AnalyzedInstruction>& Instructions,
                           BlockType Type, QGraphicsItem* Parent)
    : QGraphicsItem(Parent)
    , Start(BlockStart)
    , End(BlockEnd)
    , Type_(Type)
    , Insns(Instructions)
    , MonoFont("Consolas", 9)
    , Metrics(nullptr)
    , Width(BlockFixedWidth)
    , Height(0)
    , HeaderHeight(0)
    , LineHeight(0)
    , DisplayedCount(0)
    , Hovered(false)
    , Selected_(false)
    , Truncated(false)
{
    MonoFont.setStyleHint(QFont::Monospace);
    Metrics = new QFontMetrics(MonoFont);
    setAcceptHoverEvents(true);
    setFlag(QGraphicsItem::ItemIsSelectable, true);
    BuildLayout();
}

QRectF CFGBlockItem::boundingRect() const {
    return QRectF(-2, -2, Width + 4, Height + 4);
}

void CFGBlockItem::paint(QPainter* Painter, const QStyleOptionGraphicsItem*, QWidget*) {
    Painter->setRenderHint(QPainter::Antialiasing, true);
    Painter->setFont(MonoFont);

    QPainterPath Path;
    QRectF Rect(0, 0, Width, Height);
    Path.addRoundedRect(Rect, CornerRadius, CornerRadius);

    Painter->fillPath(Path, BackgroundColor());

    QPen Border(BorderColor(), Selected_ ? 2.5 : 1.5);
    if (Hovered && !Selected_) {
        Border.setColor(QColor(120, 160, 220));
        Border.setWidthF(2.0);
    }
    Painter->setPen(Border);
    Painter->drawPath(Path);

    Painter->setPen(QColor(180, 200, 220));
    QRectF HeaderRect(Padding, Padding, Width - 2 * Padding, HeaderHeight - Padding);
    QString HeaderText = QString("0x%1 - 0x%2")
        .arg(Start, 8, 16, QChar('0'))
        .arg(End, 8, 16, QChar('0'));
    Painter->drawText(HeaderRect, Qt::AlignLeft | Qt::AlignVCenter, HeaderText);

    Painter->setPen(QColor(60, 65, 75));
    qreal SepY = HeaderHeight;
    Painter->drawLine(QPointF(Padding, SepY), QPointF(Width - Padding, SepY));

    qreal Y = HeaderHeight + 4;
    for (int I = 0; I < DisplayedCount; ++I) {
        const auto& Inst = Insns[I];

        Painter->setPen(QColor(100, 110, 130));
        QString AddrStr = QString("%1  ").arg(Inst.Addr, 8, 16, QChar('0'));
        Painter->drawText(QPointF(Padding, Y + Metrics->ascent()), AddrStr);

        qreal MnemonicX = Padding + Metrics->horizontalAdvance(AddrStr);

        QColor MnColor(180, 180, 220);
        if (Inst.IsCall) MnColor = QColor(220, 160, 100);
        else if (Inst.IsJump) MnColor = QColor(100, 200, 160);
        else if (Inst.IsRet) MnColor = QColor(220, 100, 100);
        else if (Inst.IsNop) MnColor = QColor(100, 100, 100);

        Painter->setPen(MnColor);
        QString MnStr = Inst.Mnemonic.leftJustified(8);
        Painter->drawText(QPointF(MnemonicX, Y + Metrics->ascent()), MnStr);

        qreal OpX = MnemonicX + Metrics->horizontalAdvance(MnStr);
        Painter->setPen(QColor(200, 200, 200));
        Painter->drawText(QPointF(OpX, Y + Metrics->ascent()), Inst.Operands);

        Y += LineHeight;
    }

    if (Truncated) {
        Painter->setPen(QColor(140, 140, 160));
        QString MoreText = QString("... (%1 more)").arg(Insns.size() - DisplayedCount);
        Painter->drawText(QPointF(Padding, Y + Metrics->ascent()), MoreText);
    }
}

Address CFGBlockItem::StartAddr() const {
    return Start;
}

Address CFGBlockItem::EndAddr() const {
    return End;
}

QPointF CFGBlockItem::TopCenter() const {
    return pos() + QPointF(Width / 2.0, 0);
}

QPointF CFGBlockItem::BottomCenter() const {
    return pos() + QPointF(Width / 2.0, Height);
}

qreal CFGBlockItem::BlockWidth() const {
    return Width;
}

qreal CFGBlockItem::BlockHeight() const {
    return Height;
}

void CFGBlockItem::SetSelected(bool Selected) {
    Selected_ = Selected;
    update();
}

void CFGBlockItem::hoverEnterEvent(QGraphicsSceneHoverEvent*) {
    Hovered = true;
    update();
}

void CFGBlockItem::hoverLeaveEvent(QGraphicsSceneHoverEvent*) {
    Hovered = false;
    update();
}

void CFGBlockItem::mouseDoubleClickEvent(QGraphicsSceneMouseEvent* Event) {
    qreal Y = Event->pos().y();
    qreal ContentStart = HeaderHeight + 4;
    if (Y >= ContentStart && LineHeight > 0) {
        int LineIdx = static_cast<int>((Y - ContentStart) / LineHeight);
        if (LineIdx >= 0 && LineIdx < DisplayedCount && LineIdx < Insns.size()) {
            CFGWidget* CfgWidget = nullptr;
            QGraphicsScene* Sc = scene();
            if (Sc) {
                for (auto* V : Sc->views()) {
                    QWidget* W = V->parentWidget();
                    while (W) {
                        CfgWidget = qobject_cast<CFGWidget*>(W);
                        if (CfgWidget) break;
                        W = W->parentWidget();
                    }
                    if (CfgWidget) break;
                }
            }
            if (CfgWidget) {
                emit CfgWidget->AddressDoubleClicked(Insns[LineIdx].Addr);
            }
        }
    }
    QGraphicsItem::mouseDoubleClickEvent(Event);
}

void CFGBlockItem::BuildLayout() {
    LineHeight = Metrics->height() + 2;
    HeaderHeight = LineHeight + Padding * 2;

    DisplayedCount = qMin(static_cast<int>(Insns.size()), MaxDisplayLines);
    Truncated = Insns.size() > MaxDisplayLines;

    int ContentLines = DisplayedCount + (Truncated ? 1 : 0);
    Height = HeaderHeight + 4 + ContentLines * LineHeight + Padding;

    qreal MaxTextWidth = 0;
    for (int I = 0; I < DisplayedCount; ++I) {
        const auto& Inst = Insns[I];
        QString Line = QString("%1  %2 %3")
            .arg(Inst.Addr, 8, 16, QChar('0'))
            .arg(Inst.Mnemonic.leftJustified(8))
            .arg(Inst.Operands);
        qreal Tw = Metrics->horizontalAdvance(Line);
        if (Tw > MaxTextWidth) MaxTextWidth = Tw;
    }

    Width = qMax(BlockFixedWidth, MaxTextWidth + 2 * Padding + 4);
}

QColor CFGBlockItem::BackgroundColor() const {
    if (Hovered) {
        switch (Type_) {
            case Entry: return QColor(35, 55, 40);
            case Exit:  return QColor(55, 35, 35);
            default:    return QColor(42, 45, 55);
        }
    }
    switch (Type_) {
        case Entry: return QColor(30, 48, 35);
        case Exit:  return QColor(48, 30, 30);
        default:    return QColor(36, 39, 48);
    }
}

QColor CFGBlockItem::BorderColor() const {
    if (Selected_) return QColor(80, 160, 255);
    switch (Type_) {
        case Entry: return QColor(60, 140, 70);
        case Exit:  return QColor(140, 60, 60);
        default:    return QColor(60, 65, 80);
    }
}

CFGEdgeItem::CFGEdgeItem(CFGBlockItem* Source, CFGBlockItem* Target, EdgeType Type,
                         QGraphicsItem* Parent)
    : QGraphicsPathItem(Parent)
    , SourceBlock(Source)
    , TargetBlock(Target)
    , Type_(Type)
{
    switch (Type_) {
        case ConditionalTrue:
            ArrowColor = QColor(80, 200, 80);
            break;
        case ConditionalFalse:
            ArrowColor = QColor(200, 80, 80);
            break;
        default:
            ArrowColor = QColor(120, 120, 140);
            break;
    }
    EdgePen = QPen(ArrowColor, 1.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
    setPen(EdgePen);
    setZValue(-1);
    UpdatePath();
}

void CFGEdgeItem::UpdatePath() {
    if (!SourceBlock || !TargetBlock) return;

    QPointF StartPt = SourceBlock->BottomCenter();
    QPointF EndPt = TargetBlock->TopCenter();

    qreal Dx = EndPt.x() - StartPt.x();
    qreal Dy = EndPt.y() - StartPt.y();

    QPainterPath P;
    P.moveTo(StartPt);

    if (Dy > 0) {
        qreal Ctrl1Y = StartPt.y() + Dy * 0.3;
        qreal Ctrl2Y = EndPt.y() - Dy * 0.3;
        P.cubicTo(StartPt.x(), Ctrl1Y, EndPt.x(), Ctrl2Y, EndPt.x(), EndPt.y());
    } else {
        qreal Offset = 40.0 + qAbs(Dx) * 0.2;
        bool GoRight = Dx >= 0;
        qreal SideX = GoRight
            ? qMax(StartPt.x(), EndPt.x()) + Offset
            : qMin(StartPt.x(), EndPt.x()) - Offset;

        P.cubicTo(StartPt.x(), StartPt.y() + 30, SideX, StartPt.y() + 30, SideX, StartPt.y());
        P.lineTo(SideX, EndPt.y());
        P.cubicTo(SideX, EndPt.y() - 30, EndPt.x(), EndPt.y() - 30, EndPt.x(), EndPt.y());
    }

    setPath(P);
}

void CFGEdgeItem::paint(QPainter* Painter, const QStyleOptionGraphicsItem* Option, QWidget* Widget) {
    QGraphicsPathItem::paint(Painter, Option, Widget);

    if (!TargetBlock) return;

    QPointF Tip = TargetBlock->TopCenter();
    QPainterPath P = path();
    qreal Len = P.length();
    if (Len < 1.0) return;

    qreal T = qMax(0.0, Len - 10.0);
    QPointF Before = P.pointAtPercent(T / Len);
    DrawArrowhead(Painter, Tip, Before);
}

void CFGEdgeItem::DrawArrowhead(QPainter* Painter, const QPointF& Tip, const QPointF& From) {
    qreal Angle = std::atan2(Tip.y() - From.y(), Tip.x() - From.x());
    qreal ArrowSize = 8.0;
    qreal HalfAngle = M_PI / 7.0;

    QPointF P1(Tip.x() - ArrowSize * std::cos(Angle - HalfAngle),
               Tip.y() - ArrowSize * std::sin(Angle - HalfAngle));
    QPointF P2(Tip.x() - ArrowSize * std::cos(Angle + HalfAngle),
               Tip.y() - ArrowSize * std::sin(Angle + HalfAngle));

    QPolygonF Arrow;
    Arrow << Tip << P1 << P2;

    Painter->setPen(Qt::NoPen);
    Painter->setBrush(ArrowColor);
    Painter->drawPolygon(Arrow);
}

CFGMinimap::CFGMinimap(QGraphicsScene* Scene, QWidget* Parent)
    : QGraphicsView(Scene, Parent)
    , Dragging(false)
{
    setFixedSize(200, 150);
    setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    setInteractive(false);
    setRenderHint(QPainter::Antialiasing, false);
    setStyleSheet("background-color: rgba(20, 22, 28, 200); border: 1px solid #3a3d4a;");
}

void CFGMinimap::UpdateViewport(const QRectF& VisibleRect) {
    VisibleArea = VisibleRect;
    fitInView(scene()->sceneRect(), Qt::KeepAspectRatio);
    viewport()->update();
}

void CFGMinimap::paintEvent(QPaintEvent* Event) {
    QGraphicsView::paintEvent(Event);

    if (VisibleArea.isNull()) return;

    QPainter Painter(viewport());
    Painter.setRenderHint(QPainter::Antialiasing, false);

    QRectF SceneR = scene()->sceneRect();
    if (SceneR.isEmpty()) return;

    QRectF ViewR = viewport()->rect().toRectF();
    qreal ScaleX = ViewR.width() / SceneR.width();
    qreal ScaleY = ViewR.height() / SceneR.height();
    qreal Scale = qMin(ScaleX, ScaleY);

    qreal OffX = (ViewR.width() - SceneR.width() * Scale) / 2.0;
    qreal OffY = (ViewR.height() - SceneR.height() * Scale) / 2.0;

    QRectF MappedRect(
        OffX + (VisibleArea.x() - SceneR.x()) * Scale,
        OffY + (VisibleArea.y() - SceneR.y()) * Scale,
        VisibleArea.width() * Scale,
        VisibleArea.height() * Scale
    );

    Painter.setPen(QPen(QColor(80, 160, 255, 180), 1.5));
    Painter.setBrush(QColor(80, 160, 255, 30));
    Painter.drawRect(MappedRect);
}

void CFGMinimap::mousePressEvent(QMouseEvent* Event) {
    if (Event->button() == Qt::LeftButton) {
        Dragging = true;
        QPointF ScenePt = mapToScene(Event->pos());
        emit ViewportMoved(ScenePt);
    }
}

void CFGMinimap::mouseMoveEvent(QMouseEvent* Event) {
    if (Dragging) {
        QPointF ScenePt = mapToScene(Event->pos());
        emit ViewportMoved(ScenePt);
    }
}

CFGWidget::CFGWidget(QWidget* Parent)
    : QWidget(Parent)
    , View(nullptr)
    , Scene(nullptr)
    , Minimap(nullptr)
    , SearchInput(nullptr)
    , FitButton(nullptr)
    , SearchButton(nullptr)
    , CurrentDb(nullptr)
    , CurrentFunction(0)
    , SearchVisible(false)
{
    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(0, 0, 0, 0);
    MainLayout->setSpacing(0);

    auto* ToolBar = new QHBoxLayout();
    ToolBar->setContentsMargins(4, 4, 4, 4);
    ToolBar->setSpacing(4);

    FitButton = new QPushButton("Fit");
    FitButton->setFixedWidth(50);
    FitButton->setStyleSheet(
        "QPushButton { background: #2a2d38; color: #c0c8d8; border: 1px solid #3a3d4a; "
        "border-radius: 3px; padding: 3px 8px; }"
        "QPushButton:hover { background: #3a3d4a; }"
    );
    ToolBar->addWidget(FitButton);

    SearchButton = new QPushButton("Search");
    SearchButton->setFixedWidth(60);
    SearchButton->setStyleSheet(FitButton->styleSheet());
    ToolBar->addWidget(SearchButton);

    SearchInput = new QLineEdit();
    SearchInput->setPlaceholderText("Address (hex)...");
    SearchInput->setFixedWidth(180);
    SearchInput->setStyleSheet(
        "QLineEdit { background: #1e2028; color: #c0c8d8; border: 1px solid #3a3d4a; "
        "border-radius: 3px; padding: 3px 6px; font-family: Consolas; font-size: 9pt; }"
    );
    SearchInput->hide();
    ToolBar->addWidget(SearchInput);

    ToolBar->addStretch();
    MainLayout->addLayout(ToolBar);

    Scene = new QGraphicsScene(this);
    Scene->setBackgroundBrush(QColor(24, 26, 32));

    View = new QGraphicsView(Scene, this);
    View->setRenderHint(QPainter::Antialiasing, true);
    View->setDragMode(QGraphicsView::ScrollHandDrag);
    View->setTransformationAnchor(QGraphicsView::AnchorUnderMouse);
    View->setResizeAnchor(QGraphicsView::AnchorUnderMouse);
    View->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    View->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    View->setStyleSheet("QGraphicsView { border: none; background: #181a20; }");
    View->viewport()->installEventFilter(this);
    MainLayout->addWidget(View);

    Minimap = new CFGMinimap(Scene, this);
    Minimap->raise();

    connect(FitButton, &QPushButton::clicked, this, &CFGWidget::FitToView);
    connect(SearchButton, &QPushButton::clicked, this, &CFGWidget::ShowSearchBar);
    connect(SearchInput, &QLineEdit::returnPressed, this, &CFGWidget::DoSearch);
    connect(Minimap, &CFGMinimap::ViewportMoved, this, [this](const QPointF& Center) {
        View->centerOn(Center);
        UpdateMinimap();
    });

    View->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(View, &QWidget::customContextMenuRequested, this, [this](const QPoint& Pos) {
        QMenu Menu;
        Menu.setStyleSheet(
            "QMenu { background: #2a2d38; color: #c0c8d8; border: 1px solid #3a3d4a; }"
            "QMenu::item:selected { background: #3a3d4a; }"
        );
        Menu.addAction("Export as PNG", this, &CFGWidget::ExportAsPng);
        Menu.addSeparator();
        Menu.addAction("Fit to View", this, &CFGWidget::FitToView);
        Menu.exec(View->mapToGlobal(Pos));
    });
}

CFGWidget::~CFGWidget() {
    Clear();
}

void CFGWidget::ShowFunction(AnalysisDatabase* Db, Address FuncAddr) {
    if (!Db) return;

    CurrentDb = Db;
    CurrentFunction = FuncAddr;

    AnalyzedFunction Func = Db->GetFunction(FuncAddr);
    if (Func.Blocks.isEmpty()) {
        Func = Db->GetFunctionContaining(FuncAddr);
    }
    if (Func.Blocks.isEmpty()) return;

    Clear();
    CurrentDb = Db;
    CurrentFunction = FuncAddr;
    BuildGraph(Db, Func);
    LayoutGraph();
    CreateEdges(Func);
    FitToView();
    UpdateMinimap();
}

void CFGWidget::Clear() {
    for (auto* Edge : EdgeItems) {
        Scene->removeItem(Edge);
        delete Edge;
    }
    EdgeItems.clear();

    for (auto It = BlockItems.begin(); It != BlockItems.end(); ++It) {
        Scene->removeItem(It.value());
        delete It.value();
    }
    BlockItems.clear();
    BlockData.clear();
    Layers.clear();
    BlockLayerMap.clear();

    CurrentDb = nullptr;
    CurrentFunction = 0;
}

void CFGWidget::FitToView() {
    if (Scene->items().isEmpty()) return;
    QRectF SceneR = Scene->itemsBoundingRect().adjusted(-40, -40, 40, 40);
    View->fitInView(SceneR, Qt::KeepAspectRatio);
    UpdateMinimap();
}

bool CFGWidget::eventFilter(QObject* Obj, QEvent* Event) {
    if (Obj == View->viewport()) {
        if (Event->type() == QEvent::Wheel) {
            auto* WheelEv = static_cast<QWheelEvent*>(Event);
            if (WheelEv->modifiers() & Qt::ControlModifier) {
                qreal Factor = WheelEv->angleDelta().y() > 0 ? 1.15 : 1.0 / 1.15;
                View->scale(Factor, Factor);
                UpdateMinimap();
                return true;
            }
        }
        if (Event->type() == QEvent::KeyPress) {
            auto* KeyEv = static_cast<QKeyEvent*>(Event);
            if (KeyEv->modifiers() & Qt::ControlModifier && KeyEv->key() == Qt::Key_F) {
                ShowSearchBar();
                return true;
            }
        }
        if (Event->type() == QEvent::MouseButtonRelease || Event->type() == QEvent::MouseMove) {
            UpdateMinimap();
        }
    }
    return QWidget::eventFilter(Obj, Event);
}

void CFGWidget::BuildGraph(AnalysisDatabase* Db, const AnalyzedFunction& Func) {
    Address EntryAddr = Func.Start;

    for (const auto& Block : Func.Blocks) {
        BlockData[Block.Start] = Block;

        QList<AnalyzedInstruction> Insns = Db->GetInstructions(Block.Start, Block.End);

        CFGBlockItem::BlockType BType = CFGBlockItem::Normal;
        if (Block.Start == EntryAddr) {
            BType = CFGBlockItem::Entry;
        } else if (!Insns.isEmpty() && Insns.last().IsRet) {
            BType = CFGBlockItem::Exit;
        }

        auto* Item = new CFGBlockItem(Block.Start, Block.End, Insns, BType);
        Scene->addItem(Item);
        BlockItems[Block.Start] = Item;
    }
}

void CFGWidget::LayoutGraph() {
    AssignLayers();
    MinimizeCrossings();
    AssignPositions();
}

void CFGWidget::AssignLayers() {
    Layers.clear();
    BlockLayerMap.clear();

    if (BlockData.isEmpty()) return;

    Address EntryAddr = BlockItems.begin().key();
    for (auto It = BlockItems.begin(); It != BlockItems.end(); ++It) {
        if (It.value()->StartAddr() == CurrentFunction) {
            EntryAddr = CurrentFunction;
            break;
        }
    }
    if (!BlockData.contains(EntryAddr)) {
        EntryAddr = BlockData.firstKey();
    }

    QQueue<Address> Queue;
    QMap<Address, int> Depth;

    Queue.enqueue(EntryAddr);
    Depth[EntryAddr] = 0;

    while (!Queue.isEmpty()) {
        Address Curr = Queue.dequeue();
        int CurrDepth = Depth[Curr];

        if (!BlockData.contains(Curr)) continue;

        const auto& Block = BlockData[Curr];
        for (Address Succ : Block.Successors) {
            if (!BlockData.contains(Succ)) continue;
            if (!Depth.contains(Succ) || Depth[Succ] < CurrDepth + 1) {
                int NewDepth = CurrDepth + 1;
                if (Succ == Curr || Depth.contains(Succ)) {
                    if (Depth.contains(Succ) && Depth[Succ] <= CurrDepth) {
                        continue;
                    }
                }
                Depth[Succ] = NewDepth;
                Queue.enqueue(Succ);
            }
        }
    }

    for (auto It = BlockData.begin(); It != BlockData.end(); ++It) {
        if (!Depth.contains(It.key())) {
            Depth[It.key()] = 0;
        }
    }

    int MaxLayer = 0;
    for (auto It = Depth.begin(); It != Depth.end(); ++It) {
        if (It.value() > MaxLayer) MaxLayer = It.value();
    }

    Layers.resize(MaxLayer + 1);
    for (auto It = Depth.begin(); It != Depth.end(); ++It) {
        int Layer = It.value();
        BlockLayerMap[It.key()] = Layer;
        Layers[Layer].Blocks.append(It.key());
    }
}

void CFGWidget::MinimizeCrossings() {
    if (Layers.size() < 2) return;

    for (int Pass = 0; Pass < 4; ++Pass) {
        for (int L = 1; L < Layers.size(); ++L) {
            auto& LayerBlocks = Layers[L].Blocks;
            if (LayerBlocks.size() <= 1) continue;

            QMap<Address, double> Barycenter;
            for (Address Addr : LayerBlocks) {
                if (!BlockData.contains(Addr)) continue;
                const auto& Block = BlockData[Addr];
                double Sum = 0;
                int Count = 0;
                for (Address Pred : Block.Predecessors) {
                    if (!BlockData.contains(Pred)) continue;
                    int PredLayer = BlockLayerMap.value(Pred, -1);
                    if (PredLayer != L - 1) continue;
                    const auto& PrevLayerBlocks = Layers[L - 1].Blocks;
                    int Idx = PrevLayerBlocks.indexOf(Pred);
                    if (Idx >= 0) {
                        Sum += Idx;
                        Count++;
                    }
                }
                Barycenter[Addr] = Count > 0 ? Sum / Count : 0;
            }

            std::sort(LayerBlocks.begin(), LayerBlocks.end(),
                [&Barycenter](Address A, Address B) {
                    return Barycenter.value(A, 0) < Barycenter.value(B, 0);
                });
        }

        for (int L = static_cast<int>(Layers.size()) - 2; L >= 0; --L) {
            auto& LayerBlocks = Layers[L].Blocks;
            if (LayerBlocks.size() <= 1) continue;

            QMap<Address, double> Barycenter;
            for (Address Addr : LayerBlocks) {
                if (!BlockData.contains(Addr)) continue;
                const auto& Block = BlockData[Addr];
                double Sum = 0;
                int Count = 0;
                for (Address Succ : Block.Successors) {
                    if (!BlockData.contains(Succ)) continue;
                    int SuccLayer = BlockLayerMap.value(Succ, -1);
                    if (SuccLayer != L + 1) continue;
                    const auto& NextLayerBlocks = Layers[L + 1].Blocks;
                    int Idx = NextLayerBlocks.indexOf(Succ);
                    if (Idx >= 0) {
                        Sum += Idx;
                        Count++;
                    }
                }
                Barycenter[Addr] = Count > 0 ? Sum / Count : 0;
            }

            std::sort(LayerBlocks.begin(), LayerBlocks.end(),
                [&Barycenter](Address A, Address B) {
                    return Barycenter.value(A, 0) < Barycenter.value(B, 0);
                });
        }
    }
}

void CFGWidget::AssignPositions() {
    constexpr qreal VSpacing = 80.0;
    constexpr qreal HSpacing = 40.0;

    qreal CurrentY = 0;

    for (int L = 0; L < Layers.size(); ++L) {
        const auto& LayerBlocks = Layers[L].Blocks;
        if (LayerBlocks.isEmpty()) {
            CurrentY += VSpacing;
            continue;
        }

        qreal MaxHeight = 0;
        qreal TotalWidth = 0;

        for (Address Addr : LayerBlocks) {
            auto* Item = BlockItems.value(Addr, nullptr);
            if (!Item) continue;
            TotalWidth += Item->BlockWidth();
            if (Item->BlockHeight() > MaxHeight) MaxHeight = Item->BlockHeight();
        }
        TotalWidth += (LayerBlocks.size() - 1) * HSpacing;

        qreal StartX = -TotalWidth / 2.0;
        qreal X = StartX;

        for (Address Addr : LayerBlocks) {
            auto* Item = BlockItems.value(Addr, nullptr);
            if (!Item) continue;

            qreal YOffset = (MaxHeight - Item->BlockHeight()) / 2.0;
            Item->setPos(X, CurrentY + YOffset);
            X += Item->BlockWidth() + HSpacing;
        }

        CurrentY += MaxHeight + VSpacing;
    }
}

void CFGWidget::CreateEdges(const AnalyzedFunction& Func) {
    for (const auto& Block : Func.Blocks) {
        auto* SourceItem = BlockItems.value(Block.Start, nullptr);
        if (!SourceItem) continue;

        bool IsConditional = false;
        if (CurrentDb) {
            QList<AnalyzedInstruction> Insns = CurrentDb->GetInstructions(Block.Start, Block.End);
            if (!Insns.isEmpty()) {
                IsConditional = Insns.last().IsConditional && Insns.last().IsJump;
            }
        }

        for (int I = 0; I < Block.Successors.size(); ++I) {
            Address SuccAddr = Block.Successors[I];
            auto* TargetItem = BlockItems.value(SuccAddr, nullptr);
            if (!TargetItem) continue;

            CFGEdgeItem::EdgeType EType = CFGEdgeItem::Unconditional;
            if (IsConditional && Block.Successors.size() == 2) {
                EType = (I == 0) ? CFGEdgeItem::ConditionalTrue : CFGEdgeItem::ConditionalFalse;
            }

            auto* Edge = new CFGEdgeItem(SourceItem, TargetItem, EType);
            Scene->addItem(Edge);
            EdgeItems.append(Edge);
        }
    }
}

void CFGWidget::UpdateMinimap() {
    if (!Minimap || !View) return;

    QPointF TopLeft = View->mapToScene(0, 0);
    QPointF BottomRight = View->mapToScene(View->viewport()->width(), View->viewport()->height());
    QRectF VisibleRect(TopLeft, BottomRight);

    Minimap->UpdateViewport(VisibleRect);

    int Mx = width() - Minimap->width() - 8;
    int My = height() - Minimap->height() - 8;
    Minimap->move(Mx, My);
}

void CFGWidget::ShowSearchBar() {
    SearchVisible = !SearchVisible;
    SearchInput->setVisible(SearchVisible);
    if (SearchVisible) {
        SearchInput->setFocus();
        SearchInput->selectAll();
    }
}

void CFGWidget::DoSearch() {
    QString Text = SearchInput->text().trimmed();
    if (Text.isEmpty()) return;

    bool Ok = false;
    Address Addr = Text.toULongLong(&Ok, 16);
    if (!Ok) {
        if (Text.startsWith("0x", Qt::CaseInsensitive)) {
            Addr = Text.mid(2).toULongLong(&Ok, 16);
        }
    }
    if (!Ok) return;

    for (auto It = BlockItems.begin(); It != BlockItems.end(); ++It) {
        auto* Item = It.value();
        if (Addr >= Item->StartAddr() && Addr <= Item->EndAddr()) {
            for (auto Jt = BlockItems.begin(); Jt != BlockItems.end(); ++Jt) {
                Jt.value()->SetSelected(false);
            }
            Item->SetSelected(true);
            View->centerOn(Item);
            UpdateMinimap();
            return;
        }
    }
}

void CFGWidget::ExportAsPng() {
    QString Path = QFileDialog::getSaveFileName(this, "Export CFG as PNG", "", "PNG Files (*.png)");
    if (Path.isEmpty()) return;

    QRectF SceneR = Scene->itemsBoundingRect().adjusted(-20, -20, 20, 20);
    qreal Scale = 2.0;
    QImage Image(static_cast<int>(SceneR.width() * Scale),
                 static_cast<int>(SceneR.height() * Scale),
                 QImage::Format_ARGB32);
    Image.fill(QColor(24, 26, 32));

    QPainter Painter(&Image);
    Painter.setRenderHint(QPainter::Antialiasing, true);
    Painter.scale(Scale, Scale);
    Painter.translate(-SceneR.topLeft());
    Scene->render(&Painter, QRectF(), SceneR);
    Painter.end();

    Image.save(Path, "PNG");
}

}
