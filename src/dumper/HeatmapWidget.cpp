#include "HeatmapWidget.h"
#include <QPainter>
#include <QMouseEvent>
#include <QWheelEvent>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QToolTip>
#include <cmath>
#include <cstring>

namespace Fidra {

HeatmapWidget::HeatmapWidget(QWidget* Parent)
    : QWidget(Parent)
    , Base(0)
    , BlockSize(4096)
    , CurrentMode(Mode::Entropy)
    , CellSize(8)
    , Cols(64)
    , Rows(0)
    , MarginX(4)
    , MarginY(30)
    , HoveredBlock(-1)
{
    setMouseTracking(true);
    setMinimumSize(200, 100);

    auto* TopLayout = new QHBoxLayout();
    TopLayout->setContentsMargins(4, 4, 4, 0);

    ModeCombo = new QComboBox(this);
    ModeCombo->addItem("Entropy", static_cast<int>(Mode::Entropy));
    ModeCombo->addItem("Byte Class", static_cast<int>(Mode::ByteClass));
    ModeCombo->addItem("Page Status", static_cast<int>(Mode::PageStatus));
    TopLayout->addWidget(new QLabel("Mode:", this));
    TopLayout->addWidget(ModeCombo);

    BlockSizeSpin = new QSpinBox(this);
    BlockSizeSpin->setRange(16, 65536);
    BlockSizeSpin->setSingleStep(256);
    BlockSizeSpin->setValue(4096);
    BlockSizeSpin->setSuffix(" B");
    TopLayout->addWidget(new QLabel("Block:", this));
    TopLayout->addWidget(BlockSizeSpin);

    InfoLabel = new QLabel("No data", this);
    TopLayout->addWidget(InfoLabel, 1);

    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(0, 0, 0, 0);
    MainLayout->addLayout(TopLayout);
    MainLayout->addStretch();

    connect(ModeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int Index) {
        CurrentMode = static_cast<Mode>(ModeCombo->itemData(Index).toInt());
        Regenerate();
    });

    connect(BlockSizeSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int Value) {
        BlockSize = Value;
        Regenerate();
    });
}

HeatmapWidget::~HeatmapWidget() = default;

void HeatmapWidget::SetData(const QByteArray& Data, Address BaseAddr) {
    Buffer = Data;
    Base = BaseAddr;
    Regenerate();
}

void HeatmapWidget::SetPageStatuses(const QVector<int>& Statuses) {
    PageStats = Statuses;
    if (CurrentMode == Mode::PageStatus) {
        Regenerate();
    }
}

void HeatmapWidget::SetMode(Mode NewMode) {
    CurrentMode = NewMode;
    for (int I = 0; I < ModeCombo->count(); ++I) {
        if (ModeCombo->itemData(I).toInt() == static_cast<int>(NewMode)) {
            ModeCombo->setCurrentIndex(I);
            break;
        }
    }
    Regenerate();
}

void HeatmapWidget::SetBlockSize(int Bytes) {
    BlockSize = qMax(16, Bytes);
    BlockSizeSpin->setValue(BlockSize);
    Regenerate();
}

void HeatmapWidget::Regenerate() {
    BlockColors.clear();
    BlockEntropies.clear();

    if (Buffer.isEmpty() && PageStats.isEmpty()) {
        InfoLabel->setText("No data");
        update();
        return;
    }

    if (CurrentMode == Mode::PageStatus && !PageStats.isEmpty()) {
        int BlockCount = PageStats.size();
        BlockColors.resize(BlockCount);
        BlockEntropies.resize(BlockCount, 0.0);
        for (int I = 0; I < BlockCount; ++I) {
            BlockColors[I] = PageStatusColor(PageStats[I]);
        }
        InfoLabel->setText(QString("%1 pages").arg(BlockCount));
    } else if (!Buffer.isEmpty()) {
        int BlockCount = (Buffer.size() + BlockSize - 1) / BlockSize;
        BlockColors.resize(BlockCount);
        BlockEntropies.resize(BlockCount);

        auto* Raw = reinterpret_cast<const uint8_t*>(Buffer.constData());
        for (int I = 0; I < BlockCount; ++I) {
            int Offset = I * BlockSize;
            int Remaining = qMin(BlockSize, Buffer.size() - Offset);

            double Ent = CalculateEntropy(Raw + Offset, Remaining);
            BlockEntropies[I] = Ent;

            if (CurrentMode == Mode::Entropy) {
                BlockColors[I] = EntropyColor(Ent);
            } else {
                BlockColors[I] = ByteClassColor(Raw + Offset, Remaining);
            }
        }

        double AvgEntropy = 0.0;
        for (double E : BlockEntropies) AvgEntropy += E;
        if (!BlockEntropies.isEmpty()) AvgEntropy /= BlockEntropies.size();

        InfoLabel->setText(QString("%1 blocks, avg entropy: %2 bits/byte")
            .arg(BlockCount).arg(AvgEntropy, 0, 'f', 2));
    }

    UpdateLayout();
    update();
}

double HeatmapWidget::CalculateEntropy(const uint8_t* Data, int Size) const {
    if (Size <= 0) return 0.0;

    int Histogram[256] = {};
    for (int I = 0; I < Size; ++I)
        ++Histogram[Data[I]];

    double Entropy = 0.0;
    double Total = static_cast<double>(Size);
    for (int I = 0; I < 256; ++I) {
        if (Histogram[I] == 0) continue;
        double P = Histogram[I] / Total;
        Entropy -= P * std::log2(P);
    }
    return Entropy;
}

QColor HeatmapWidget::EntropyColor(double Entropy) const {
    double Normalized = Entropy / 8.0;
    if (Normalized > 1.0) Normalized = 1.0;

    if (Normalized < 0.125) {
        return QColor(0, 0, static_cast<int>(Normalized / 0.125 * 80));
    } else if (Normalized < 0.25) {
        double T = (Normalized - 0.125) / 0.125;
        return QColor(0, static_cast<int>(T * 160), 80);
    } else if (Normalized < 0.5) {
        double T = (Normalized - 0.25) / 0.25;
        return QColor(0, 160 + static_cast<int>(T * 95), static_cast<int>((1.0 - T) * 80));
    } else if (Normalized < 0.75) {
        double T = (Normalized - 0.5) / 0.25;
        return QColor(static_cast<int>(T * 255), 255, 0);
    } else if (Normalized < 0.875) {
        double T = (Normalized - 0.75) / 0.125;
        return QColor(255, static_cast<int>((1.0 - T) * 255), 0);
    } else {
        double T = (Normalized - 0.875) / 0.125;
        return QColor(255, 0, static_cast<int>(T * 200));
    }
}

QColor HeatmapWidget::ByteClassColor(const uint8_t* Data, int Size) const {
    int ZeroCount = 0;
    int AsciiCount = 0;
    int HighCount = 0;

    for (int I = 0; I < Size; ++I) {
        if (Data[I] == 0) ++ZeroCount;
        else if (Data[I] >= 0x20 && Data[I] <= 0x7E) ++AsciiCount;
        else ++HighCount;
    }

    double ZeroRatio = static_cast<double>(ZeroCount) / Size;
    double AsciiRatio = static_cast<double>(AsciiCount) / Size;

    if (ZeroRatio > 0.9) return QColor(20, 20, 40);
    if (AsciiRatio > 0.7) return QColor(60, 180, 60);
    if (ZeroRatio > 0.5) return QColor(40, 40, 80);

    double Entropy = CalculateEntropy(Data, Size);
    if (Entropy > 7.0) return QColor(220, 40, 40);
    if (Entropy > 5.0) return QColor(220, 160, 40);
    return QColor(80, 80, 180);
}

QColor HeatmapWidget::PageStatusColor(int Status) const {
    switch (Status) {
        case 0: return QColor(60, 200, 60);
        case 1: return QColor(200, 60, 60);
        case 2: return QColor(200, 200, 60);
        case 3: return QColor(80, 80, 80);
        default: return QColor(40, 40, 40);
    }
}

void HeatmapWidget::UpdateLayout() {
    int AvailWidth = width() - 2 * MarginX;
    if (AvailWidth < CellSize) return;

    Cols = qMax(1, AvailWidth / CellSize);
    int BlockCount = BlockColors.size();
    Rows = (BlockCount + Cols - 1) / Cols;
}

int HeatmapWidget::BlockAtPos(const QPoint& Pos) const {
    int X = Pos.x() - MarginX;
    int Y = Pos.y() - MarginY;

    if (X < 0 || Y < 0) return -1;

    int Col = X / CellSize;
    int Row = Y / CellSize;

    if (Col >= Cols) return -1;

    int Idx = Row * Cols + Col;
    if (Idx >= BlockColors.size()) return -1;
    return Idx;
}

void HeatmapWidget::paintEvent(QPaintEvent*) {
    QPainter Painter(this);
    Painter.setRenderHint(QPainter::Antialiasing, false);

    Painter.fillRect(rect(), QColor(24, 24, 28));

    if (BlockColors.isEmpty()) {
        Painter.setPen(QColor(128, 128, 128));
        Painter.drawText(rect(), Qt::AlignCenter, "No data loaded");
        return;
    }

    for (int I = 0; I < BlockColors.size(); ++I) {
        int Col = I % Cols;
        int Row = I / Cols;
        int X = MarginX + Col * CellSize;
        int Y = MarginY + Row * CellSize;

        Painter.fillRect(X, Y, CellSize - 1, CellSize - 1, BlockColors[I]);

        if (I == HoveredBlock) {
            Painter.setPen(QColor(255, 255, 255));
            Painter.drawRect(X - 1, Y - 1, CellSize, CellSize);
        }
    }

    if (CurrentMode == Mode::Entropy) {
        int LegendX = width() - 100;
        int LegendY = MarginY;
        int LegendH = qMin(120, height() - MarginY - 10);
        int LegendW = 16;

        for (int I = 0; I < LegendH; ++I) {
            double Entropy = 8.0 * (1.0 - static_cast<double>(I) / LegendH);
            Painter.setPen(EntropyColor(Entropy));
            Painter.drawLine(LegendX, LegendY + I, LegendX + LegendW, LegendY + I);
        }

        Painter.setPen(QColor(200, 200, 200));
        Painter.drawText(LegendX + LegendW + 4, LegendY + 10, "8.0");
        Painter.drawText(LegendX + LegendW + 4, LegendY + LegendH / 2, "4.0");
        Painter.drawText(LegendX + LegendW + 4, LegendY + LegendH, "0.0");
    }
}

void HeatmapWidget::mousePressEvent(QMouseEvent* Event) {
    if (Event->button() == Qt::LeftButton) {
        int Idx = BlockAtPos(Event->pos());
        if (Idx >= 0) {
            Address Addr = Base + static_cast<uint64_t>(Idx) * BlockSize;
            emit BlockClicked(Addr, Idx);
        }
    }
    QWidget::mousePressEvent(Event);
}

void HeatmapWidget::mouseMoveEvent(QMouseEvent* Event) {
    int Idx = BlockAtPos(Event->pos());
    if (Idx != HoveredBlock) {
        HoveredBlock = Idx;
        update();
    }

    if (Idx >= 0 && Idx < BlockEntropies.size()) {
        Address Addr = Base + static_cast<uint64_t>(Idx) * BlockSize;
        QString Tip = QString("Block %1 @ 0x%2\nEntropy: %3 bits/byte")
            .arg(Idx)
            .arg(Addr, 0, 16)
            .arg(BlockEntropies[Idx], 0, 'f', 2);
        QToolTip::showText(Event->globalPosition().toPoint(), Tip, this);
        emit BlockHovered(Addr, BlockEntropies[Idx], Idx);
    }

    QWidget::mouseMoveEvent(Event);
}

void HeatmapWidget::resizeEvent(QResizeEvent* Event) {
    QWidget::resizeEvent(Event);
    UpdateLayout();
    update();
}

void HeatmapWidget::wheelEvent(QWheelEvent* Event) {
    if (Event->modifiers() & Qt::ControlModifier) {
        int Delta = Event->angleDelta().y() > 0 ? 1 : -1;
        CellSize = qBound(2, CellSize + Delta, 32);
        UpdateLayout();
        update();
        Event->accept();
    } else {
        QWidget::wheelEvent(Event);
    }
}

}
