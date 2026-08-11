#include "EntropyMapWidget.h"
#include <QPainter>
#include <QPaintEvent>
#include <QMouseEvent>
#include <QFontMetrics>
#include <QtMath>
#include <cmath>

namespace Fidra {

EntropyMapWidget::EntropyMapWidget(QWidget* Parent)
    : QWidget(Parent)
    , BaseAddress(0)
    , BlockSizeBytes(256)
    , HoveredBlock(-1)
    , LabelFont("Consolas", 8)
{
    LabelFont.setStyleHint(QFont::Monospace);
    setMouseTracking(true);
    setMinimumHeight(80);
}

EntropyMapWidget::~EntropyMapWidget() = default;

void EntropyMapWidget::SetData(const QByteArray& Data, Address BaseAddr, int BlockSize) {
    RawData = Data;
    BaseAddress = BaseAddr;
    BlockSizeBytes = BlockSize;
    RecalculateEntropy();
    update();
}

void EntropyMapWidget::Clear() {
    RawData.clear();
    Blocks.clear();
    BaseAddress = 0;
    HoveredBlock = -1;
    update();
}

void EntropyMapWidget::SetCodeRegions(const QVector<QPair<Address, Address>>& Regions) {
    CodeRegions = Regions;
    for (auto& Block : Blocks) {
        Block.IsCode = false;
        for (const auto& Region : CodeRegions) {
            if (Block.Addr >= Region.first && Block.Addr < Region.second) {
                Block.IsCode = true;
                break;
            }
        }
    }
    update();
}

void EntropyMapWidget::SetBlockSize(int Size) {
    BlockSizeBytes = qMax(16, Size);
    RecalculateEntropy();
    update();
}

double EntropyMapWidget::AverageEntropy() const {
    if (Blocks.isEmpty()) return 0.0;
    double Sum = 0.0;
    for (const auto& Block : Blocks) Sum += Block.Entropy;
    return Sum / Blocks.size();
}

int EntropyMapWidget::EncryptedBlockCount() const {
    int Count = 0;
    for (const auto& Block : Blocks) {
        if (Block.IsEncrypted) Count++;
    }
    return Count;
}

void EntropyMapWidget::RecalculateEntropy() {
    Blocks.clear();
    if (RawData.isEmpty()) return;

    int NumBlocks = (RawData.size() + BlockSizeBytes - 1) / BlockSizeBytes;
    Blocks.reserve(NumBlocks);

    const uint8_t* DataPtr = reinterpret_cast<const uint8_t*>(RawData.constData());

    for (int I = 0; I < NumBlocks; ++I) {
        int Offset = I * BlockSizeBytes;
        int Size = qMin(BlockSizeBytes, RawData.size() - Offset);

        EntropyBlock Block;
        Block.Addr = BaseAddress + static_cast<Address>(Offset);
        Block.Size = Size;
        Block.Entropy = ShannonEntropy(DataPtr + Offset, Size);
        Block.IsEncrypted = Block.Entropy >= 7.5;
        Block.IsCompressed = Block.Entropy >= 6.5 && Block.Entropy < 7.5;
        Block.IsCode = false;

        for (const auto& Region : CodeRegions) {
            if (Block.Addr >= Region.first && Block.Addr < Region.second) {
                Block.IsCode = true;
                break;
            }
        }

        Blocks.append(Block);
    }
}

double EntropyMapWidget::ShannonEntropy(const uint8_t* Data, int Size) {
    if (Size <= 0) return 0.0;

    int Freq[256] = {};
    for (int I = 0; I < Size; ++I) {
        Freq[Data[I]]++;
    }

    double Entropy = 0.0;

    for (int I = 0; I < 256; ++I) {
        if (Freq[I] > 0) {
            double P = static_cast<double>(Freq[I]) / Size;
            Entropy -= P * std::log2(P);
        }
    }

    return Entropy;
}

QColor EntropyMapWidget::EntropyColor(double Entropy) const {
    if (Entropy < 1.0) return QColor(40, 40, 80);
    if (Entropy < 3.0) return QColor(40, 80, 40);
    if (Entropy < 5.0) return QColor(80, 120, 40);
    if (Entropy < 6.5) return QColor(180, 180, 40);
    if (Entropy < 7.5) return QColor(220, 120, 40);
    return QColor(220, 40, 40);
}

int EntropyMapWidget::BlockAtPos(const QPoint& Pos) const {
    if (Blocks.isEmpty()) return -1;

    int LegendHeight = 20;
    int MapHeight = height() - LegendHeight - 30;
    int MapY = 25;

    if (Pos.y() < MapY || Pos.y() > MapY + MapHeight) return -1;

    int AvailWidth = width() - 20;
    if (AvailWidth <= 0) return -1;

    int BlocksPerRow = qMax(1, AvailWidth / 4);
    int NumRows = (Blocks.size() + BlocksPerRow - 1) / BlocksPerRow;
    qreal BlockWidth = static_cast<qreal>(AvailWidth) / BlocksPerRow;
    qreal BlockHeight = NumRows > 0 ? static_cast<qreal>(MapHeight) / NumRows : MapHeight;

    int Col = static_cast<int>((Pos.x() - 10) / BlockWidth);
    int Row = static_cast<int>((Pos.y() - MapY) / BlockHeight);

    if (Col < 0 || Col >= BlocksPerRow || Row < 0) return -1;

    int Idx = Row * BlocksPerRow + Col;
    if (Idx >= Blocks.size()) return -1;

    return Idx;
}

void EntropyMapWidget::DrawLegend(QPainter& Painter, int X, int Y) {
    Painter.setFont(LabelFont);
    int SegWidth = 30;
    double Values[] = {0.0, 1.0, 3.0, 5.0, 6.5, 7.5, 8.0};
    QString Labels[] = {"0", "1", "3", "5", "6.5", "7.5", "8"};

    for (int I = 0; I < 6; ++I) {
        double Mid = (Values[I] + Values[I + 1]) / 2.0;
        Painter.fillRect(X + I * SegWidth, Y, SegWidth, 12, EntropyColor(Mid));
        Painter.setPen(QColor(200, 200, 200));
        Painter.drawText(X + I * SegWidth, Y + 24, Labels[I]);
    }
    Painter.drawText(X + 6 * SegWidth, Y + 24, "8");
}

void EntropyMapWidget::paintEvent(QPaintEvent*) {
    QPainter Painter(this);
    Painter.setRenderHint(QPainter::Antialiasing, false);
    Painter.fillRect(rect(), QColor(30, 30, 30));

    if (Blocks.isEmpty()) {
        Painter.setPen(QColor(128, 128, 128));
        Painter.drawText(rect(), Qt::AlignCenter, "No entropy data");
        return;
    }

    int Margin = 10;
    int HeaderHeight = 20;
    int LegendSpace = 30;
    int MapY = HeaderHeight + 5;
    int MapHeight = height() - MapY - LegendSpace;
    int AvailWidth = width() - 2 * Margin;

    Painter.setFont(LabelFont);
    Painter.setPen(QColor(200, 200, 200));
    QString Header = QString("Entropy Map | Avg: %1 | Encrypted: %2 | Blocks: %3 (size: %4)")
        .arg(AverageEntropy(), 0, 'f', 2)
        .arg(EncryptedBlockCount())
        .arg(Blocks.size())
        .arg(BlockSizeBytes);
    Painter.drawText(Margin, 14, Header);

    int BlocksPerRow = qMax(1, AvailWidth / 4);
    int NumRows = (Blocks.size() + BlocksPerRow - 1) / BlocksPerRow;
    qreal BlockWidth = static_cast<qreal>(AvailWidth) / BlocksPerRow;
    qreal BlockHeight = NumRows > 0 ? qMin(static_cast<qreal>(MapHeight) / NumRows, 20.0) : 20.0;

    for (int I = 0; I < Blocks.size(); ++I) {
        int Col = I % BlocksPerRow;
        int Row = I / BlocksPerRow;
        qreal X = Margin + Col * BlockWidth;
        qreal Y = MapY + Row * BlockHeight;

        QColor Fill = EntropyColor(Blocks[I].Entropy);
        if (I == HoveredBlock) Fill = Fill.lighter(150);

        Painter.fillRect(QRectF(X, Y, BlockWidth - 0.5, BlockHeight - 0.5), Fill);

        if (Blocks[I].IsCode) {
            Painter.setPen(QPen(QColor(100, 100, 255), 1));
            Painter.drawRect(QRectF(X, Y, BlockWidth - 1, BlockHeight - 1));
        }
    }

    DrawLegend(Painter, Margin, height() - LegendSpace + 2);

    if (HoveredBlock >= 0 && HoveredBlock < Blocks.size()) {
        const auto& Block = Blocks[HoveredBlock];
        QString Tip = QString("0x%1 | Entropy: %2 | %3")
            .arg(Block.Addr, 0, 16)
            .arg(Block.Entropy, 0, 'f', 3)
            .arg(Block.IsEncrypted ? "ENCRYPTED" : (Block.IsCompressed ? "COMPRESSED" : "normal"));

        Painter.setPen(QColor(255, 255, 200));
        QFontMetrics Fm(LabelFont);
        int TipWidth = Fm.horizontalAdvance(Tip) + 10;
        int TipX = qMin(width() - TipWidth - 5, width() / 2);
        Painter.fillRect(TipX - 2, 0, TipWidth + 4, 16, QColor(60, 60, 60));
        Painter.drawText(TipX, 12, Tip);
    }
}

void EntropyMapWidget::mousePressEvent(QMouseEvent* Event) {
    if (Event->button() == Qt::LeftButton) {
        int Idx = BlockAtPos(Event->pos());
        if (Idx >= 0 && Idx < Blocks.size()) {
            emit BlockClicked(Blocks[Idx].Addr);
        }
    }
    QWidget::mousePressEvent(Event);
}

void EntropyMapWidget::mouseMoveEvent(QMouseEvent* Event) {
    int Idx = BlockAtPos(Event->pos());
    if (Idx != HoveredBlock) {
        HoveredBlock = Idx;
        if (Idx >= 0 && Idx < Blocks.size()) {
            emit BlockHovered(Blocks[Idx].Addr, Blocks[Idx].Entropy);
        }
        update();
    }
    QWidget::mouseMoveEvent(Event);
}

void EntropyMapWidget::resizeEvent(QResizeEvent* Event) {
    QWidget::resizeEvent(Event);
}

}
