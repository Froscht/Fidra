#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QByteArray>
#include <QVector>
#include <QFont>

namespace Fidra {

struct EntropyBlock {
    Address Addr;
    double Entropy;
    int Size;
    bool IsCode;
    bool IsEncrypted;
    bool IsCompressed;
};

class EntropyMapWidget : public QWidget {
    Q_OBJECT

public:
    explicit EntropyMapWidget(QWidget* Parent = nullptr);
    ~EntropyMapWidget() override;

    void SetData(const QByteArray& Data, Address BaseAddr, int BlockSize = 256);
    void Clear();
    void SetCodeRegions(const QVector<QPair<Address, Address>>& Regions);
    void SetBlockSize(int Size);

    double AverageEntropy() const;
    int EncryptedBlockCount() const;

signals:
    void BlockClicked(Address Addr);
    void BlockHovered(Address Addr, double Entropy);

protected:
    void paintEvent(QPaintEvent* Event) override;
    void mousePressEvent(QMouseEvent* Event) override;
    void mouseMoveEvent(QMouseEvent* Event) override;
    void resizeEvent(QResizeEvent* Event) override;

private:
    void RecalculateEntropy();
    double ShannonEntropy(const uint8_t* Data, int Size);
    QColor EntropyColor(double Entropy) const;
    int BlockAtPos(const QPoint& Pos) const;
    void DrawLegend(QPainter& Painter, int X, int Y);

    QByteArray RawData;
    Address BaseAddress;
    int BlockSizeBytes;
    QVector<EntropyBlock> Blocks;
    QVector<QPair<Address, Address>> CodeRegions;
    int HoveredBlock;
    QFont LabelFont;
};

}
