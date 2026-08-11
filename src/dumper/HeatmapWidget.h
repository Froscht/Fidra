#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QByteArray>
#include <QVector>
#include <QImage>
#include <QLabel>
#include <QSpinBox>
#include <QComboBox>

namespace Fidra {

class HeatmapWidget : public QWidget {
    Q_OBJECT

public:
    enum class Mode {
        Entropy,
        ByteClass,
        PageStatus
    };

    explicit HeatmapWidget(QWidget* Parent = nullptr);
    ~HeatmapWidget() override;

    void SetData(const QByteArray& Data, Address BaseAddr);
    void SetPageStatuses(const QVector<int>& Statuses);
    void SetMode(Mode NewMode);
    void SetBlockSize(int Bytes);

signals:
    void BlockClicked(Address Addr, int BlockIndex);
    void BlockHovered(Address Addr, double Entropy, int BlockIndex);

protected:
    void paintEvent(QPaintEvent* Event) override;
    void mousePressEvent(QMouseEvent* Event) override;
    void mouseMoveEvent(QMouseEvent* Event) override;
    void resizeEvent(QResizeEvent* Event) override;
    void wheelEvent(QWheelEvent* Event) override;

private:
    void Regenerate();
    double CalculateEntropy(const uint8_t* Data, int Size) const;
    QColor EntropyColor(double Entropy) const;
    QColor ByteClassColor(const uint8_t* Data, int Size) const;
    QColor PageStatusColor(int Status) const;
    int BlockAtPos(const QPoint& Pos) const;
    void UpdateLayout();

    QByteArray Buffer;
    Address Base;
    int BlockSize;
    Mode CurrentMode;
    QVector<QColor> BlockColors;
    QVector<double> BlockEntropies;
    QVector<int> PageStats;

    int CellSize;
    int Cols;
    int Rows;
    int MarginX;
    int MarginY;
    int HoveredBlock;

    QLabel* InfoLabel;
    QComboBox* ModeCombo;
    QSpinBox* BlockSizeSpin;
};

}
