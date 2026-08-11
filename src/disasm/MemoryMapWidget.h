#pragma once

#include <fidra/Types.h>
#include "../analysis/AnalysisTypes.h"
#include <QWidget>
#include <QVector>
#include <QFont>
#include <QColor>
#include <QRectF>
#include <QPoint>

namespace Fidra {

class AnalysisDatabase;

struct SegmentVisual {
    QString Name;
    Address StartAddr;
    Address EndAddr;
    size_t Size;
    SegmentType Type;
    bool IsReadable;
    bool IsWritable;
    bool IsExecutable;
    QColor Color;
    QRectF Rect;
    double Entropy;
};

class MemoryMapWidget : public QWidget {
    Q_OBJECT

public:
    explicit MemoryMapWidget(QWidget* Parent = nullptr);
    ~MemoryMapWidget() override;

    void LoadFromDatabase(AnalysisDatabase* Db);
    void Clear();

signals:
    void NavigateToAddress(Address Addr);
    void SegmentSelected(const QString& Name);

protected:
    void paintEvent(QPaintEvent* Event) override;
    void mousePressEvent(QMouseEvent* Event) override;
    void mouseMoveEvent(QMouseEvent* Event) override;
    void mouseReleaseEvent(QMouseEvent* Event) override;
    void wheelEvent(QWheelEvent* Event) override;
    void resizeEvent(QResizeEvent* Event) override;

private:
    QColor SegmentColor(SegmentType Type) const;
    QString FormatSize(size_t Size) const;
    QString FormatAddress(Address Addr) const;
    int SegmentAtPos(const QPoint& Pos) const;
    double CalculateEntropy(const QByteArray& Data) const;
    QString PermissionsString(bool R, bool W, bool X) const;
    void RecalculateLayout();

    QVector<SegmentVisual> Segments;
    QVector<Address> FunctionAddresses;
    QVector<Address> StringAddresses;
    Address EntryPointAddr;
    Address ImageBaseAddr;
    QVector<Address> ImportAddresses;
    QVector<Address> ExportAddresses;

    int HoveredSegment;
    double ZoomLevel;
    double PanOffset;
    QPoint LastMousePos;
    bool IsDragging;
    QFont LabelFont;
    QFont HeaderFont;

    static constexpr int MapBarWidth = 120;
    static constexpr int MapBarX = 40;
    static constexpr int DetailPanelX = 200;
    static constexpr int TopMargin = 40;
    static constexpr int BottomMargin = 20;
};

}
