#pragma once

#include <fidra/Types.h>
#include "../analysis/AnalysisDatabase.h"
#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QByteArray>
#include <QVector>

namespace Fidra {

class HistogramWidget : public QWidget {
    Q_OBJECT

public:
    explicit HistogramWidget(QWidget* Parent = nullptr);
    ~HistogramWidget() override;

    void AnalyzeData(const QByteArray& Data);
    void AnalyzeSegment(AnalysisDatabase* Db, const QString& SegmentName);
    void AnalyzeRange(AnalysisDatabase* Db, Address Start, Address End);

protected:
    void paintEvent(QPaintEvent* Event) override;
    void mouseMoveEvent(QMouseEvent* Event) override;
    void resizeEvent(QResizeEvent* Event) override;

private:
    void ComputeHistogram(const QByteArray& Data);
    void UpdateStatistics();
    QRect ChartRect() const;
    int BarIndexAt(const QPoint& Pos) const;
    QColor BarColor(double NormalizedFreq) const;
    QString FormatStatistics() const;

    uint64_t Frequencies[256];
    uint64_t TotalBytes;
    int UniqueValues;
    double ShannonEntropy;
    uint8_t MostCommonByte;
    uint64_t MostCommonCount;
    uint8_t LeastCommonByte;
    uint64_t LeastCommonCount;
    double ChiSquared;
    double CompressionRatioEstimate;
    uint64_t MaxFrequency;

    bool LogScale;
    bool ShowAsciiHighlight;
    int HoveredBar;

    QPushButton* ScaleToggle;
    QPushButton* AsciiToggle;
    QPushButton* CopyStatsButton;
    QLabel* StatsLabel;
};

}
