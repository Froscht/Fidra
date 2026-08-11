#include "HistogramWidget.h"
#include <QPainter>
#include <QPaintEvent>
#include <QMouseEvent>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QToolTip>
#include <QClipboard>
#include <QApplication>
#include <QFont>
#include <cmath>
#include <cstring>
#include <algorithm>

namespace Fidra {

HistogramWidget::HistogramWidget(QWidget* Parent)
    : QWidget(Parent)
    , TotalBytes(0)
    , UniqueValues(0)
    , ShannonEntropy(0.0)
    , MostCommonByte(0)
    , MostCommonCount(0)
    , LeastCommonByte(0)
    , LeastCommonCount(0)
    , ChiSquared(0.0)
    , CompressionRatioEstimate(0.0)
    , MaxFrequency(0)
    , LogScale(false)
    , ShowAsciiHighlight(true)
    , HoveredBar(-1) {

    std::memset(Frequencies, 0, sizeof(Frequencies));

    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(4, 4, 4, 4);
    MainLayout->setSpacing(4);

    auto* ToolbarLayout = new QHBoxLayout();
    ToolbarLayout->setContentsMargins(0, 0, 0, 0);
    ToolbarLayout->setSpacing(4);

    ScaleToggle = new QPushButton("Linear", this);
    ScaleToggle->setCheckable(true);
    ScaleToggle->setFixedWidth(80);
    connect(ScaleToggle, &QPushButton::toggled, this, [this](bool Checked) {
        LogScale = Checked;
        ScaleToggle->setText(Checked ? "Log" : "Linear");
        update();
    });

    AsciiToggle = new QPushButton("ASCII", this);
    AsciiToggle->setCheckable(true);
    AsciiToggle->setChecked(true);
    AsciiToggle->setFixedWidth(80);
    connect(AsciiToggle, &QPushButton::toggled, this, [this](bool Checked) {
        ShowAsciiHighlight = Checked;
        update();
    });

    CopyStatsButton = new QPushButton("Copy Stats", this);
    CopyStatsButton->setFixedWidth(100);
    connect(CopyStatsButton, &QPushButton::clicked, this, [this]() {
        QApplication::clipboard()->setText(FormatStatistics());
    });

    ToolbarLayout->addWidget(ScaleToggle);
    ToolbarLayout->addWidget(AsciiToggle);
    ToolbarLayout->addWidget(CopyStatsButton);
    ToolbarLayout->addStretch();

    MainLayout->addLayout(ToolbarLayout);
    MainLayout->addStretch(1);

    StatsLabel = new QLabel(this);
    StatsLabel->setWordWrap(true);
    QFont MonoFont("Consolas", 9);
    MonoFont.setStyleHint(QFont::Monospace);
    StatsLabel->setFont(MonoFont);
    MainLayout->addWidget(StatsLabel);

    setMouseTracking(true);
    setMinimumSize(600, 350);
}

HistogramWidget::~HistogramWidget() = default;

void HistogramWidget::AnalyzeData(const QByteArray& Data) {
    ComputeHistogram(Data);
    UpdateStatistics();
    StatsLabel->setText(FormatStatistics());
    update();
}

void HistogramWidget::AnalyzeSegment(AnalysisDatabase* Db, const QString& SegmentName) {
    if (!Db) return;

    BinaryInfo Info = Db->GetBinaryInfo();
    for (const auto& Seg : Info.Segments) {
        if (Seg.Name == SegmentName) {
            AnalyzeData(Seg.Data);
            return;
        }
    }
}

void HistogramWidget::AnalyzeRange(AnalysisDatabase* Db, Address Start, Address End) {
    if (!Db || End <= Start) return;

    size_t Size = static_cast<size_t>(End - Start);
    QByteArray Data = Db->ReadBytes(Start, Size);
    if (!Data.isEmpty())
        AnalyzeData(Data);
}

void HistogramWidget::ComputeHistogram(const QByteArray& Data) {
    std::memset(Frequencies, 0, sizeof(Frequencies));
    TotalBytes = static_cast<uint64_t>(Data.size());
    MaxFrequency = 0;

    for (int I = 0; I < Data.size(); ++I) {
        uint8_t Byte = static_cast<uint8_t>(Data[I]);
        Frequencies[Byte]++;
    }

    for (int I = 0; I < 256; ++I) {
        if (Frequencies[I] > MaxFrequency)
            MaxFrequency = Frequencies[I];
    }
}

void HistogramWidget::UpdateStatistics() {
    UniqueValues = 0;
    MostCommonByte = 0;
    MostCommonCount = 0;
    LeastCommonByte = 0;
    LeastCommonCount = UINT64_MAX;
    ShannonEntropy = 0.0;
    ChiSquared = 0.0;
    CompressionRatioEstimate = 0.0;

    if (TotalBytes == 0) {
        LeastCommonCount = 0;
        return;
    }

    for (int I = 0; I < 256; ++I) {
        if (Frequencies[I] > 0) {
            UniqueValues++;
            double Prob = static_cast<double>(Frequencies[I]) / static_cast<double>(TotalBytes);
            ShannonEntropy -= Prob * std::log2(Prob);
        }

        if (Frequencies[I] > MostCommonCount) {
            MostCommonCount = Frequencies[I];
            MostCommonByte = static_cast<uint8_t>(I);
        }

        if (Frequencies[I] < LeastCommonCount) {
            LeastCommonCount = Frequencies[I];
            LeastCommonByte = static_cast<uint8_t>(I);
        }
    }

    double Expected = static_cast<double>(TotalBytes) / 256.0;
    for (int I = 0; I < 256; ++I) {
        double Diff = static_cast<double>(Frequencies[I]) - Expected;
        ChiSquared += (Diff * Diff) / Expected;
    }

    if (ShannonEntropy > 0.0)
        CompressionRatioEstimate = ShannonEntropy / 8.0;
    else
        CompressionRatioEstimate = 0.0;
}

QRect HistogramWidget::ChartRect() const {
    int LeftMargin = 60;
    int RightMargin = 20;
    int TopMargin = 40;
    int BottomMargin = 50;

    int StatsHeight = StatsLabel->isVisible() ? StatsLabel->sizeHint().height() + 8 : 0;
    int ToolbarHeight = 34;

    return QRect(
        LeftMargin,
        TopMargin + ToolbarHeight,
        width() - LeftMargin - RightMargin,
        height() - TopMargin - BottomMargin - StatsHeight - ToolbarHeight
    );
}

int HistogramWidget::BarIndexAt(const QPoint& Pos) const {
    QRect Chart = ChartRect();
    if (!Chart.contains(Pos) || Chart.width() <= 0)
        return -1;

    double BarWidth = static_cast<double>(Chart.width()) / 256.0;
    int Idx = static_cast<int>((Pos.x() - Chart.left()) / BarWidth);
    if (Idx < 0 || Idx > 255)
        return -1;
    return Idx;
}

QColor HistogramWidget::BarColor(double NormalizedFreq) const {
    int R, G, B;

    if (NormalizedFreq < 0.5) {
        double T = NormalizedFreq * 2.0;
        R = static_cast<int>(30 * (1.0 - T) + 50 * T);
        G = static_cast<int>(100 * (1.0 - T) + 200 * T);
        B = static_cast<int>(220 * (1.0 - T) + 80 * T);
    } else {
        double T = (NormalizedFreq - 0.5) * 2.0;
        R = static_cast<int>(50 * (1.0 - T) + 220 * T);
        G = static_cast<int>(200 * (1.0 - T) + 60 * T);
        B = static_cast<int>(80 * (1.0 - T) + 30 * T);
    }

    return QColor(R, G, B);
}

QString HistogramWidget::FormatStatistics() const {
    if (TotalBytes == 0)
        return "No data analyzed.";

    auto ByteLabel = [](uint8_t Val) -> QString {
        QString HexStr = QString("%1").arg(Val, 2, 16, QChar('0')).toUpper();
        if (Val >= 0x20 && Val <= 0x7E)
            return QString("0x%1 ('%2')").arg(HexStr, QString(QChar(Val)));
        return QString("0x%1").arg(HexStr);
    };

    double MostPct = (TotalBytes > 0)
        ? (static_cast<double>(MostCommonCount) / static_cast<double>(TotalBytes)) * 100.0
        : 0.0;
    double LeastPct = (TotalBytes > 0)
        ? (static_cast<double>(LeastCommonCount) / static_cast<double>(TotalBytes)) * 100.0
        : 0.0;

    QString Stats;
    Stats += QString("Total bytes: %1  |  Unique values: %2/256\n")
        .arg(TotalBytes).arg(UniqueValues);
    Stats += QString("Shannon entropy: %1 bits/byte\n")
        .arg(ShannonEntropy, 0, 'f', 4);
    Stats += QString("Most common: %1 = %2 (%3%)\n")
        .arg(ByteLabel(MostCommonByte)).arg(MostCommonCount).arg(MostPct, 0, 'f', 2);
    Stats += QString("Least common: %1 = %2 (%3%)\n")
        .arg(ByteLabel(LeastCommonByte)).arg(LeastCommonCount).arg(LeastPct, 0, 'f', 2);
    Stats += QString("Chi-squared: %1 (uniform dist.)\n")
        .arg(ChiSquared, 0, 'f', 2);
    Stats += QString("Compression ratio estimate: %1%")
        .arg(CompressionRatioEstimate * 100.0, 0, 'f', 1);

    return Stats;
}

void HistogramWidget::paintEvent(QPaintEvent* Event) {
    Q_UNUSED(Event);

    QPainter Painter(this);
    Painter.setRenderHint(QPainter::Antialiasing, false);

    Painter.fillRect(rect(), palette().window());

    QRect Chart = ChartRect();
    if (Chart.width() <= 0 || Chart.height() <= 0 || TotalBytes == 0)
        return;

    if (ShowAsciiHighlight) {
        double BarWidth = static_cast<double>(Chart.width()) / 256.0;
        int AsciiStart = static_cast<int>(0x20 * BarWidth) + Chart.left();
        int AsciiEnd = static_cast<int>(0x7F * BarWidth) + Chart.left();
        QColor HighlightColor = palette().highlight().color();
        HighlightColor.setAlpha(25);
        Painter.fillRect(QRect(AsciiStart, Chart.top(), AsciiEnd - AsciiStart, Chart.height()), HighlightColor);
    }

    Painter.setPen(palette().mid().color());
    Painter.drawRect(Chart);

    double BarWidth = static_cast<double>(Chart.width()) / 256.0;

    double MaxVal = static_cast<double>(MaxFrequency);
    if (LogScale && MaxFrequency > 0)
        MaxVal = std::log(static_cast<double>(MaxFrequency) + 1.0);

    for (int I = 0; I < 256; ++I) {
        if (Frequencies[I] == 0) continue;

        double Val = static_cast<double>(Frequencies[I]);
        if (LogScale)
            Val = std::log(Val + 1.0);

        double NormHeight = (MaxVal > 0.0) ? (Val / MaxVal) : 0.0;
        double NormFreq = (MaxFrequency > 0) ? (static_cast<double>(Frequencies[I]) / static_cast<double>(MaxFrequency)) : 0.0;

        int BarH = static_cast<int>(NormHeight * Chart.height());
        if (BarH < 1 && Frequencies[I] > 0) BarH = 1;

        int BarX = Chart.left() + static_cast<int>(I * BarWidth);
        int BarW = std::max(1, static_cast<int>(BarWidth));
        int BarY = Chart.bottom() - BarH;

        QColor Color = BarColor(NormFreq);
        if (I == HoveredBar) {
            Color = Color.lighter(140);
        }

        Painter.fillRect(QRect(BarX, BarY, BarW, BarH), Color);
    }

    Painter.setPen(palette().text().color());
    QFont AxisFont("Consolas", 8);
    AxisFont.setStyleHint(QFont::Monospace);
    Painter.setFont(AxisFont);

    for (int I = 0; I <= 0xFF; I += 0x10) {
        int TickX = Chart.left() + static_cast<int>(I * BarWidth);
        Painter.drawLine(TickX, Chart.bottom(), TickX, Chart.bottom() + 4);

        QString Label = QString("%1").arg(I, 2, 16, QChar('0')).toUpper();
        QRect LabelRect(TickX - 12, Chart.bottom() + 5, 24, 14);
        Painter.drawText(LabelRect, Qt::AlignCenter, Label);
    }

    int YTicks = 5;
    for (int I = 0; I <= YTicks; ++I) {
        double Frac = static_cast<double>(I) / static_cast<double>(YTicks);
        int TickY = Chart.bottom() - static_cast<int>(Frac * Chart.height());

        Painter.setPen(QPen(palette().mid().color(), 1, Qt::DotLine));
        if (I > 0 && I < YTicks)
            Painter.drawLine(Chart.left(), TickY, Chart.right(), TickY);

        Painter.setPen(palette().text().color());

        uint64_t YVal;
        if (LogScale) {
            double LogMax = std::log(static_cast<double>(MaxFrequency) + 1.0);
            YVal = static_cast<uint64_t>(std::exp(Frac * LogMax) - 1.0);
        } else {
            YVal = static_cast<uint64_t>(Frac * static_cast<double>(MaxFrequency));
        }

        QString YLabel;
        if (YVal >= 1000000)
            YLabel = QString("%1M").arg(static_cast<double>(YVal) / 1000000.0, 0, 'f', 1);
        else if (YVal >= 1000)
            YLabel = QString("%1K").arg(static_cast<double>(YVal) / 1000.0, 0, 'f', 1);
        else
            YLabel = QString::number(YVal);

        QRect YLabelRect(0, TickY - 7, Chart.left() - 4, 14);
        Painter.drawText(YLabelRect, Qt::AlignRight | Qt::AlignVCenter, YLabel);
    }

    QFont TitleFont("Consolas", 10, QFont::Bold);
    TitleFont.setStyleHint(QFont::Monospace);
    Painter.setFont(TitleFont);
    Painter.setPen(palette().text().color());
    Painter.drawText(QRect(Chart.left(), 4, Chart.width(), 30),
                     Qt::AlignHCenter | Qt::AlignTop,
                     "Byte Frequency Distribution");
}

void HistogramWidget::mouseMoveEvent(QMouseEvent* Event) {
    int NewHovered = BarIndexAt(Event->pos());

    if (NewHovered != HoveredBar) {
        HoveredBar = NewHovered;
        update();
    }

    if (HoveredBar >= 0 && HoveredBar <= 255) {
        uint8_t ByteVal = static_cast<uint8_t>(HoveredBar);
        uint64_t Count = Frequencies[ByteVal];
        double Pct = (TotalBytes > 0)
            ? (static_cast<double>(Count) / static_cast<double>(TotalBytes)) * 100.0
            : 0.0;

        QString CharInfo;
        if (ByteVal >= 0x20 && ByteVal <= 0x7E)
            CharInfo = QString(" ('%1')").arg(QChar(ByteVal));

        QString HexStr = QString("%1").arg(ByteVal, 2, 16, QChar('0')).toUpper();
        QString Tip = QString("0x%1%2: %3 occurrences (%4%)")
            .arg(HexStr)
            .arg(CharInfo)
            .arg(Count)
            .arg(Pct, 0, 'f', 2);

        QToolTip::showText(Event->globalPosition().toPoint(), Tip, this);
    } else {
        QToolTip::hideText();
    }

    QWidget::mouseMoveEvent(Event);
}

void HistogramWidget::resizeEvent(QResizeEvent* Event) {
    QWidget::resizeEvent(Event);
    update();
}

}
