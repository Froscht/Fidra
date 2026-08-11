#include "EntropyWidget.h"
#include "PeParser.h"
#include <fidra/ICore.h>
#include <QPainter>
#include <QPaintEvent>
#include <QMouseEvent>
#include <QPainterPath>
#include <QFontMetrics>

namespace Fidra {

EntropyWidget::EntropyWidget(QWidget* Parent)
    : QWidget(Parent)
    , CoreRef(nullptr)
    , MaxOffset(0)
    , HoveredIndex(-1)
{
    setMinimumHeight(200);
    setMouseTracking(true);
    setBackgroundRole(QPalette::Window);
    setAutoFillBackground(true);
}

EntropyWidget::~EntropyWidget() = default;

void EntropyWidget::SetCore(ICore* Core)
{
    CoreRef = Core;
}

void EntropyWidget::SetEntropyData(const QList<QPair<uint64_t, double>>& Data)
{
    EntropyData = Data;
    MaxOffset = 0;
    if (!EntropyData.isEmpty()) {
        MaxOffset = EntropyData.last().first;
    }
    update();
}

void EntropyWidget::SetSections(const QList<PeSectionInfo>& Sections)
{
    SectionBoundaries.clear();
    for (const auto& Section : Sections) {
        SectionBoundaries.append({Section.VirtualAddress, Section.Name});
    }
    update();
}

void EntropyWidget::Clear()
{
    EntropyData.clear();
    SectionBoundaries.clear();
    MaxOffset = 0;
    HoveredIndex = -1;
    update();
}

void EntropyWidget::paintEvent(QPaintEvent* Event)
{
    Q_UNUSED(Event);

    QPainter Painter(this);
    Painter.setRenderHint(QPainter::Antialiasing, true);
    Painter.setRenderHint(QPainter::TextAntialiasing, true);

    QColor BgColor = palette().color(QPalette::Window);
    Painter.fillRect(rect(), BgColor);

    if (EntropyData.isEmpty()) {
        Painter.setPen(palette().color(QPalette::WindowText));
        QFont EmptyFont = font();
        EmptyFont.setPointSize(12);
        Painter.setFont(EmptyFont);
        Painter.drawText(rect(), Qt::AlignCenter, "No data loaded");
        return;
    }

    int DrawLeft = MarginLeft;
    int DrawTop = MarginTop;
    int DrawWidth = width() - MarginLeft - MarginRight;
    int DrawHeight = height() - MarginTop - MarginBottom;

    if (DrawWidth <= 0 || DrawHeight <= 0)
        return;

    QColor TextColor = palette().color(QPalette::WindowText);
    QColor GridColor = palette().color(QPalette::Mid);
    GridColor.setAlpha(80);

    QFont AxisFont = font();
    AxisFont.setPointSize(8);
    Painter.setFont(AxisFont);
    QFontMetrics Fm(AxisFont);

    QPen AxisPen(TextColor, 1.0);
    Painter.setPen(AxisPen);
    Painter.drawLine(DrawLeft, DrawTop, DrawLeft, DrawTop + DrawHeight);
    Painter.drawLine(DrawLeft, DrawTop + DrawHeight, DrawLeft + DrawWidth, DrawTop + DrawHeight);

    for (int I = 0; I <= 8; ++I) {
        int Y = DrawTop + DrawHeight - static_cast<int>(DrawHeight * I / 8.0);
        QString Label = QString::number(I);
        QRect LabelRect(0, Y - Fm.height() / 2, MarginLeft - 8, Fm.height());
        Painter.setPen(TextColor);
        Painter.drawText(LabelRect, Qt::AlignRight | Qt::AlignVCenter, Label);
        Painter.drawLine(DrawLeft - 4, Y, DrawLeft, Y);

        if (I > 0 && I < 8) {
            QPen DashPen(GridColor, 1.0, Qt::DotLine);
            Painter.setPen(DashPen);
            Painter.drawLine(DrawLeft + 1, Y, DrawLeft + DrawWidth, Y);
        }
    }

    Painter.save();
    Painter.setPen(TextColor);
    QFont VertFont = AxisFont;
    VertFont.setPointSize(9);
    VertFont.setBold(true);
    Painter.setFont(VertFont);
    Painter.translate(12, DrawTop + DrawHeight / 2);
    Painter.rotate(-90);
    Painter.drawText(QRect(-50, -10, 100, 20), Qt::AlignCenter, "Entropy");
    Painter.restore();

    int TickCount = qMin(8, static_cast<int>(MaxOffset > 0 ? 8 : 0));
    if (TickCount > 0 && MaxOffset > 0) {
        Painter.setPen(TextColor);
        Painter.setFont(AxisFont);
        for (int I = 0; I <= TickCount; ++I) {
            uint64_t OffsetVal = MaxOffset * I / TickCount;
            int X = DrawLeft + static_cast<int>(static_cast<double>(DrawWidth) * I / TickCount);
            Painter.drawLine(X, DrawTop + DrawHeight, X, DrawTop + DrawHeight + 4);
            QString HexLabel = QString("0x%1").arg(OffsetVal, 0, 16).toUpper();
            QRect TickLabelRect(X - 30, DrawTop + DrawHeight + 6, 60, Fm.height());
            Painter.drawText(TickLabelRect, Qt::AlignCenter, HexLabel);
        }
    }

    double BarWidth = static_cast<double>(DrawWidth) / EntropyData.size();
    if (BarWidth < 1.0)
        BarWidth = 1.0;

    QPainterPath LinePath;
    bool FirstPoint = true;

    for (int I = 0; I < EntropyData.size(); ++I) {
        double Offset = static_cast<double>(EntropyData[I].first);
        double Entropy = EntropyData[I].second;

        double XPos;
        if (MaxOffset > 0) {
            XPos = DrawLeft + (Offset / static_cast<double>(MaxOffset)) * DrawWidth;
        } else {
            XPos = DrawLeft + static_cast<double>(I) / EntropyData.size() * DrawWidth;
        }

        double YPos = DrawTop + DrawHeight * (1.0 - Entropy / 8.0);
        double BarHeight = DrawTop + DrawHeight - YPos;

        QColor BarColor = EntropyToColor(Entropy);
        BarColor.setAlpha(180);
        Painter.setPen(Qt::NoPen);
        Painter.setBrush(BarColor);
        Painter.drawRect(QRectF(XPos, YPos, qMax(BarWidth, 1.0), BarHeight));

        if (FirstPoint) {
            LinePath.moveTo(XPos + BarWidth / 2.0, YPos);
            FirstPoint = false;
        } else {
            LinePath.lineTo(XPos + BarWidth / 2.0, YPos);
        }
    }

    if (!FirstPoint) {
        QPen LinePen(palette().color(QPalette::Highlight), 1.5);
        Painter.setPen(LinePen);
        Painter.setBrush(Qt::NoBrush);
        Painter.drawPath(LinePath);
    }

    QPen RefPenHigh(QColor(220, 50, 50, 150), 1.0, Qt::DashLine);
    Painter.setPen(RefPenHigh);
    int HighY = DrawTop + static_cast<int>(DrawHeight * (1.0 - 7.0 / 8.0));
    Painter.drawLine(DrawLeft + 1, HighY, DrawLeft + DrawWidth, HighY);

    QPen RefPenMid(QColor(220, 180, 50, 150), 1.0, Qt::DashLine);
    Painter.setPen(RefPenMid);
    int MidY = DrawTop + static_cast<int>(DrawHeight * (1.0 - 4.5 / 8.0));
    Painter.drawLine(DrawLeft + 1, MidY, DrawLeft + DrawWidth, MidY);

    bool IsDarkTheme = BgColor.lightnessF() < 0.5;
    QColor SectionLineColor = IsDarkTheme ? QColor(200, 200, 200, 180) : QColor(60, 60, 60, 180);

    for (const auto& Boundary : SectionBoundaries) {
        if (MaxOffset == 0)
            break;

        double XPos = DrawLeft + (static_cast<double>(Boundary.first) / static_cast<double>(MaxOffset)) * DrawWidth;
        if (XPos < DrawLeft || XPos > DrawLeft + DrawWidth)
            continue;

        QPen SectionPen(SectionLineColor, 1.0, Qt::DashDotLine);
        Painter.setPen(SectionPen);
        Painter.drawLine(static_cast<int>(XPos), DrawTop, static_cast<int>(XPos), DrawTop + DrawHeight);

        Painter.save();
        QFont SectionFont = AxisFont;
        SectionFont.setPointSize(7);
        SectionFont.setBold(true);
        Painter.setFont(SectionFont);
        Painter.setPen(SectionLineColor);
        Painter.translate(static_cast<int>(XPos) + 2, DrawTop + 2);
        Painter.rotate(45);
        Painter.drawText(0, 0, Boundary.second);
        Painter.restore();
    }

    if (HoveredIndex >= 0 && HoveredIndex < EntropyData.size()) {
        uint64_t HoverOffset = EntropyData[HoveredIndex].first;
        double HoverEntropy = EntropyData[HoveredIndex].second;

        QString TooltipText = QString("Offset: 0x%1\nEntropy: %2")
            .arg(HoverOffset, 0, 16)
            .arg(HoverEntropy, 0, 'f', 4);

        double HoverX;
        if (MaxOffset > 0) {
            HoverX = DrawLeft + (static_cast<double>(HoverOffset) / static_cast<double>(MaxOffset)) * DrawWidth;
        } else {
            HoverX = DrawLeft + static_cast<double>(HoveredIndex) / EntropyData.size() * DrawWidth;
        }
        double HoverY = DrawTop + DrawHeight * (1.0 - HoverEntropy / 8.0);

        QColor DotColor = EntropyToColor(HoverEntropy);
        Painter.setPen(QPen(DotColor.darker(130), 2.0));
        Painter.setBrush(DotColor);
        Painter.drawEllipse(QPointF(HoverX + BarWidth / 2.0, HoverY), 4.0, 4.0);

        QFont TooltipFont = font();
        TooltipFont.setPointSize(9);
        Painter.setFont(TooltipFont);
        QFontMetrics TooltipFm(TooltipFont);
        QStringList Lines = TooltipText.split('\n');
        int MaxLineWidth = 0;
        for (const auto& Line : Lines) {
            MaxLineWidth = qMax(MaxLineWidth, TooltipFm.horizontalAdvance(Line));
        }
        int TooltipW = MaxLineWidth + 16;
        int TooltipH = Lines.size() * TooltipFm.height() + 10;

        int TipX = static_cast<int>(HoverX + BarWidth / 2.0) + 12;
        int TipY = static_cast<int>(HoverY) - TooltipH - 8;

        if (TipX + TooltipW > width() - MarginRight)
            TipX = static_cast<int>(HoverX) - TooltipW - 12;
        if (TipY < MarginTop)
            TipY = static_cast<int>(HoverY) + 12;

        QColor TooltipBg = IsDarkTheme ? QColor(40, 40, 40, 230) : QColor(255, 255, 240, 230);
        QColor TooltipBorder = IsDarkTheme ? QColor(100, 100, 100) : QColor(180, 180, 180);
        QColor TooltipTextColor = IsDarkTheme ? QColor(220, 220, 220) : QColor(30, 30, 30);

        Painter.setPen(QPen(TooltipBorder, 1.0));
        Painter.setBrush(TooltipBg);
        Painter.drawRoundedRect(TipX, TipY, TooltipW, TooltipH, 4, 4);

        Painter.setPen(TooltipTextColor);
        int TextY = TipY + 5 + TooltipFm.ascent();
        for (const auto& Line : Lines) {
            Painter.drawText(TipX + 8, TextY, Line);
            TextY += TooltipFm.height();
        }
    }
}

void EntropyWidget::mouseMoveEvent(QMouseEvent* Event)
{
    if (EntropyData.isEmpty() || MaxOffset == 0) {
        HoveredIndex = -1;
        update();
        return;
    }

    int DrawLeft_ = MarginLeft;
    int DrawWidth_ = width() - MarginLeft - MarginRight;

    if (DrawWidth_ <= 0) {
        HoveredIndex = -1;
        update();
        return;
    }

    int MouseX = static_cast<int>(Event->position().x());

    if (MouseX < DrawLeft_ || MouseX > DrawLeft_ + DrawWidth_) {
        HoveredIndex = -1;
        update();
        return;
    }

    double Ratio = static_cast<double>(MouseX - DrawLeft_) / DrawWidth_;
    uint64_t TargetOffset = static_cast<uint64_t>(Ratio * MaxOffset);

    int ClosestIdx = 0;
    uint64_t ClosestDist = UINT64_MAX;
    for (int I = 0; I < EntropyData.size(); ++I) {
        uint64_t Dist = (EntropyData[I].first > TargetOffset)
            ? (EntropyData[I].first - TargetOffset)
            : (TargetOffset - EntropyData[I].first);
        if (Dist < ClosestDist) {
            ClosestDist = Dist;
            ClosestIdx = I;
        }
    }

    HoveredIndex = ClosestIdx;
    update();
}

void EntropyWidget::resizeEvent(QResizeEvent* Event)
{
    Q_UNUSED(Event);
    update();
}

QColor EntropyWidget::EntropyToColor(double Entropy) const
{
    Entropy = qBound(0.0, Entropy, 8.0);

    double T = Entropy / 8.0;

    struct ColorStop {
        double Position;
        int R, G, B;
    };

    static const ColorStop Stops[] = {
        {0.0,    40,  80, 200},
        {0.375,  40, 180, 100},
        {0.625, 220, 200,  40},
        {0.875, 220,  80,  40},
        {1.0,   180,  20,  20}
    };

    int StopCount = 5;
    int LowerIdx = 0;
    for (int I = 0; I < StopCount - 1; ++I) {
        if (T >= Stops[I].Position && T <= Stops[I + 1].Position) {
            LowerIdx = I;
            break;
        }
        if (I == StopCount - 2) {
            LowerIdx = I;
        }
    }

    double SegLen = Stops[LowerIdx + 1].Position - Stops[LowerIdx].Position;
    double LocalT = (SegLen > 0.0) ? (T - Stops[LowerIdx].Position) / SegLen : 0.0;

    int R = static_cast<int>(Stops[LowerIdx].R + (Stops[LowerIdx + 1].R - Stops[LowerIdx].R) * LocalT);
    int G = static_cast<int>(Stops[LowerIdx].G + (Stops[LowerIdx + 1].G - Stops[LowerIdx].G) * LocalT);
    int B = static_cast<int>(Stops[LowerIdx].B + (Stops[LowerIdx + 1].B - Stops[LowerIdx].B) * LocalT);

    return QColor(qBound(0, R, 255), qBound(0, G, 255), qBound(0, B, 255));
}

}
