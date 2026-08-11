#include "MemoryMapWidget.h"
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <QPainter>
#include <QPaintEvent>
#include <QMouseEvent>
#include <QWheelEvent>
#include <QFontMetrics>
#include <QToolTip>
#include <QtMath>
#include <cmath>
#include <array>
#include <algorithm>

namespace Fidra {

MemoryMapWidget::MemoryMapWidget(QWidget* Parent)
    : QWidget(Parent)
    , EntryPointAddr(0)
    , ImageBaseAddr(0)
    , HoveredSegment(-1)
    , ZoomLevel(1.0)
    , PanOffset(0.0)
    , IsDragging(false)
    , LabelFont("Consolas", 8)
    , HeaderFont("Consolas", 10, QFont::Bold)
{
    LabelFont.setStyleHint(QFont::Monospace);
    HeaderFont.setStyleHint(QFont::Monospace);
    setMouseTracking(true);
    setMinimumSize(400, 300);
}

MemoryMapWidget::~MemoryMapWidget() = default;

void MemoryMapWidget::LoadFromDatabase(AnalysisDatabase* Db) {
    Clear();
    if (!Db) return;

    BinaryInfo Info = Db->GetBinaryInfo();
    EntryPointAddr = Info.EntryPoint;
    ImageBaseAddr = Info.ImageBase;

    for (const auto& Seg : Info.Segments) {
        SegmentVisual Vis;
        Vis.Name = Seg.Name;
        Vis.StartAddr = Seg.VirtualAddress;
        Vis.EndAddr = Seg.VirtualAddress + Seg.VirtualSize;
        Vis.Size = Seg.VirtualSize;
        Vis.Type = Seg.Type;
        Vis.IsReadable = Seg.IsReadable;
        Vis.IsWritable = Seg.IsWritable;
        Vis.IsExecutable = Seg.IsExecutable;
        Vis.Color = SegmentColor(Seg.Type);
        Vis.Entropy = CalculateEntropy(Seg.Data);
        Segments.append(Vis);
    }

    auto AllFunctions = Db->GetAllFunctions();
    FunctionAddresses.reserve(AllFunctions.size());
    for (const auto& Func : AllFunctions) {
        FunctionAddresses.append(Func.Start);
    }

    auto AllStrings = Db->GetAllStrings();
    StringAddresses.reserve(AllStrings.size());
    for (const auto& Str : AllStrings) {
        StringAddresses.append(Str.Addr);
    }

    ImportAddresses.reserve(Info.Imports.size());
    for (const auto& Imp : Info.Imports) {
        ImportAddresses.append(Imp.IatAddress);
    }

    ExportAddresses.reserve(Info.Exports.size());
    for (const auto& Exp : Info.Exports) {
        ExportAddresses.append(Exp.Addr);
    }

    RecalculateLayout();
    update();
}

void MemoryMapWidget::Clear() {
    Segments.clear();
    FunctionAddresses.clear();
    StringAddresses.clear();
    ImportAddresses.clear();
    ExportAddresses.clear();
    EntryPointAddr = 0;
    ImageBaseAddr = 0;
    HoveredSegment = -1;
    ZoomLevel = 1.0;
    PanOffset = 0.0;
    IsDragging = false;
    update();
}

void MemoryMapWidget::RecalculateLayout() {
    if (Segments.isEmpty()) return;

    double AvailableHeight = static_cast<double>(height() - TopMargin - BottomMargin) * ZoomLevel;
    if (AvailableHeight < 1.0) AvailableHeight = 1.0;

    double TotalLogSum = 0.0;
    for (const auto& Seg : Segments) {
        TotalLogSum += std::log2(static_cast<double>(Seg.Size) + 1.0);
    }

    if (TotalLogSum <= 0.0) TotalLogSum = 1.0;

    double CurrentY = static_cast<double>(TopMargin);

    for (auto& Seg : Segments) {
        double Proportion = std::log2(static_cast<double>(Seg.Size) + 1.0) / TotalLogSum;
        double BlockHeight = Proportion * AvailableHeight;
        if (BlockHeight < 20.0) BlockHeight = 20.0;

        Seg.Rect = QRectF(MapBarX, CurrentY - PanOffset, MapBarWidth, BlockHeight);
        CurrentY += BlockHeight + 2.0;
    }
}

QColor MemoryMapWidget::SegmentColor(SegmentType Type) const {
    switch (Type) {
        case SegmentType::Code:     return QColor(0x44, 0x88, 0xCC);
        case SegmentType::Data:     return QColor(0x44, 0xCC, 0x88);
        case SegmentType::Bss:      return QColor(0x66, 0x66, 0x66);
        case SegmentType::Import:   return QColor(0xCC, 0x88, 0x44);
        case SegmentType::Export:   return QColor(0x88, 0xCC, 0x44);
        case SegmentType::Resource: return QColor(0x88, 0x44, 0xCC);
        case SegmentType::Reloc:    return QColor(0xAA, 0xAA, 0x44);
        case SegmentType::Unknown:  return QColor(0x88, 0x88, 0x88);
    }
    return QColor(0x88, 0x88, 0x88);
}

QString MemoryMapWidget::FormatSize(size_t Size) const {
    if (Size < 1024) {
        return QString("%1 B").arg(Size);
    } else if (Size < 1024 * 1024) {
        return QString("%1 KB").arg(static_cast<double>(Size) / 1024.0, 0, 'f', 1);
    } else {
        return QString("%1 MB").arg(static_cast<double>(Size) / (1024.0 * 1024.0), 0, 'f', 1);
    }
}

QString MemoryMapWidget::FormatAddress(Address Addr) const {
    return QString("0x") + QString("%1").arg(Addr, 16, 16, QChar('0')).toUpper();
}

QString MemoryMapWidget::PermissionsString(bool R, bool W, bool X) const {
    QString Result;
    Result += R ? 'R' : '-';
    Result += W ? 'W' : '-';
    Result += X ? 'X' : '-';
    return Result;
}

double MemoryMapWidget::CalculateEntropy(const QByteArray& Data) const {
    if (Data.isEmpty()) return 0.0;

    std::array<uint64_t, 256> Freq{};
    for (unsigned char Byte : Data) {
        Freq[Byte]++;
    }

    double Entropy = 0.0;
    double Length = static_cast<double>(Data.size());

    for (int I = 0; I < 256; ++I) {
        if (Freq[I] == 0) continue;
        double P = static_cast<double>(Freq[I]) / Length;
        Entropy -= P * std::log2(P);
    }

    return Entropy;
}

int MemoryMapWidget::SegmentAtPos(const QPoint& Pos) const {
    for (int I = 0; I < Segments.size(); ++I) {
        if (Segments[I].Rect.contains(Pos)) {
            return I;
        }
    }
    return -1;
}

void MemoryMapWidget::paintEvent(QPaintEvent*) {
    QPainter Painter(this);
    Painter.setRenderHint(QPainter::Antialiasing, true);
    Painter.fillRect(rect(), QColor(30, 30, 30));

    if (Segments.isEmpty()) {
        Painter.setPen(QColor(128, 128, 128));
        Painter.setFont(HeaderFont);
        Painter.drawText(rect(), Qt::AlignCenter, "No memory map data");
        return;
    }

    Painter.setFont(HeaderFont);
    Painter.setPen(QColor(220, 220, 220));

    Address LowestAddr = Segments.first().StartAddr;
    Address HighestAddr = Segments.first().EndAddr;
    for (const auto& Seg : Segments) {
        if (Seg.StartAddr < LowestAddr) LowestAddr = Seg.StartAddr;
        if (Seg.EndAddr > HighestAddr) HighestAddr = Seg.EndAddr;
    }

    QString HeaderText = QString("Memory Map | %1 segments | %2 - %3")
        .arg(Segments.size())
        .arg(FormatAddress(LowestAddr))
        .arg(FormatAddress(HighestAddr));
    Painter.drawText(10, 20, HeaderText);

    Painter.setFont(LabelFont);
    QFontMetrics Fm(LabelFont);

    for (int I = 0; I < Segments.size(); ++I) {
        const auto& Seg = Segments[I];

        if (Seg.Rect.bottom() < 0 || Seg.Rect.top() > height()) continue;

        QColor FillColor = Seg.Color;
        if (I == HoveredSegment) {
            FillColor = FillColor.lighter(130);
        }

        Painter.setBrush(FillColor);
        Painter.setPen(QPen(FillColor.darker(150), 1));
        Painter.drawRoundedRect(Seg.Rect, 3, 3);

        Painter.setPen(QColor(255, 255, 255));
        if (Seg.Rect.height() >= 16.0) {
            Painter.drawText(Seg.Rect, Qt::AlignCenter, Seg.Name);
        }

        Painter.setPen(QColor(180, 180, 180));
        QString AddrLabel = QString("0x%1").arg(Seg.StartAddr, 0, 16).toUpper();
        int AddrWidth = Fm.horizontalAdvance(AddrLabel);
        Painter.drawText(static_cast<int>(Seg.Rect.left()) - AddrWidth - 4,
                         static_cast<int>(Seg.Rect.top()) + Fm.ascent(), AddrLabel);

        if (Seg.Rect.height() >= 30.0) {
            QString SizeLabel = FormatSize(Seg.Size);
            Painter.setPen(QColor(160, 160, 160));
            Painter.drawText(Seg.Rect.adjusted(4, 0, -4, 0),
                             Qt::AlignBottom | Qt::AlignHCenter, SizeLabel);
        }
    }

    int DetailY = TopMargin;
    Painter.setFont(LabelFont);
    for (int I = 0; I < Segments.size(); ++I) {
        const auto& Seg = Segments[I];
        int RowY = DetailY + I * 18;

        if (RowY < 0 || RowY > height()) continue;

        Painter.fillRect(DetailPanelX, RowY, 12, 12, Seg.Color);
        Painter.setPen(QPen(Seg.Color.darker(150), 1));
        Painter.drawRect(DetailPanelX, RowY, 12, 12);

        Painter.setPen(QColor(220, 220, 220));
        QString DetailText = QString("%1  %2 - %3  %4  [%5]")
            .arg(Seg.Name, -12)
            .arg(FormatAddress(Seg.StartAddr))
            .arg(FormatAddress(Seg.EndAddr))
            .arg(FormatSize(Seg.Size))
            .arg(PermissionsString(Seg.IsReadable, Seg.IsWritable, Seg.IsExecutable));
        Painter.drawText(DetailPanelX + 16, RowY + Fm.ascent(), DetailText);
    }

    for (const auto& FuncAddr : FunctionAddresses) {
        for (const auto& Seg : Segments) {
            if (FuncAddr >= Seg.StartAddr && FuncAddr < Seg.EndAddr && Seg.Size > 0) {
                double Fraction = static_cast<double>(FuncAddr - Seg.StartAddr) / static_cast<double>(Seg.Size);
                double DotY = Seg.Rect.top() + Fraction * Seg.Rect.height();
                if (DotY >= 0 && DotY <= height()) {
                    Painter.setPen(Qt::NoPen);
                    Painter.setBrush(QColor(0, 220, 255, 180));
                    Painter.drawEllipse(QPointF(Seg.Rect.right() - 6, DotY), 2, 2);
                }
                break;
            }
        }
    }

    for (const auto& StrAddr : StringAddresses) {
        for (const auto& Seg : Segments) {
            if (StrAddr >= Seg.StartAddr && StrAddr < Seg.EndAddr && Seg.Size > 0) {
                double Fraction = static_cast<double>(StrAddr - Seg.StartAddr) / static_cast<double>(Seg.Size);
                double DotY = Seg.Rect.top() + Fraction * Seg.Rect.height();
                if (DotY >= 0 && DotY <= height()) {
                    Painter.setPen(Qt::NoPen);
                    Painter.setBrush(QColor(80, 220, 80, 180));
                    Painter.drawEllipse(QPointF(Seg.Rect.right() - 12, DotY), 2, 2);
                }
                break;
            }
        }
    }

    if (EntryPointAddr != 0) {
        for (const auto& Seg : Segments) {
            if (EntryPointAddr >= Seg.StartAddr && EntryPointAddr < Seg.EndAddr && Seg.Size > 0) {
                double Fraction = static_cast<double>(EntryPointAddr - Seg.StartAddr) / static_cast<double>(Seg.Size);
                double ArrowY = Seg.Rect.top() + Fraction * Seg.Rect.height();
                double ArrowX = Seg.Rect.right() + 4;

                QPolygonF Arrow;
                Arrow << QPointF(ArrowX, ArrowY)
                      << QPointF(ArrowX + 10, ArrowY - 5)
                      << QPointF(ArrowX + 10, ArrowY + 5);

                Painter.setPen(Qt::NoPen);
                Painter.setBrush(QColor(220, 40, 40));
                Painter.drawPolygon(Arrow);

                Painter.setPen(QColor(220, 40, 40));
                Painter.drawText(static_cast<int>(ArrowX) + 14,
                                 static_cast<int>(ArrowY) + Fm.ascent() / 2, "EP");
                break;
            }
        }
    }

    for (const auto& ImpAddr : ImportAddresses) {
        for (const auto& Seg : Segments) {
            if (ImpAddr >= Seg.StartAddr && ImpAddr < Seg.EndAddr && Seg.Size > 0) {
                double Fraction = static_cast<double>(ImpAddr - Seg.StartAddr) / static_cast<double>(Seg.Size);
                double TickY = Seg.Rect.top() + Fraction * Seg.Rect.height();
                if (TickY >= 0 && TickY <= height()) {
                    Painter.setPen(QPen(QColor(0xCC, 0x88, 0x44), 1));
                    Painter.drawLine(QPointF(Seg.Rect.left(), TickY),
                                     QPointF(Seg.Rect.left() + 4, TickY));
                }
                break;
            }
        }
    }

    for (const auto& ExpAddr : ExportAddresses) {
        for (const auto& Seg : Segments) {
            if (ExpAddr >= Seg.StartAddr && ExpAddr < Seg.EndAddr && Seg.Size > 0) {
                double Fraction = static_cast<double>(ExpAddr - Seg.StartAddr) / static_cast<double>(Seg.Size);
                double TickY = Seg.Rect.top() + Fraction * Seg.Rect.height();
                if (TickY >= 0 && TickY <= height()) {
                    Painter.setPen(QPen(QColor(0x88, 0xCC, 0x44), 1));
                    Painter.drawLine(QPointF(Seg.Rect.right() - 4, TickY),
                                     QPointF(Seg.Rect.right(), TickY));
                }
                break;
            }
        }
    }
}

void MemoryMapWidget::mousePressEvent(QMouseEvent* Event) {
    if (Event->button() == Qt::LeftButton) {
        int Idx = SegmentAtPos(Event->pos());
        if (Idx >= 0 && Idx < Segments.size()) {
            emit NavigateToAddress(Segments[Idx].StartAddr);
            emit SegmentSelected(Segments[Idx].Name);
        } else {
            IsDragging = true;
            LastMousePos = Event->pos();
        }
    } else if (Event->button() == Qt::MiddleButton) {
        IsDragging = true;
        LastMousePos = Event->pos();
    }
    QWidget::mousePressEvent(Event);
}

void MemoryMapWidget::mouseMoveEvent(QMouseEvent* Event) {
    if (IsDragging) {
        int DeltaY = Event->pos().y() - LastMousePos.y();
        PanOffset -= static_cast<double>(DeltaY);
        LastMousePos = Event->pos();
        RecalculateLayout();
        update();
    } else {
        int Idx = SegmentAtPos(Event->pos());
        if (Idx != HoveredSegment) {
            HoveredSegment = Idx;
            if (Idx >= 0 && Idx < Segments.size()) {
                const auto& Seg = Segments[Idx];
                QString TipText = QString("%1\n%2 - %3\nSize: %4\nPermissions: %5\nEntropy: %6")
                    .arg(Seg.Name)
                    .arg(FormatAddress(Seg.StartAddr))
                    .arg(FormatAddress(Seg.EndAddr))
                    .arg(FormatSize(Seg.Size))
                    .arg(PermissionsString(Seg.IsReadable, Seg.IsWritable, Seg.IsExecutable))
                    .arg(Seg.Entropy, 0, 'f', 3);
                QToolTip::showText(Event->globalPosition().toPoint(), TipText, this);
            } else {
                QToolTip::hideText();
            }
            update();
        }
    }
    QWidget::mouseMoveEvent(Event);
}

void MemoryMapWidget::mouseReleaseEvent(QMouseEvent* Event) {
    if (Event->button() == Qt::LeftButton || Event->button() == Qt::MiddleButton) {
        IsDragging = false;
    }
    QWidget::mouseReleaseEvent(Event);
}

void MemoryMapWidget::wheelEvent(QWheelEvent* Event) {
    double Delta = Event->angleDelta().y();
    if (Delta > 0) {
        ZoomLevel *= 1.15;
    } else if (Delta < 0) {
        ZoomLevel /= 1.15;
    }

    ZoomLevel = std::clamp(ZoomLevel, 0.5, 10.0);

    RecalculateLayout();
    update();
    Event->accept();
}

void MemoryMapWidget::resizeEvent(QResizeEvent* Event) {
    QWidget::resizeEvent(Event);
    RecalculateLayout();
}

}
