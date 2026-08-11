#include "HexWidget.h"
#include <fidra/ICore.h>
#include <QPainter>
#include <QPaintEvent>
#include <QScrollBar>
#include <QFontMetrics>
#include <QInputDialog>
#include <QMouseEvent>
#include <QKeyEvent>
#include <cmath>

namespace Fidra {

HexWidget::HexWidget(QWidget* Parent)
    : QAbstractScrollArea(Parent)
    , CorePtr(nullptr)
    , BaseAddress(0)
    , BytesPerLine(16)
    , SelectionStart(-1)
    , SelectionEnd(-1)
    , HasSelection(false)
    , MonoFont("Consolas", 10)
    , EntropyOverlayEnabled(false)
    , EntropyBlockSize(16)
{
    MonoFont.setStyleHint(QFont::Monospace, QFont::PreferDefault);
    MonoFont.setFamilies({"Consolas", "Courier New", "monospace"});
    setFont(MonoFont);
    viewport()->setBackgroundRole(QPalette::Base);
    viewport()->setAutoFillBackground(true);
    setFocusPolicy(Qt::StrongFocus);
    setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
}

HexWidget::~HexWidget() = default;

void HexWidget::SetCore(ICore* Core) {
    CorePtr = Core;
}

void HexWidget::SetData(const QByteArray& Data, Address BaseAddr) {
    HexBuffer = Data;
    BaseAddress = BaseAddr;
    SelectionStart = -1;
    SelectionEnd = -1;
    HasSelection = false;
    RecalculateEntropy();
    UpdateScrollBar();
    viewport()->update();
    emit AddressChanged(BaseAddr);
}

void HexWidget::SetEntropyOverlay(bool Enabled) {
    EntropyOverlayEnabled = Enabled;
    RecalculateEntropy();
    viewport()->update();
}

bool HexWidget::IsEntropyOverlayEnabled() const {
    return EntropyOverlayEnabled;
}

void HexWidget::SetEntropyBlockSize(int Bytes) {
    EntropyBlockSize = qMax(1, Bytes);
    RecalculateEntropy();
    viewport()->update();
}

void HexWidget::RecalculateEntropy() {
    EntropyValues.clear();
    if (!EntropyOverlayEnabled || HexBuffer.isEmpty()) return;

    int BlockCount = (HexBuffer.size() + EntropyBlockSize - 1) / EntropyBlockSize;
    EntropyValues.resize(BlockCount);

    auto* Raw = reinterpret_cast<const uint8_t*>(HexBuffer.constData());
    for (int I = 0; I < BlockCount; ++I) {
        int Offset = I * EntropyBlockSize;
        int Remaining = qMin(EntropyBlockSize, HexBuffer.size() - Offset);
        EntropyValues[I] = CalculateBlockEntropy(Raw + Offset, Remaining);
    }
}

double HexWidget::CalculateBlockEntropy(const uint8_t* Data, int Size) const {
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

QColor HexWidget::EntropyToColor(double Entropy) const {
    double Normalized = Entropy / 8.0;
    if (Normalized > 1.0) Normalized = 1.0;

    if (Normalized < 0.25) {
        int G = static_cast<int>(Normalized / 0.25 * 200);
        return QColor(0, 60 + G, 0, 160);
    } else if (Normalized < 0.5) {
        double T = (Normalized - 0.25) / 0.25;
        return QColor(static_cast<int>(T * 255), 255, 0, 160);
    } else if (Normalized < 0.75) {
        double T = (Normalized - 0.5) / 0.25;
        return QColor(255, static_cast<int>((1.0 - T) * 255), 0, 160);
    } else {
        return QColor(255, 0, static_cast<int>((Normalized - 0.75) / 0.25 * 128), 180);
    }
}

void HexWidget::NavigateTo(Address Addr) {
    if (Addr < BaseAddress) {
        ReadFromProcess(Addr, 4096);
        return;
    }

    Address EndAddr = BaseAddress + static_cast<Address>(HexBuffer.size());
    if (Addr >= EndAddr) {
        ReadFromProcess(Addr, 4096);
        return;
    }

    int Offset = static_cast<int>(Addr - BaseAddress);
    int Line = Offset / BytesPerLine;
    verticalScrollBar()->setValue(Line);
    SelectionStart = Offset;
    SelectionEnd = Offset;
    HasSelection = true;
    viewport()->update();
    emit AddressChanged(Addr);
}

void HexWidget::Refresh() {
    size_t Size = HexBuffer.size() > 0 ? static_cast<size_t>(HexBuffer.size()) : 4096;
    ReadFromProcess(BaseAddress, Size);
}

void HexWidget::OnProcessAttached(const ProcessInfo& Info) {
    ReadFromProcess(Info.BaseAddress, 4096);
}

void HexWidget::OnProcessDetached() {
    HexBuffer.clear();
    BaseAddress = 0;
    SelectionStart = -1;
    SelectionEnd = -1;
    HasSelection = false;
    UpdateScrollBar();
    viewport()->update();
}

void HexWidget::ReadFromProcess(Address Addr, size_t Size) {
    if (!CorePtr || !CorePtr->IsAttached()) {
        return;
    }

    QByteArray Data(static_cast<int>(Size), 0);
    if (CorePtr->ReadMemory(Addr, Data.data(), Size)) {
        SetData(Data, Addr);
    }
}

int HexWidget::GetCharWidth() const {
    QFontMetrics Fm(MonoFont);
    return Fm.horizontalAdvance('0');
}

int HexWidget::GetLineHeight() const {
    QFontMetrics Fm(MonoFont);
    return Fm.height() + 2;
}

int HexWidget::GetAddressWidth() const {
    return 18 * GetCharWidth();
}

int HexWidget::GetEntropyBarWidth() const {
    return EntropyOverlayEnabled ? 14 : 0;
}

int HexWidget::GetHexColumnX() const {
    return GetAddressWidth() + GetEntropyBarWidth();
}

int HexWidget::GetAsciiColumnX() const {
    return GetHexColumnX() + (BytesPerLine * 3 + 1) * GetCharWidth();
}

int HexWidget::PositionToOffset(const QPoint& Pos) const {
    if (HexBuffer.isEmpty()) {
        return -1;
    }

    int LineHeight = GetLineHeight();
    int FirstVisibleLine = verticalScrollBar()->value();
    int ClickedLine = FirstVisibleLine + Pos.y() / LineHeight;
    int CharW = GetCharWidth();

    int HexX = GetHexColumnX();
    int AsciiX = GetAsciiColumnX();

    int ByteIndex = -1;

    if (Pos.x() >= HexX && Pos.x() < AsciiX) {
        int RelX = Pos.x() - HexX;
        int Col = RelX / (CharW * 3);
        if (Col >= 8) {
            int AdjustedRelX = RelX - CharW;
            Col = AdjustedRelX / (CharW * 3);
        }
        if (Col >= 0 && Col < BytesPerLine) {
            ByteIndex = ClickedLine * BytesPerLine + Col;
        }
    } else if (Pos.x() >= AsciiX) {
        int RelX = Pos.x() - AsciiX;
        int Col = RelX / CharW;
        if (Col >= 0 && Col < BytesPerLine) {
            ByteIndex = ClickedLine * BytesPerLine + Col;
        }
    }

    if (ByteIndex < 0 || ByteIndex >= HexBuffer.size()) {
        return -1;
    }

    return ByteIndex;
}

void HexWidget::UpdateScrollBar() {
    int TotalLines = (HexBuffer.size() + BytesPerLine - 1) / BytesPerLine;
    int VisibleLines = viewport()->height() / GetLineHeight();
    verticalScrollBar()->setRange(0, qMax(0, TotalLines - VisibleLines));
    verticalScrollBar()->setPageStep(VisibleLines);
}

void HexWidget::paintEvent(QPaintEvent*) {
    QPainter Painter(viewport());
    Painter.setFont(MonoFont);

    int CharW = GetCharWidth();
    int LineH = GetLineHeight();
    int FirstVisibleLine = verticalScrollBar()->value();
    int VisibleLines = viewport()->height() / LineH + 1;

    QColor AddressColor(86, 156, 214);
    QColor NormalColor(212, 212, 212);
    QColor NonPrintableColor(128, 128, 128);
    QColor SelectionBg(38, 79, 120);
    QColor SeparatorColor(62, 62, 62);

    int HexX = GetHexColumnX();
    int AsciiX = GetAsciiColumnX();

    int EntropyBarW = GetEntropyBarWidth();

    Painter.setPen(SeparatorColor);
    if (EntropyOverlayEnabled) {
        Painter.drawLine(GetAddressWidth() - CharW / 2, 0, GetAddressWidth() - CharW / 2, viewport()->height());
    }
    Painter.drawLine(HexX - CharW / 2, 0, HexX - CharW / 2, viewport()->height());
    Painter.drawLine(AsciiX - CharW / 2, 0, AsciiX - CharW / 2, viewport()->height());

    for (int Line = 0; Line < VisibleLines; ++Line) {
        int DataLine = FirstVisibleLine + Line;
        int DataOffset = DataLine * BytesPerLine;

        if (DataOffset >= HexBuffer.size()) {
            break;
        }

        int Y = Line * LineH + LineH - 3;

        Address LineAddr = BaseAddress + static_cast<Address>(DataOffset);
        QString AddrStr = QString("%1:").arg(LineAddr, 16, 16, QChar('0')).toUpper();
        Painter.setPen(AddressColor);
        Painter.drawText(0, Y, AddrStr);

        if (EntropyOverlayEnabled && EntropyBarW > 0 && !EntropyValues.isEmpty()) {
            int BlockIdx = DataOffset / EntropyBlockSize;
            if (BlockIdx < EntropyValues.size()) {
                double Ent = EntropyValues[BlockIdx];
                QColor BarColor = EntropyToColor(Ent);
                int BarX = GetAddressWidth();
                int BarH = LineH;
                int FillH = static_cast<int>((Ent / 8.0) * BarH);
                Painter.fillRect(BarX, Line * LineH + (BarH - FillH), EntropyBarW - 2, FillH, BarColor);
            }
        }

        int BytesInLine = qMin(BytesPerLine, HexBuffer.size() - DataOffset);

        for (int Col = 0; Col < BytesInLine; ++Col) {
            int ByteIdx = DataOffset + Col;
            uint8_t Byte = static_cast<uint8_t>(HexBuffer.at(ByteIdx));

            int ExtraGap = (Col >= 8) ? CharW : 0;
            int ByteX = HexX + Col * 3 * CharW + ExtraGap;

            bool IsSelected = HasSelection && ByteIdx >= qMin(SelectionStart, SelectionEnd)
                              && ByteIdx <= qMax(SelectionStart, SelectionEnd);

            if (IsSelected) {
                Painter.fillRect(ByteX - 1, Line * LineH, CharW * 2 + 2, LineH, SelectionBg);
            }

            QString HexStr = QString("%1").arg(Byte, 2, 16, QChar('0')).toUpper();
            Painter.setPen(IsSelected ? AddressColor : NormalColor);
            Painter.drawText(ByteX, Y, HexStr);

            int AsciiByteX = AsciiX + Col * CharW;

            if (IsSelected) {
                Painter.fillRect(AsciiByteX - 1, Line * LineH, CharW + 1, LineH, SelectionBg);
            }

            QChar Ch = (Byte >= 0x20 && Byte <= 0x7E) ? QChar(Byte) : QChar('.');
            Painter.setPen((Byte >= 0x20 && Byte <= 0x7E) ? NormalColor : NonPrintableColor);
            if (IsSelected) {
                Painter.setPen(AddressColor);
            }
            Painter.drawText(AsciiByteX, Y, QString(Ch));
        }
    }
}

void HexWidget::resizeEvent(QResizeEvent* Event) {
    QAbstractScrollArea::resizeEvent(Event);
    UpdateScrollBar();
}

void HexWidget::mousePressEvent(QMouseEvent* Event) {
    if (Event->button() == Qt::LeftButton) {
        int Offset = PositionToOffset(Event->pos());
        if (Offset >= 0) {
            SelectionStart = Offset;
            SelectionEnd = Offset;
            HasSelection = true;
            viewport()->update();
        }
    }
    QAbstractScrollArea::mousePressEvent(Event);
}

void HexWidget::keyPressEvent(QKeyEvent* Event) {
    if (Event->modifiers() & Qt::ControlModifier && Event->key() == Qt::Key_G) {
        bool Ok = false;
        QString Input = QInputDialog::getText(this, "Go to Address", "Address (hex):",
                                               QLineEdit::Normal, "", &Ok);
        if (Ok && !Input.isEmpty()) {
            Address Addr = Input.toULongLong(&Ok, 16);
            if (Ok) {
                NavigateTo(Addr);
            }
        }
        return;
    }

    if (!HasSelection || HexBuffer.isEmpty()) {
        QAbstractScrollArea::keyPressEvent(Event);
        return;
    }

    int Current = SelectionEnd;

    switch (Event->key()) {
    case Qt::Key_Right:
        if (Current + 1 < HexBuffer.size()) {
            SelectionStart = Current + 1;
            SelectionEnd = Current + 1;
        }
        break;
    case Qt::Key_Left:
        if (Current - 1 >= 0) {
            SelectionStart = Current - 1;
            SelectionEnd = Current - 1;
        }
        break;
    case Qt::Key_Down:
        if (Current + BytesPerLine < HexBuffer.size()) {
            SelectionStart = Current + BytesPerLine;
            SelectionEnd = Current + BytesPerLine;
        }
        break;
    case Qt::Key_Up:
        if (Current - BytesPerLine >= 0) {
            SelectionStart = Current - BytesPerLine;
            SelectionEnd = Current - BytesPerLine;
        }
        break;
    default:
        QAbstractScrollArea::keyPressEvent(Event);
        return;
    }

    int Line = SelectionEnd / BytesPerLine;
    int FirstVisible = verticalScrollBar()->value();
    int VisibleLines = viewport()->height() / GetLineHeight();
    if (Line < FirstVisible) {
        verticalScrollBar()->setValue(Line);
    } else if (Line >= FirstVisible + VisibleLines) {
        verticalScrollBar()->setValue(Line - VisibleLines + 1);
    }

    viewport()->update();
}

}
