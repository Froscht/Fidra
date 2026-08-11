#include "StackWidget.h"
#include <QHeaderView>
#include <QFont>

namespace Fidra {

StackWidget::StackWidget(QWidget* Parent)
    : QWidget(Parent)
    , EngineRef(nullptr)
    , Layout(new QVBoxLayout(this))
    , Splitter(new QSplitter(Qt::Vertical, this))
    , CallStackContainer(new QWidget(this))
    , CallStackLayout(new QVBoxLayout(CallStackContainer))
    , CallStackLabel(new QLabel("Call Stack", CallStackContainer))
    , CallStackTable(new QTableWidget(CallStackContainer))
    , RawStackContainer(new QWidget(this))
    , RawStackLayout(new QVBoxLayout(RawStackContainer))
    , RawStackLabel(new QLabel("Stack Memory", RawStackContainer))
    , RawStackTable(new QTableWidget(RawStackContainer))
{
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(0);

    QFont MonoFont("Consolas", 9);
    MonoFont.setStyleHint(QFont::Monospace);

    CallStackLayout->setContentsMargins(0, 0, 0, 0);
    CallStackLayout->setSpacing(2);
    QFont BoldFont = CallStackLabel->font();
    BoldFont.setBold(true);
    CallStackLabel->setFont(BoldFont);
    CallStackLayout->addWidget(CallStackLabel);

    SetupCallStackTable();
    CallStackTable->setFont(MonoFont);
    CallStackLayout->addWidget(CallStackTable);

    RawStackLayout->setContentsMargins(0, 0, 0, 0);
    RawStackLayout->setSpacing(2);
    RawStackLabel->setFont(BoldFont);
    RawStackLayout->addWidget(RawStackLabel);

    SetupRawStackTable();
    RawStackTable->setFont(MonoFont);
    RawStackLayout->addWidget(RawStackTable);

    Splitter->addWidget(CallStackContainer);
    Splitter->addWidget(RawStackContainer);
    Splitter->setStretchFactor(0, 1);
    Splitter->setStretchFactor(1, 2);

    Layout->addWidget(Splitter);
}

void StackWidget::SetEngine(DebugEngine* Engine) {
    if (EngineRef) {
        disconnect(EngineRef, nullptr, this, nullptr);
    }

    EngineRef = Engine;

    if (EngineRef) {
        connect(EngineRef, &DebugEngine::RegistersChanged, this, &StackWidget::UpdateStack);
        connect(EngineRef, &DebugEngine::StateChanged, this, &StackWidget::OnStateChanged);
    }
}

void StackWidget::SetupCallStackTable() {
    CallStackTable->setColumnCount(5);
    CallStackTable->setHorizontalHeaderLabels({"#", "Return Address", "Frame Pointer", "Module", "Function"});
    CallStackTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    CallStackTable->setSelectionMode(QAbstractItemView::SingleSelection);
    CallStackTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    CallStackTable->verticalHeader()->hide();
    CallStackTable->setAlternatingRowColors(true);
    CallStackTable->horizontalHeader()->setStretchLastSection(true);
    CallStackTable->horizontalHeader()->resizeSection(0, 30);
    CallStackTable->horizontalHeader()->resizeSection(1, 150);
    CallStackTable->horizontalHeader()->resizeSection(2, 150);
    CallStackTable->horizontalHeader()->resizeSection(3, 120);
}

void StackWidget::SetupRawStackTable() {
    RawStackTable->setColumnCount(3);
    RawStackTable->setHorizontalHeaderLabels({"Address", "Value", "ASCII"});
    RawStackTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    RawStackTable->setSelectionMode(QAbstractItemView::SingleSelection);
    RawStackTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    RawStackTable->verticalHeader()->hide();
    RawStackTable->setAlternatingRowColors(true);
    RawStackTable->horizontalHeader()->setStretchLastSection(true);
    RawStackTable->horizontalHeader()->resizeSection(0, 150);
    RawStackTable->horizontalHeader()->resizeSection(1, 180);
}

void StackWidget::UpdateStack() {
    if (!EngineRef) return;
    if (EngineRef->CurrentState() != DebugState::Paused) return;

    UpdateCallStack();
    UpdateRawStack();
}

void StackWidget::UpdateCallStack() {
    if (!EngineRef) return;

    QList<StackFrame> Frames = EngineRef->GetCallStack();

    CallStackTable->setRowCount(Frames.size());

    for (int I = 0; I < Frames.size(); ++I) {
        const auto& Frame = Frames[I];

        auto* IndexItem = new QTableWidgetItem(QString::number(I));
        IndexItem->setTextAlignment(Qt::AlignCenter);
        CallStackTable->setItem(I, 0, IndexItem);

        auto* RetAddrItem = new QTableWidgetItem(
            QString("0x%1").arg(Frame.ReturnAddress, 16, 16, QChar('0')).toUpper());
        CallStackTable->setItem(I, 1, RetAddrItem);

        auto* FramePtrItem = new QTableWidgetItem(
            QString("0x%1").arg(Frame.FramePointer, 16, 16, QChar('0')).toUpper());
        CallStackTable->setItem(I, 2, FramePtrItem);

        CallStackTable->setItem(I, 3, new QTableWidgetItem(Frame.ModuleName));
        CallStackTable->setItem(I, 4, new QTableWidgetItem(Frame.FunctionName));
    }
}

void StackWidget::UpdateRawStack() {
    if (!EngineRef) return;

    RegisterSet Regs = EngineRef->GetRegisters();
    Address Rsp = Regs.Rsp;

    uint8_t Buffer[RawStackBytes] = {};
    bool ReadOk = EngineRef->ReadDebugMemory(Rsp, Buffer, RawStackBytes);

    int RowCount = RawStackBytes / 8;
    RawStackTable->setRowCount(RowCount);

    for (int I = 0; I < RowCount; ++I) {
        Address Addr = Rsp + static_cast<Address>(I * 8);

        auto* AddrItem = new QTableWidgetItem(
            QString("0x%1").arg(Addr, 16, 16, QChar('0')).toUpper());
        RawStackTable->setItem(I, 0, AddrItem);

        if (ReadOk) {
            uint64_t Value = 0;
            memcpy(&Value, Buffer + (I * 8), 8);

            auto* ValItem = new QTableWidgetItem(
                QString("0x%1").arg(Value, 16, 16, QChar('0')).toUpper());
            RawStackTable->setItem(I, 1, ValItem);

            QString Ascii;
            for (int J = 0; J < 8; ++J) {
                uint8_t Byte = Buffer[I * 8 + J];
                if (Byte >= 0x20 && Byte <= 0x7E) {
                    Ascii += QChar(Byte);
                } else {
                    Ascii += '.';
                }
            }
            RawStackTable->setItem(I, 2, new QTableWidgetItem(Ascii));
        } else {
            RawStackTable->setItem(I, 1, new QTableWidgetItem("????????"));
            RawStackTable->setItem(I, 2, new QTableWidgetItem(""));
        }

        if (Addr == Rsp) {
            for (int Col = 0; Col < 3; ++Col) {
                if (auto* Item = RawStackTable->item(I, Col)) {
                    Item->setBackground(QBrush(QColor(60, 60, 120)));
                }
            }
        }
    }
}

void StackWidget::OnStateChanged(DebugState NewState) {
    if (NewState == DebugState::Paused) {
        UpdateStack();
    } else if (NewState == DebugState::Idle || NewState == DebugState::Stopped) {
        ClearAll();
    }
}

void StackWidget::ClearAll() {
    CallStackTable->setRowCount(0);
    RawStackTable->setRowCount(0);
}

}
