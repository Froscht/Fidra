#include "DebuggerWidget.h"
#include <QHeaderView>
#include <QStyle>
#include <QFont>

namespace Fidra {

DebuggerWidget::DebuggerWidget(QWidget* Parent)
    : QWidget(Parent)
    , EngineRef(nullptr)
    , CoreRef(nullptr)
    , MainLayout(new QVBoxLayout(this))
    , ToolBar(nullptr)
    , CentralSplitter(nullptr)
    , DisasmTable(nullptr)
    , MemoryTable(nullptr)
    , StateLabel(nullptr)
    , RunAction(nullptr)
    , PauseAction(nullptr)
    , StepIntoAction(nullptr)
    , StepOverAction(nullptr)
    , StepOutAction(nullptr)
    , StopAction(nullptr)
    , CurrentAddress(0)
{
    MainLayout->setContentsMargins(0, 0, 0, 0);
    MainLayout->setSpacing(0);

    SetupToolBar();

    CentralSplitter = new QSplitter(Qt::Vertical, this);

    SetupDisassemblyView();
    SetupMemoryDumpView();

    MainLayout->addWidget(CentralSplitter);

    UpdateToolBarState(DebugState::Idle);
}

void DebuggerWidget::SetEngine(DebugEngine* Engine) {
    if (EngineRef) {
        disconnect(EngineRef, nullptr, this, nullptr);
    }
    EngineRef = Engine;
    if (EngineRef) {
        connect(EngineRef, &DebugEngine::StateChanged, this, &DebuggerWidget::OnStateChanged);
        connect(EngineRef, &DebugEngine::BreakpointHit, this, &DebuggerWidget::OnBreakpointHit);
        connect(EngineRef, &DebugEngine::SingleStepCompleted, this, &DebuggerWidget::OnSingleStepCompleted);
    }
}

void DebuggerWidget::SetCore(ICore* Core) {
    CoreRef = Core;
}

void DebuggerWidget::SetupToolBar() {
    ToolBar = new QToolBar(this);
    ToolBar->setIconSize(QSize(20, 20));
    ToolBar->setMovable(false);

    RunAction = ToolBar->addAction(style()->standardIcon(QStyle::SP_MediaPlay), "Run");
    connect(RunAction, &QAction::triggered, this, [this]() {
        if (EngineRef) EngineRef->Continue();
    });

    PauseAction = ToolBar->addAction(style()->standardIcon(QStyle::SP_MediaPause), "Pause");
    connect(PauseAction, &QAction::triggered, this, [this]() {
        if (EngineRef) EngineRef->Pause();
    });

    ToolBar->addSeparator();

    StepIntoAction = ToolBar->addAction(style()->standardIcon(QStyle::SP_ArrowDown), "Step Into");
    StepIntoAction->setShortcut(QKeySequence(Qt::Key_F11));
    connect(StepIntoAction, &QAction::triggered, this, [this]() {
        if (EngineRef) EngineRef->StepInto();
    });

    StepOverAction = ToolBar->addAction(style()->standardIcon(QStyle::SP_ArrowRight), "Step Over");
    StepOverAction->setShortcut(QKeySequence(Qt::Key_F10));
    connect(StepOverAction, &QAction::triggered, this, [this]() {
        if (EngineRef) EngineRef->StepOver();
    });

    StepOutAction = ToolBar->addAction(style()->standardIcon(QStyle::SP_ArrowUp), "Step Out");
    StepOutAction->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F11));
    connect(StepOutAction, &QAction::triggered, this, [this]() {
        if (EngineRef) EngineRef->StepOut();
    });

    ToolBar->addSeparator();

    StopAction = ToolBar->addAction(style()->standardIcon(QStyle::SP_MediaStop), "Stop");
    connect(StopAction, &QAction::triggered, this, [this]() {
        if (EngineRef) EngineRef->Stop();
    });

    ToolBar->addSeparator();

    StateLabel = new QLabel("Idle", this);
    StateLabel->setMinimumWidth(100);
    QFont LabelFont = StateLabel->font();
    LabelFont.setBold(true);
    StateLabel->setFont(LabelFont);
    ToolBar->addWidget(StateLabel);

    MainLayout->addWidget(ToolBar);
}

void DebuggerWidget::SetupDisassemblyView() {
    DisasmTable = new QTableWidget(this);
    DisasmTable->setColumnCount(4);
    DisasmTable->setHorizontalHeaderLabels({"Address", "Bytes", "Mnemonic", "Operands"});
    DisasmTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Interactive);
    DisasmTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Interactive);
    DisasmTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Interactive);
    DisasmTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    DisasmTable->setColumnWidth(0, 160);
    DisasmTable->setColumnWidth(1, 200);
    DisasmTable->setColumnWidth(2, 120);
    DisasmTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    DisasmTable->setSelectionMode(QAbstractItemView::SingleSelection);
    DisasmTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    DisasmTable->verticalHeader()->hide();
    DisasmTable->setAlternatingRowColors(true);

    QFont MonoFont("Consolas", 10);
    MonoFont.setStyleHint(QFont::Monospace);
    DisasmTable->setFont(MonoFont);

    CentralSplitter->addWidget(DisasmTable);
}

void DebuggerWidget::SetupMemoryDumpView() {
    MemoryTable = new QTableWidget(this);
    MemoryTable->setColumnCount(18);

    QStringList Headers;
    Headers << "Address";
    for (int I = 0; I < 16; ++I) {
        Headers << QString("%1").arg(I, 2, 16, QChar('0')).toUpper();
    }
    Headers << "ASCII";
    MemoryTable->setHorizontalHeaderLabels(Headers);

    MemoryTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Interactive);
    for (int I = 1; I <= 16; ++I) {
        MemoryTable->horizontalHeader()->setSectionResizeMode(I, QHeaderView::ResizeToContents);
    }
    MemoryTable->horizontalHeader()->setSectionResizeMode(17, QHeaderView::Stretch);
    MemoryTable->setColumnWidth(0, 160);

    MemoryTable->setSelectionBehavior(QAbstractItemView::SelectItems);
    MemoryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    MemoryTable->verticalHeader()->hide();
    MemoryTable->setAlternatingRowColors(true);

    QFont MonoFont("Consolas", 10);
    MonoFont.setStyleHint(QFont::Monospace);
    MemoryTable->setFont(MonoFont);

    CentralSplitter->addWidget(MemoryTable);
}

void DebuggerWidget::UpdateToolBarState(DebugState State) {
    switch (State) {
    case DebugState::Idle:
        StateLabel->setText("Idle");
        StateLabel->setStyleSheet("color: gray;");
        RunAction->setEnabled(false);
        PauseAction->setEnabled(false);
        StepIntoAction->setEnabled(false);
        StepOverAction->setEnabled(false);
        StepOutAction->setEnabled(false);
        StopAction->setEnabled(false);
        break;
    case DebugState::Running:
        StateLabel->setText("Running");
        StateLabel->setStyleSheet("color: #2ecc71;");
        RunAction->setEnabled(false);
        PauseAction->setEnabled(true);
        StepIntoAction->setEnabled(false);
        StepOverAction->setEnabled(false);
        StepOutAction->setEnabled(false);
        StopAction->setEnabled(true);
        break;
    case DebugState::Paused:
        StateLabel->setText("Paused");
        StateLabel->setStyleSheet("color: #f39c12;");
        RunAction->setEnabled(true);
        PauseAction->setEnabled(false);
        StepIntoAction->setEnabled(true);
        StepOverAction->setEnabled(true);
        StepOutAction->setEnabled(true);
        StopAction->setEnabled(true);
        break;
    case DebugState::Stopped:
        StateLabel->setText("Stopped");
        StateLabel->setStyleSheet("color: #e74c3c;");
        RunAction->setEnabled(false);
        PauseAction->setEnabled(false);
        StepIntoAction->setEnabled(false);
        StepOverAction->setEnabled(false);
        StepOutAction->setEnabled(false);
        StopAction->setEnabled(false);
        break;
    }
}

void DebuggerWidget::OnStateChanged(DebugState NewState) {
    UpdateToolBarState(NewState);

    if (NewState == DebugState::Paused) {
        RefreshViewsAtRip();
    }

    if (NewState == DebugState::Stopped || NewState == DebugState::Idle) {
        DisasmTable->setRowCount(0);
        MemoryTable->setRowCount(0);
    }
}

void DebuggerWidget::OnBreakpointHit(Address Addr) {
    CurrentAddress = Addr;
    RefreshViewsAtRip();
}

void DebuggerWidget::OnSingleStepCompleted() {
    RefreshViewsAtRip();
}

void DebuggerWidget::RefreshViewsAtRip() {
    if (!EngineRef) return;

    RegisterSet Regs = EngineRef->GetRegisters();
    CurrentAddress = Regs.Rip;

    Address DisasmStart = (CurrentAddress >= 0x40) ? CurrentAddress - 0x40 : 0;
    UpdateDisassembly(DisasmStart);

    Address MemStart = CurrentAddress & ~0xFULL;
    UpdateMemoryDump(MemStart);
}

void DebuggerWidget::UpdateDisassembly(Address Addr) {
    if (!EngineRef) return;

    constexpr size_t ReadSize = 256;
    uint8_t Buffer[ReadSize] = {};

    bool Ok = EngineRef->ReadDebugMemory(Addr, Buffer, ReadSize);
    if (!Ok) {
        DisasmTable->setRowCount(1);
        DisasmTable->setItem(0, 0, new QTableWidgetItem(QString("0x%1").arg(Addr, 16, 16, QChar('0'))));
        DisasmTable->setItem(0, 1, new QTableWidgetItem("??"));
        DisasmTable->setItem(0, 2, new QTableWidgetItem("(unreadable)"));
        DisasmTable->setItem(0, 3, new QTableWidgetItem(""));
        return;
    }

    constexpr int MaxRows = 32;
    DisasmTable->setRowCount(MaxRows);

    RegisterSet Regs = EngineRef->GetRegisters();
    Address Rip = Regs.Rip;

    size_t Offset = 0;
    for (int Row = 0; Row < MaxRows && Offset < ReadSize; ++Row) {
        Address InstrAddr = Addr + Offset;

        int InstrLen = 1;
        uint8_t FirstByte = Buffer[Offset];

        if ((FirstByte & 0xF0) == 0x40 && Offset + 1 < ReadSize) {
            InstrLen = 2;
            uint8_t SecondByte = Buffer[Offset + 1];
            if (SecondByte >= 0x80 && SecondByte <= 0x8F) InstrLen = 6;
            else if (SecondByte == 0x8D || SecondByte == 0x89 || SecondByte == 0x8B) InstrLen = 3;
            else if (SecondByte == 0xC3) InstrLen = 2;
            else if (SecondByte == 0xFF) InstrLen = 3;
            else InstrLen = 2;
        } else if (FirstByte == 0xCC) {
            InstrLen = 1;
        } else if (FirstByte == 0xC3 || FirstByte == 0xCB) {
            InstrLen = 1;
        } else if (FirstByte == 0x90) {
            InstrLen = 1;
        } else if (FirstByte == 0xE8 || FirstByte == 0xE9) {
            InstrLen = 5;
        } else if (FirstByte >= 0x70 && FirstByte <= 0x7F) {
            InstrLen = 2;
        } else if (FirstByte == 0xEB) {
            InstrLen = 2;
        } else if (FirstByte >= 0x50 && FirstByte <= 0x5F) {
            InstrLen = 1;
        } else if (FirstByte >= 0xB8 && FirstByte <= 0xBF) {
            InstrLen = 5;
        } else {
            InstrLen = 1;
        }

        if (Offset + InstrLen > ReadSize) {
            InstrLen = static_cast<int>(ReadSize - Offset);
        }

        QString AddrStr = QString("0x%1").arg(InstrAddr, 16, 16, QChar('0'));
        QString ByteStr;
        for (int B = 0; B < InstrLen; ++B) {
            if (!ByteStr.isEmpty()) ByteStr += " ";
            ByteStr += QString("%1").arg(Buffer[Offset + B], 2, 16, QChar('0')).toUpper();
        }

        QString Mnemonic;
        QString Operands;

        switch (FirstByte) {
        case 0xCC: Mnemonic = "int3"; break;
        case 0xC3: Mnemonic = "ret"; break;
        case 0xCB: Mnemonic = "retf"; break;
        case 0x90: Mnemonic = "nop"; break;
        case 0xE8: Mnemonic = "call"; {
            if (InstrLen >= 5) {
                int32_t Rel = *reinterpret_cast<const int32_t*>(&Buffer[Offset + 1]);
                Address Target = InstrAddr + 5 + Rel;
                Operands = QString("0x%1").arg(Target, 16, 16, QChar('0'));
            }
        } break;
        case 0xE9: Mnemonic = "jmp"; {
            if (InstrLen >= 5) {
                int32_t Rel = *reinterpret_cast<const int32_t*>(&Buffer[Offset + 1]);
                Address Target = InstrAddr + 5 + Rel;
                Operands = QString("0x%1").arg(Target, 16, 16, QChar('0'));
            }
        } break;
        case 0xEB: Mnemonic = "jmp short"; {
            if (InstrLen >= 2) {
                int8_t Rel = static_cast<int8_t>(Buffer[Offset + 1]);
                Address Target = InstrAddr + 2 + Rel;
                Operands = QString("0x%1").arg(Target, 16, 16, QChar('0'));
            }
        } break;
        default:
            if (FirstByte >= 0x50 && FirstByte <= 0x57) {
                Mnemonic = "push";
                const char* RegNames[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"};
                Operands = RegNames[FirstByte - 0x50];
            } else if (FirstByte >= 0x58 && FirstByte <= 0x5F) {
                Mnemonic = "pop";
                const char* RegNames[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"};
                Operands = RegNames[FirstByte - 0x58];
            } else if (FirstByte >= 0x70 && FirstByte <= 0x7F) {
                const char* JccNames[] = {"jo","jno","jb","jnb","jz","jnz","jbe","ja",
                                          "js","jns","jp","jnp","jl","jnl","jle","jg"};
                Mnemonic = JccNames[FirstByte - 0x70];
                if (InstrLen >= 2) {
                    int8_t Rel = static_cast<int8_t>(Buffer[Offset + 1]);
                    Address Target = InstrAddr + 2 + Rel;
                    Operands = QString("0x%1").arg(Target, 16, 16, QChar('0'));
                }
            } else {
                Mnemonic = "db";
                Operands = QString("0x%1").arg(FirstByte, 2, 16, QChar('0'));
            }
            break;
        }

        auto* AddrItem = new QTableWidgetItem(AddrStr);
        auto* ByteItem = new QTableWidgetItem(ByteStr);
        auto* MnemonicItem = new QTableWidgetItem(Mnemonic);
        auto* OperandsItem = new QTableWidgetItem(Operands);

        if (InstrAddr == Rip) {
            QBrush HighlightBg(QColor(60, 60, 120));
            QBrush HighlightFg(QColor(255, 255, 100));
            for (auto* Itm : {AddrItem, ByteItem, MnemonicItem, OperandsItem}) {
                Itm->setBackground(HighlightBg);
                Itm->setForeground(HighlightFg);
            }
        }

        DisasmTable->setItem(Row, 0, AddrItem);
        DisasmTable->setItem(Row, 1, ByteItem);
        DisasmTable->setItem(Row, 2, MnemonicItem);
        DisasmTable->setItem(Row, 3, OperandsItem);

        Offset += InstrLen;
    }

    int FinalRowCount = 0;
    for (int Row = 0; Row < MaxRows; ++Row) {
        if (DisasmTable->item(Row, 0)) FinalRowCount = Row + 1;
        else break;
    }
    DisasmTable->setRowCount(FinalRowCount);
}

void DebuggerWidget::UpdateMemoryDump(Address Addr) {
    if (!EngineRef) return;

    constexpr int NumRows = 16;
    constexpr int BytesPerRow = 16;
    constexpr size_t TotalBytes = NumRows * BytesPerRow;

    uint8_t Buffer[TotalBytes] = {};
    bool Ok = EngineRef->ReadDebugMemory(Addr, Buffer, TotalBytes);

    MemoryTable->setRowCount(NumRows);

    for (int Row = 0; Row < NumRows; ++Row) {
        Address RowAddr = Addr + Row * BytesPerRow;

        auto* AddrItem = new QTableWidgetItem(QString("0x%1").arg(RowAddr, 16, 16, QChar('0')));
        MemoryTable->setItem(Row, 0, AddrItem);

        QString AsciiStr;
        for (int Col = 0; Col < BytesPerRow; ++Col) {
            int ByteIndex = Row * BytesPerRow + Col;
            if (Ok) {
                uint8_t Byte = Buffer[ByteIndex];
                auto* ByteItem = new QTableWidgetItem(QString("%1").arg(Byte, 2, 16, QChar('0')).toUpper());
                MemoryTable->setItem(Row, Col + 1, ByteItem);

                if (Byte >= 0x20 && Byte < 0x7F) {
                    AsciiStr += QChar(Byte);
                } else {
                    AsciiStr += '.';
                }
            } else {
                MemoryTable->setItem(Row, Col + 1, new QTableWidgetItem("??"));
                AsciiStr += '?';
            }
        }

        auto* AsciiItem = new QTableWidgetItem(AsciiStr);
        MemoryTable->setItem(Row, 17, AsciiItem);
    }
}

}
