#pragma once

#include "DebugEngine.h"
#include <fidra/ICore.h>
#include <QWidget>
#include <QTableWidget>
#include <QSplitter>
#include <QToolBar>
#include <QLabel>
#include <QVBoxLayout>
#include <QAction>

namespace Fidra {

class DebuggerWidget : public QWidget {
    Q_OBJECT

public:
    explicit DebuggerWidget(QWidget* Parent = nullptr);
    ~DebuggerWidget() override = default;

    void SetEngine(DebugEngine* Engine);
    void SetCore(ICore* Core);

public slots:
    void OnStateChanged(DebugState NewState);
    void OnBreakpointHit(Address Addr);
    void OnSingleStepCompleted();

    void UpdateDisassembly(Address Addr);
    void UpdateMemoryDump(Address Addr);

private:
    void SetupToolBar();
    void SetupDisassemblyView();
    void SetupMemoryDumpView();
    void UpdateToolBarState(DebugState State);
    void RefreshViewsAtRip();

    DebugEngine* EngineRef;
    ICore* CoreRef;

    QVBoxLayout* MainLayout;
    QToolBar* ToolBar;
    QSplitter* CentralSplitter;

    QTableWidget* DisasmTable;
    QTableWidget* MemoryTable;

    QLabel* StateLabel;
    QAction* RunAction;
    QAction* PauseAction;
    QAction* StepIntoAction;
    QAction* StepOverAction;
    QAction* StepOutAction;
    QAction* StopAction;

    Address CurrentAddress;
};

}
