#include "DebuggerModule.h"
#include "DebugEngine.h"
#include "DebuggerWidget.h"
#include "RegisterWidget.h"
#include "StackWidget.h"
#include "BreakpointWidget.h"
#include <QApplication>
#include <QStyle>
#include <QMenuBar>
#include <QMenu>
#include <QToolBar>
#include <QInputDialog>

namespace Fidra {

DebuggerModule::DebuggerModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , Engine(nullptr)
    , MainWidget(nullptr)
    , Registers(nullptr)
    , Stack(nullptr)
    , Breakpoints(nullptr)
{
}

DebuggerModule::~DebuggerModule() {
}

QString DebuggerModule::Name() const {
    return "Debugger";
}

QString DebuggerModule::Description() const {
    return "Process debugger with breakpoints and stepping";
}

QIcon DebuggerModule::Icon() const {
    return qApp->style()->standardIcon(QStyle::SP_MediaPlay);
}

int DebuggerModule::Priority() const {
    return 200;
}

void DebuggerModule::Initialize(ICore* Core) {
    CoreRef = Core;

    Engine = new DebugEngine(this);

    connect(Engine, &DebugEngine::DebugOutput, this, [this](const QString& Message) {
        if (CoreRef) CoreRef->Log(Message, LogLevel::Info);
    });

    connect(Engine, &DebugEngine::ExceptionOccurred, this, [this](uint32_t Code, Address Addr) {
        if (CoreRef) {
            CoreRef->Log(QString("Exception 0x%1 at 0x%2")
                .arg(Code, 8, 16, QChar('0'))
                .arg(Addr, 16, 16, QChar('0')), LogLevel::Warning);
        }
    });

    connect(Engine, &DebugEngine::ProcessStarted, this, [this](uint32_t Pid) {
        if (CoreRef) CoreRef->Log(QString("Debug target started (PID: %1)").arg(Pid), LogLevel::Info);
    });

    connect(Engine, &DebugEngine::ProcessExited, this, [this](int ExitCode) {
        if (CoreRef) CoreRef->Log(QString("Debug target exited (code: %1)").arg(ExitCode), LogLevel::Info);
    });

    connect(Engine, &DebugEngine::BreakpointHit, this, [this](Address Addr) {
        if (CoreRef) CoreRef->Log(QString("Breakpoint hit at 0x%1").arg(Addr, 16, 16, QChar('0')), LogLevel::Info);
    });

    connect(Engine, &DebugEngine::StateChanged, this, [this](DebugState NewState) {
        if (!CoreRef) return;
        switch (NewState) {
        case DebugState::Idle: CoreRef->Log("Debugger: Idle", LogLevel::Debug); break;
        case DebugState::Running: CoreRef->Log("Debugger: Running", LogLevel::Debug); break;
        case DebugState::Paused: CoreRef->Log("Debugger: Paused", LogLevel::Debug); break;
        case DebugState::Stopped: CoreRef->Log("Debugger: Stopped", LogLevel::Debug); break;
        }
    });

    if (MainWidget) {
        MainWidget->SetEngine(Engine);
        MainWidget->SetCore(CoreRef);
    }
    if (Registers) Registers->SetEngine(Engine);
    if (Stack) Stack->SetEngine(Engine);
    if (Breakpoints) Breakpoints->SetEngine(Engine);
}

void DebuggerModule::Shutdown() {
    if (Engine) {
        if (Engine->CurrentState() != DebugState::Idle && Engine->CurrentState() != DebugState::Stopped) {
            Engine->Stop();
            Engine->wait(3000);
        }
        if (Engine->isRunning()) {
            Engine->terminate();
            Engine->wait(1000);
        }
    }
}

QWidget* DebuggerModule::CreateMainWidget(QWidget* Parent) {
    MainWidget = new DebuggerWidget(Parent);
    if (Engine) {
        MainWidget->SetEngine(Engine);
    }
    if (CoreRef) {
        MainWidget->SetCore(CoreRef);
    }
    return MainWidget;
}

QList<QPair<QString, QWidget*>> DebuggerModule::CreateDockWidgets(QWidget* Parent) {
    QList<QPair<QString, QWidget*>> Docks;

    Registers = new RegisterWidget(Parent);
    if (Engine) Registers->SetEngine(Engine);
    Docks.append({"Registers", Registers});

    Stack = new StackWidget(Parent);
    if (Engine) Stack->SetEngine(Engine);
    Docks.append({"Call Stack", Stack});

    Breakpoints = new BreakpointWidget(Parent);
    if (Engine) Breakpoints->SetEngine(Engine);
    Docks.append({"Breakpoints", Breakpoints});

    return Docks;
}

void DebuggerModule::OnProcessAttached(const ProcessInfo& Info) {
    if (Engine && Engine->CurrentState() == DebugState::Idle) {
        if (CoreRef) {
            CoreRef->Log(QString("Debugger: Process %1 (PID: %2) attached via ICore")
                .arg(Info.Name).arg(Info.Pid), LogLevel::Info);
        }
    }
}

void DebuggerModule::OnProcessDetached() {
    if (Engine && Engine->CurrentState() != DebugState::Idle) {
        Engine->DetachFromProcess();
    }
}

void DebuggerModule::ContributeToMenu(QMenuBar* MenuBar) {
    QMenu* DebugMenu = nullptr;
    for (auto* Action : MenuBar->actions()) {
        if (Action->text().contains("Debug", Qt::CaseInsensitive)) {
            DebugMenu = Action->menu();
            break;
        }
    }

    if (!DebugMenu) {
        DebugMenu = MenuBar->addMenu("&Debug");
    }

    auto* AttachAction = DebugMenu->addAction("Attach Debugger...");
    AttachAction->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_A));
    connect(AttachAction, &QAction::triggered, this, [this]() {
        if (!CoreRef) return;
        bool Ok = false;
        int Pid = QInputDialog::getInt(CoreRef->MainWindow(), "Attach Debugger",
            "Process ID:", 0, 0, 2147483647, 1, &Ok);
        if (Ok && Pid > 0 && Engine) {
            Engine->AttachToProcess(static_cast<uint32_t>(Pid));
        }
    });

    auto* LaunchAction = DebugMenu->addAction("Launch Process...");
    connect(LaunchAction, &QAction::triggered, this, [this]() {
        if (!CoreRef) return;
        bool Ok = false;
        QString Path = QInputDialog::getText(CoreRef->MainWindow(), "Launch Process",
            "Executable path:", QLineEdit::Normal, "", &Ok);
        if (Ok && !Path.isEmpty() && Engine) {
            Engine->LaunchProcess(Path);
        }
    });

    auto* DetachAction = DebugMenu->addAction("Detach Debugger");
    connect(DetachAction, &QAction::triggered, this, [this]() {
        if (Engine) Engine->DetachFromProcess();
    });

    DebugMenu->addSeparator();

    auto* ContinueAction = DebugMenu->addAction("Continue");
    ContinueAction->setShortcut(QKeySequence(Qt::Key_F5));
    connect(ContinueAction, &QAction::triggered, this, [this]() {
        if (Engine) Engine->Continue();
    });

    auto* StepIntoAction = DebugMenu->addAction("Step Into");
    StepIntoAction->setShortcut(QKeySequence(Qt::Key_F11));
    connect(StepIntoAction, &QAction::triggered, this, [this]() {
        if (Engine) Engine->StepInto();
    });

    auto* StepOverAction = DebugMenu->addAction("Step Over");
    StepOverAction->setShortcut(QKeySequence(Qt::Key_F10));
    connect(StepOverAction, &QAction::triggered, this, [this]() {
        if (Engine) Engine->StepOver();
    });

    auto* StepOutAction = DebugMenu->addAction("Step Out");
    StepOutAction->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F11));
    connect(StepOutAction, &QAction::triggered, this, [this]() {
        if (Engine) Engine->StepOut();
    });

    DebugMenu->addSeparator();

    auto* BreakAction = DebugMenu->addAction("Break");
    BreakAction->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_Pause));
    connect(BreakAction, &QAction::triggered, this, [this]() {
        if (Engine) Engine->Pause();
    });

    auto* StopAction = DebugMenu->addAction("Stop Debugging");
    StopAction->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F5));
    connect(StopAction, &QAction::triggered, this, [this]() {
        if (Engine) Engine->Stop();
    });

    DebugMenu->addSeparator();

    auto* AddBpAction = DebugMenu->addAction("Add Breakpoint...");
    AddBpAction->setShortcut(QKeySequence(Qt::Key_F9));
    connect(AddBpAction, &QAction::triggered, this, [this]() {
        if (!CoreRef || !Engine) return;
        bool Ok = false;
        QString AddrStr = QInputDialog::getText(CoreRef->MainWindow(), "Add Breakpoint",
            "Address (hex):", QLineEdit::Normal, "0x", &Ok);
        if (Ok && !AddrStr.isEmpty()) {
            QString Stripped = AddrStr.trimmed();
            if (Stripped.startsWith("0x", Qt::CaseInsensitive)) {
                Stripped = Stripped.mid(2);
            }
            bool ParseOk = false;
            Address Addr = Stripped.toULongLong(&ParseOk, 16);
            if (ParseOk && Addr != 0) {
                Engine->AddBreakpoint(Addr);
            }
        }
    });
}

void DebuggerModule::ContributeToToolBar(QToolBar* ToolBar) {
    ToolBar->addSeparator();

    auto* AttachDbgAction = ToolBar->addAction(
        qApp->style()->standardIcon(QStyle::SP_MediaPlay), "Debug Attach");
    connect(AttachDbgAction, &QAction::triggered, this, [this]() {
        if (!CoreRef) return;
        bool Ok = false;
        int Pid = QInputDialog::getInt(CoreRef->MainWindow(), "Attach Debugger",
            "Process ID:", 0, 0, 2147483647, 1, &Ok);
        if (Ok && Pid > 0 && Engine) {
            Engine->AttachToProcess(static_cast<uint32_t>(Pid));
        }
    });
}

}
