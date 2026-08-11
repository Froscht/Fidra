#pragma once

#include <fidra/IModule.h>

namespace Fidra {

class DebugEngine;
class DebuggerWidget;
class RegisterWidget;
class StackWidget;
class BreakpointWidget;

class DebuggerModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit DebuggerModule(QObject* Parent = nullptr);
    ~DebuggerModule() override;

    QString Name() const override;
    QString Description() const override;
    QIcon Icon() const override;
    int Priority() const override;

    QWidget* CreateMainWidget(QWidget* Parent) override;
    QList<QPair<QString, QWidget*>> CreateDockWidgets(QWidget* Parent) override;

    void Initialize(ICore* Core) override;
    void Shutdown() override;

    void OnProcessAttached(const ProcessInfo& Info) override;
    void OnProcessDetached() override;

    void ContributeToMenu(QMenuBar* MenuBar) override;
    void ContributeToToolBar(QToolBar* ToolBar) override;

private:
    ICore* CoreRef;
    DebugEngine* Engine;
    DebuggerWidget* MainWidget;
    RegisterWidget* Registers;
    StackWidget* Stack;
    BreakpointWidget* Breakpoints;
};

}
