#pragma once

#include "ICore.h"
#include <QString>
#include <QIcon>
#include <QWidget>
#include <QAction>
#include <QMenu>
#include <QToolBar>

namespace Fidra {

class AnalysisDatabase;

class IModule {
public:
    virtual ~IModule() = default;

    virtual QString Name() const = 0;
    virtual QString Description() const = 0;
    virtual QIcon Icon() const = 0;
    virtual int Priority() const = 0;

    virtual QWidget* CreateMainWidget(QWidget* Parent) = 0;
    virtual QList<QPair<QString, QWidget*>> CreateDockWidgets(QWidget* Parent) { Q_UNUSED(Parent); return {}; }

    virtual void Initialize(ICore* Core) = 0;
    virtual void PostInitialize(ICore* Core) { Q_UNUSED(Core); }
    virtual void Shutdown() = 0;

    virtual void OnProcessAttached(const ProcessInfo& Info) { Q_UNUSED(Info); }
    virtual void OnProcessDetached() {}

    virtual void ContributeToMenu(QMenuBar* MenuBar) { Q_UNUSED(MenuBar); }
    virtual void ContributeToToolBar(QToolBar* ToolBar) { Q_UNUSED(ToolBar); }

    virtual void OnAnalysisComplete(AnalysisDatabase* Db, Address EntryPoint) { Q_UNUSED(Db); Q_UNUSED(EntryPoint); }

    virtual QList<QPair<QString, QKeySequence>> GetShortcuts() { return {}; }
};

}
