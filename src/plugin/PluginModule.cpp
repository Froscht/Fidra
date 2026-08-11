#include "PluginModule.h"
#include "PluginWidget.h"
#include "PluginManager.h"
#include <QStyle>
#include <QApplication>

namespace Fidra {

PluginModule::PluginModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , MainWidget(nullptr)
{
}

PluginModule::~PluginModule() = default;

QString PluginModule::Name() const { return QStringLiteral("Plugins"); }
QString PluginModule::Description() const { return QStringLiteral("Plugin Manager"); }

QIcon PluginModule::Icon() const
{
    return qApp->style()->standardIcon(QStyle::SP_FileDialogNewFolder);
}

int PluginModule::Priority() const { return 3; }

QWidget* PluginModule::CreateMainWidget(QWidget* Parent)
{
    MainWidget = new PluginWidget(Parent, CoreRef);
    return MainWidget;
}

QList<QPair<QString, QWidget*>> PluginModule::CreateDockWidgets(QWidget* Parent)
{
    Q_UNUSED(Parent);
    return {};
}

void PluginModule::Initialize(ICore* Core)
{
    CoreRef = Core;
    CoreRef->Log(QStringLiteral("Plugin module initialized"));
}

void PluginModule::Shutdown()
{
    if (MainWidget) {
        PluginManager* Manager = MainWidget->GetManager();
        if (Manager) {
            Manager->UnloadAll();
        }
    }
    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Plugin module shutdown"));
    }
}

}
