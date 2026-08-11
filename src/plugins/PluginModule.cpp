#include "PluginModule.h"
#include "PluginWidget.h"
#include "PluginLoader.h"
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
QString PluginModule::Description() const { return QStringLiteral("Dynamic Plugin Manager"); }

QIcon PluginModule::Icon() const
{
    return qApp->style()->standardIcon(QStyle::SP_FileDialogInfoView);
}

int PluginModule::Priority() const { return 90; }

QWidget* PluginModule::CreateMainWidget(QWidget* Parent)
{
    MainWidget = new PluginWidget(Parent, CoreRef);
    return MainWidget;
}

void PluginModule::Initialize(ICore* Core)
{
    CoreRef = Core;
    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Plugin module initialized"));
    }
}

void PluginModule::Shutdown()
{
    if (MainWidget) {
        PluginLoader* Loader = MainWidget->GetLoader();
        if (Loader) {
            Loader->UnloadAll();
        }
    }
    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Plugin module shutdown"));
    }
}

}
