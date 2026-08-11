#include "ScannerModule.h"
#include "ScannerWidget.h"

namespace Fidra {

ScannerModule::ScannerModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , MainWidget(nullptr)
{
}

ScannerModule::~ScannerModule() = default;

QString ScannerModule::Name() const
{
    return QStringLiteral("Scanner");
}

QString ScannerModule::Description() const
{
    return QStringLiteral("Memory scanner for finding and modifying values");
}

QIcon ScannerModule::Icon() const
{
    return QIcon::fromTheme(QStringLiteral("edit-find"));
}

int ScannerModule::Priority() const
{
    return 300;
}

QWidget* ScannerModule::CreateMainWidget(QWidget* Parent)
{
    MainWidget = new ScannerWidget(Parent, CoreRef);
    return MainWidget;
}

QList<QPair<QString, QWidget*>> ScannerModule::CreateDockWidgets(QWidget* Parent)
{
    Q_UNUSED(Parent);
    return {};
}

void ScannerModule::Initialize(ICore* Core)
{
    CoreRef = Core;
    CoreRef->Log(QStringLiteral("Scanner module initialized"));
}

void ScannerModule::Shutdown()
{
    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Scanner module shutdown"));
    }
}

void ScannerModule::OnProcessAttached(const ProcessInfo& Info)
{
    if (MainWidget) {
        MainWidget->OnProcessAttached(Info);
    }
}

void ScannerModule::OnProcessDetached()
{
    if (MainWidget) {
        MainWidget->OnProcessDetached();
    }
}

}
