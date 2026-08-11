#include "DumperModule.h"
#include "DumperWidget.h"
#include "../analysis/AnalysisEngine.h"
#include "../core/Application.h"
#include <QStyle>
#include <QApplication>

namespace Fidra {

DumperModule::DumperModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , MainWidget(nullptr)
{
}

DumperModule::~DumperModule() = default;

QString DumperModule::Name() const
{
    return QStringLiteral("Dumper");
}

QString DumperModule::Description() const
{
    return QStringLiteral("Live Process Memory Dumper");
}

QIcon DumperModule::Icon() const
{
    return qApp->style()->standardIcon(QStyle::SP_DriveHDIcon);
}

int DumperModule::Priority() const
{
    return 45;
}

QWidget* DumperModule::CreateMainWidget(QWidget* Parent)
{
    MainWidget = new DumperWidget(Parent, CoreRef);
    connect(MainWidget, &DumperWidget::RequestOpenFile, this, [this](const QString& FilePath) {
        auto* App = qobject_cast<Application*>(CoreRef->MainWindow());
        if (App && App->GetAnalysisEngine()) {
            App->GetAnalysisEngine()->LoadFile(FilePath);
        }
    });
    return MainWidget;
}

QList<QPair<QString, QWidget*>> DumperModule::CreateDockWidgets(QWidget* Parent)
{
    Q_UNUSED(Parent);
    return {};
}

void DumperModule::Initialize(ICore* Core)
{
    CoreRef = Core;
    CoreRef->Log(QStringLiteral("Dumper module initialized"));
}

void DumperModule::Shutdown()
{
    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Dumper module shutdown"));
    }
}

void DumperModule::OnProcessAttached(const ProcessInfo& Info)
{
    if (MainWidget) {
        MainWidget->OnProcessAttached(Info);
    }
}

void DumperModule::OnProcessDetached()
{
    if (MainWidget) {
        MainWidget->OnProcessDetached();
    }
}

}
