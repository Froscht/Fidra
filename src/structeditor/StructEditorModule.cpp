#include "StructEditorModule.h"
#include "StructEditorWidget.h"
#include <QStyle>
#include <QApplication>

namespace Fidra {

StructEditorModule::StructEditorModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , MainWidget(nullptr)
{
}

StructEditorModule::~StructEditorModule() = default;

QString StructEditorModule::Name() const
{
    return QStringLiteral("Struct Editor");
}

QString StructEditorModule::Description() const
{
    return QStringLiteral("Type System & Structure Editor");
}

QIcon StructEditorModule::Icon() const
{
    return QApplication::style()->standardIcon(QStyle::SP_FileDialogDetailedView);
}

int StructEditorModule::Priority() const
{
    return 50;
}

QWidget* StructEditorModule::CreateMainWidget(QWidget* Parent)
{
    MainWidget = new StructEditorWidget(Parent, CoreRef);
    return MainWidget;
}

QList<QPair<QString, QWidget*>> StructEditorModule::CreateDockWidgets(QWidget* Parent)
{
    Q_UNUSED(Parent);
    return {};
}

void StructEditorModule::Initialize(ICore* Core)
{
    CoreRef = Core;
    CoreRef->Log(QStringLiteral("Struct Editor module initialized"));
}

void StructEditorModule::Shutdown()
{
    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Struct Editor module shutdown"));
    }
}

void StructEditorModule::OnProcessAttached(const ProcessInfo& Info)
{
    if (MainWidget) {
        MainWidget->OnProcessAttached(Info);
    }
}

void StructEditorModule::OnProcessDetached()
{
    if (MainWidget) {
        MainWidget->OnProcessDetached();
    }
}

}
