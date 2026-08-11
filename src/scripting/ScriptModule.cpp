#include "ScriptModule.h"
#include "ScriptWidget.h"
#include <QStyle>
#include <QApplication>

namespace Fidra {

ScriptModule::ScriptModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , MainWidget(nullptr)
{
}

ScriptModule::~ScriptModule() = default;

QString ScriptModule::Name() const {
    return QStringLiteral("Scripting");
}

QString ScriptModule::Description() const {
    return QStringLiteral("FidraScript Scripting Engine");
}

QIcon ScriptModule::Icon() const {
    return qApp->style()->standardIcon(QStyle::SP_FileDialogListView);
}

int ScriptModule::Priority() const {
    return 70;
}

QWidget* ScriptModule::CreateMainWidget(QWidget* Parent) {
    MainWidget = new ScriptWidget(Parent, CoreRef);
    return MainWidget;
}

QList<QPair<QString, QWidget*>> ScriptModule::CreateDockWidgets(QWidget* Parent) {
    Q_UNUSED(Parent);
    return {};
}

void ScriptModule::Initialize(ICore* Core) {
    CoreRef = Core;
    CoreRef->Log(QStringLiteral("Scripting module initialized"));
}

void ScriptModule::Shutdown() {
    if (CoreRef) CoreRef->Log(QStringLiteral("Scripting module shutdown"));
}

void ScriptModule::OnProcessAttached(const ProcessInfo& Info) {
    if (MainWidget) MainWidget->OnProcessAttached(Info);
}

void ScriptModule::OnProcessDetached() {
    if (MainWidget) MainWidget->OnProcessDetached();
}

void ScriptModule::OnAnalysisComplete(AnalysisDatabase* Db, Address) {
    if (MainWidget) MainWidget->SetDatabase(Db);
}

}
