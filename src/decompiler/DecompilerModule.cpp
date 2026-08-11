#include "DecompilerModule.h"
#include "DecompilerWidget.h"
#include <QStyle>
#include <QApplication>

namespace Fidra {

DecompilerModule::DecompilerModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , MainWidget(nullptr)
{
}

DecompilerModule::~DecompilerModule() = default;

QString DecompilerModule::Name() const {
    return QStringLiteral("Decompiler");
}

QString DecompilerModule::Description() const {
    return QStringLiteral("Pseudo-C Decompiler");
}

QIcon DecompilerModule::Icon() const {
    return qApp->style()->standardIcon(QStyle::SP_FileDialogDetailedView);
}

int DecompilerModule::Priority() const {
    return 40;
}

QWidget* DecompilerModule::CreateMainWidget(QWidget* Parent) {
    MainWidget = new DecompilerWidget(Parent, CoreRef);
    return MainWidget;
}

QList<QPair<QString, QWidget*>> DecompilerModule::CreateDockWidgets(QWidget* Parent) {
    Q_UNUSED(Parent);
    return {};
}

void DecompilerModule::Initialize(ICore* Core) {
    CoreRef = Core;
    CoreRef->Log(QStringLiteral("Decompiler module initialized"));
}

void DecompilerModule::Shutdown() {
    if (CoreRef)
        CoreRef->Log(QStringLiteral("Decompiler module shutdown"));
}

void DecompilerModule::OnAnalysisComplete(AnalysisDatabase* Db, Address EntryPoint) {
    if (MainWidget) {
        MainWidget->SetDatabase(Db);
        if (EntryPoint != 0)
            MainWidget->DecompileFunction(EntryPoint, Db);
    }
}

}
