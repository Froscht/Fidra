#include "CallGraphModule.h"
#include "CallGraphWidget.h"

#include <QStyle>
#include <QApplication>

namespace Fidra {

CallGraphModule::CallGraphModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , Widget(nullptr) {
}

CallGraphModule::~CallGraphModule() {
}

QString CallGraphModule::Name() const {
    return QStringLiteral("Call Graph");
}

QString CallGraphModule::Description() const {
    return QStringLiteral("Interactive Call Graph Visualization");
}

QIcon CallGraphModule::Icon() const {
    return QApplication::style()->standardIcon(QStyle::SP_FileDialogInfoView);
}

int CallGraphModule::Priority() const {
    return 55;
}

QWidget* CallGraphModule::CreateMainWidget(QWidget* Parent) {
    Widget = new CallGraphWidget(Parent);
    return Widget;
}

void CallGraphModule::Initialize(ICore* Core) {
    CoreRef = Core;
}

void CallGraphModule::Shutdown() {
    Widget = nullptr;
}

void CallGraphModule::OnAnalysisComplete(AnalysisDatabase* Db, Address EntryPoint) {
    if (Widget) {
        Widget->SetDatabase(Db);
        Widget->BuildGraph(EntryPoint, 3);
    }
}

}
