#include "DiffModule.h"
#include "DiffWidget.h"
#include <QStyle>
#include <QApplication>

namespace Fidra {

DiffModule::DiffModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , MainWidget(nullptr)
{
}

DiffModule::~DiffModule() = default;

QString DiffModule::Name() const {
    return QStringLiteral("Binary Diff");
}

QString DiffModule::Description() const {
    return QStringLiteral("Binary diff and comparison tool");
}

QIcon DiffModule::Icon() const {
    return qApp->style()->standardIcon(QStyle::SP_FileDialogDetailedView);
}

int DiffModule::Priority() const {
    return 55;
}

QWidget* DiffModule::CreateMainWidget(QWidget* Parent) {
    MainWidget = new DiffWidget(Parent, CoreRef);
    return MainWidget;
}

QList<QPair<QString, QWidget*>> DiffModule::CreateDockWidgets(QWidget* Parent) {
    Q_UNUSED(Parent);
    return {};
}

void DiffModule::Initialize(ICore* Core) {
    CoreRef = Core;
    CoreRef->Log(QStringLiteral("Diff module initialized"));
}

void DiffModule::Shutdown() {
    if (CoreRef)
        CoreRef->Log(QStringLiteral("Diff module shutdown"));
}

}
