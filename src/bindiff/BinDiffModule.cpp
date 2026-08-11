#include "BinDiffModule.h"
#include "BinDiffWidget.h"
#include <QStyle>
#include <QApplication>

namespace Fidra {

BinDiffModule::BinDiffModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , Widget(nullptr)
{
}

BinDiffModule::~BinDiffModule() {}

QString BinDiffModule::Name() const { return QStringLiteral("Binary Diff"); }
QString BinDiffModule::Description() const { return QStringLiteral("Binary File Comparison"); }
QIcon BinDiffModule::Icon() const { return QApplication::style()->standardIcon(QStyle::SP_FileDialogContentsView); }
int BinDiffModule::Priority() const { return 65; }

QWidget* BinDiffModule::CreateMainWidget(QWidget* Parent) {
    Widget = new BinDiffWidget(Parent);
    return Widget;
}

void BinDiffModule::Initialize(ICore* Core) {
    CoreRef = Core;
}

void BinDiffModule::Shutdown() {
    Widget = nullptr;
}

}
