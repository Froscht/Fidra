#include "MultibinaryModule.h"
#include <QStyle>
#include <QApplication>

namespace Fidra {

MultibinaryModule::MultibinaryModule(QObject* Parent)
    : QObject(Parent), CoreRef(nullptr), MainWidget(nullptr) {}

MultibinaryModule::~MultibinaryModule() = default;

QIcon MultibinaryModule::Icon() const {
    return qApp->style()->standardIcon(QStyle::SP_DirIcon);
}

QWidget* MultibinaryModule::CreateMainWidget(QWidget* Parent) {
    MainWidget = new QLabel(QStringLiteral(
        "Cross-binary index / project.\n\n"
        "MultibinaryProject compiled. MultibinaryIndex excluded pending Hexrays microcode bridge "
        "(88 errors in visit_insn/visit_expr / cinsn_t::cswitch traversal).\n\n"
        "See src/multibinary/PORT_NOTES.md."
    ), Parent);
    MainWidget->setWordWrap(true);
    MainWidget->setMargin(24);
    return MainWidget;
}

void MultibinaryModule::Initialize(ICore* Core) {
    CoreRef = Core;
    if (CoreRef) CoreRef->Log(QStringLiteral("Multibinary module initialized (Project compiled, Index blocked)"));
}

void MultibinaryModule::Shutdown() {
    if (CoreRef) CoreRef->Log(QStringLiteral("Multibinary module shutdown"));
}

}
