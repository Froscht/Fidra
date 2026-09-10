#include "VulnModule.h"
#include <QStyle>
#include <QApplication>

namespace Fidra {

VulnModule::VulnModule(QObject* Parent)
    : QObject(Parent), CoreRef(nullptr), MainWidget(nullptr) {}

VulnModule::~VulnModule() = default;

QIcon VulnModule::Icon() const {
    return qApp->style()->standardIcon(QStyle::SP_MessageBoxWarning);
}

QWidget* VulnModule::CreateMainWidget(QWidget* Parent) {
    MainWidget = new QLabel(QStringLiteral(
        "Vuln chain analysis ported from AiDA.\n\n"
        "19 chain files compiled. 16 files pending Hexrays microcode bridge.\n"
        "Runtime API surface: chain::extraction, chain::verification,\n"
        "chain::taint (behind FIDRA_ENABLE_TRITON for symbolic engine).\n\n"
        "Wire up UI panels in future work — see src/vuln/PORT_NOTES.md."
    ), Parent);
    MainWidget->setWordWrap(true);
    MainWidget->setMargin(24);
    return MainWidget;
}

void VulnModule::Initialize(ICore* Core) {
    CoreRef = Core;
    if (CoreRef) CoreRef->Log(QStringLiteral("Vuln module initialized (compile-only stubs)"));
}

void VulnModule::Shutdown() {
    if (CoreRef) CoreRef->Log(QStringLiteral("Vuln module shutdown"));
}

void VulnModule::OnAnalysisComplete(AnalysisDatabase* /*Db*/, Address /*EntryPoint*/) {
    // Full chain scan would kick off here — deferred pending runtime bring-up.
}

}
