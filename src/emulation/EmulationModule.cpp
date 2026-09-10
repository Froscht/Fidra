#include "EmulationModule.h"
#include "EmulationEngine.h"
#include <QStyle>
#include <QApplication>

namespace Fidra {

EmulationModule::EmulationModule(QObject* Parent)
    : QObject(Parent), CoreRef(nullptr), MainWidget(nullptr) {}

EmulationModule::~EmulationModule() = default;

QIcon EmulationModule::Icon() const {
    return qApp->style()->standardIcon(QStyle::SP_MediaPlay);
}

QWidget* EmulationModule::CreateMainWidget(QWidget* Parent) {
    QString Body;
    if (EmulationEngine::IsAvailable()) {
        Body = QStringLiteral(
            "Unicorn emulation available.\n\n"
            "API: Fidra::EmulationEngine::EmulateFunction(db, ea).\n"
            "Auto-maps segments from AnalysisDatabase, initialises stack at "
            "0x7FFF00000000, runs until func.End or timeout.\n\n"
            "UI panel with register view / trace list is next-session work."
        );
    } else {
        Body = QStringLiteral(
            "Unicorn not compiled in.\n\n"
            "Rebuild with -DFIDRA_ENABLE_UNICORN=ON.\n"
            "Submodule at third_party/unicorn — run\n"
            "  git submodule update --init --recursive"
        );
    }
    MainWidget = new QLabel(Body, Parent);
    MainWidget->setWordWrap(true);
    MainWidget->setMargin(24);
    return MainWidget;
}

void EmulationModule::Initialize(ICore* Core) {
    CoreRef = Core;
    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Emulation module initialized (Unicorn: %1)")
                     .arg(EmulationEngine::IsAvailable() ? "available" : "off"));
    }
}

void EmulationModule::Shutdown() {
    if (CoreRef) CoreRef->Log(QStringLiteral("Emulation module shutdown"));
}

}
