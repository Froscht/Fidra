#include "WebSecModule.h"
#include "WebSecWidget.h"

#include <QMenu>
#include <QMenuBar>
#include <QAction>

namespace Fidra {

WebSecModule::WebSecModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , MainWidget(nullptr) {
}

WebSecModule::~WebSecModule() {
}

QString WebSecModule::Name() const {
    return QStringLiteral("WebSec");
}

QString WebSecModule::Description() const {
    return QStringLiteral("Web security testing suite with proxy, repeater, intruder, and decoder");
}

QIcon WebSecModule::Icon() const {
    return QIcon::fromTheme(QStringLiteral("network-server"));
}

int WebSecModule::Priority() const {
    return 600;
}

QWidget* WebSecModule::CreateMainWidget(QWidget* Parent) {
    MainWidget = new WebSecWidget(Parent);
    return MainWidget;
}

void WebSecModule::Initialize(ICore* Core) {
    CoreRef = Core;
    if (MainWidget) {
        MainWidget->SetCore(Core);
    }
}

void WebSecModule::Shutdown() {
    if (MainWidget) {
        MainWidget->StopProxy();
    }
    CoreRef = nullptr;
}

void WebSecModule::ContributeToMenu(QMenuBar* MenuBar) {
    QMenu* WebMenu = MenuBar->addMenu(QStringLiteral("WebSec"));

    QAction* StartProxyAction = WebMenu->addAction(QStringLiteral("Start Proxy"));
    StartProxyAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+P")));
    connect(StartProxyAction, &QAction::triggered, this, [this]() {
        if (MainWidget) {
            MainWidget->ToggleProxy();
        }
    });

    QAction* NewRepeaterAction = WebMenu->addAction(QStringLiteral("New Repeater Tab"));
    NewRepeaterAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+R")));
    connect(NewRepeaterAction, &QAction::triggered, this, [this]() {
        if (MainWidget) {
            MainWidget->AddRepeaterTab();
        }
    });
}

}
