#include "NetworkModule.h"
#include "NetworkWidget.h"

#include <QMenu>
#include <QMenuBar>
#include <QToolBar>
#include <QAction>
#include <QFileDialog>

namespace Fidra {

NetworkModule::NetworkModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , MainWidget(nullptr) {
}

NetworkModule::~NetworkModule() {
}

QString NetworkModule::Name() const {
    return QStringLiteral("Network");
}

QString NetworkModule::Description() const {
    return QStringLiteral("Network packet capture and analysis");
}

QIcon NetworkModule::Icon() const {
    return QIcon::fromTheme(QStringLiteral("network-wired"));
}

int NetworkModule::Priority() const {
    return 500;
}

QWidget* NetworkModule::CreateMainWidget(QWidget* Parent) {
    MainWidget = new NetworkWidget(Parent);
    return MainWidget;
}

QList<QPair<QString, QWidget*>> NetworkModule::CreateDockWidgets(QWidget* Parent) {
    Q_UNUSED(Parent);
    return {};
}

void NetworkModule::Initialize(ICore* Core) {
    CoreRef = Core;

    if (MainWidget) {
        MainWidget->SetCore(Core);
    }
}

void NetworkModule::Shutdown() {
    CoreRef = nullptr;
}

void NetworkModule::ContributeToMenu(QMenuBar* MenuBar) {
    QMenu* NetworkMenu = MenuBar->addMenu(QStringLiteral("Network"));

    QAction* StartCaptureAction = NetworkMenu->addAction(QStringLiteral("Start Capture"));
    StartCaptureAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+C")));
    connect(StartCaptureAction, &QAction::triggered, this, [this]() {
        if (MainWidget) {
            MainWidget->OnStartStopCapture();
        }
    });

    QAction* StopCaptureAction = NetworkMenu->addAction(QStringLiteral("Stop Capture"));
    StopCaptureAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+X")));
    connect(StopCaptureAction, &QAction::triggered, this, [this]() {
        if (MainWidget) {
            MainWidget->OnStartStopCapture();
        }
    });

    NetworkMenu->addSeparator();

    QAction* ClearAction = NetworkMenu->addAction(QStringLiteral("Clear Packets"));
    connect(ClearAction, &QAction::triggered, this, [this]() {
        if (MainWidget) {
            MainWidget->OnClearPackets();
        }
    });

    NetworkMenu->addSeparator();

    QAction* OpenPcapAction = NetworkMenu->addAction(QStringLiteral("Open PCAP..."));
    OpenPcapAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+O")));
    connect(OpenPcapAction, &QAction::triggered, this, [this]() {
        if (MainWidget) {
            MainWidget->OnLoadPcap();
        }
    });

    QAction* SavePcapAction = NetworkMenu->addAction(QStringLiteral("Save PCAP..."));
    SavePcapAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+S")));
    connect(SavePcapAction, &QAction::triggered, this, [this]() {
        if (MainWidget) {
            MainWidget->OnSavePcap();
        }
    });
}

void NetworkModule::ContributeToToolBar(QToolBar* ToolBar) {
    Q_UNUSED(ToolBar);
}

}
