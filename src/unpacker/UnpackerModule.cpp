#include "UnpackerModule.h"
#include "UnpackerWidget.h"
#include "EntropyWidget.h"

#include <QToolBar>
#include <QAction>
#include <QFileDialog>
#include <QIcon>

namespace Fidra {

UnpackerModule::UnpackerModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , MainWidget(nullptr)
    , EntropyView(nullptr)
{
}

UnpackerModule::~UnpackerModule() = default;

QString UnpackerModule::Name() const
{
    return QStringLiteral("Unpacker");
}

QString UnpackerModule::Description() const
{
    return QStringLiteral("PE Analyzer & Unpacker");
}

QIcon UnpackerModule::Icon() const
{
    return QIcon::fromTheme(QStringLiteral("package"),
        QIcon(QStringLiteral(":/icons/unpacker.png")));
}

int UnpackerModule::Priority() const
{
    return 400;
}

QWidget* UnpackerModule::CreateMainWidget(QWidget* Parent)
{
    MainWidget = new UnpackerWidget(Parent);
    return MainWidget;
}

QList<QPair<QString, QWidget*>> UnpackerModule::CreateDockWidgets(QWidget* Parent)
{
    EntropyView = new EntropyWidget(Parent);
    return {{ QStringLiteral("Entropy"), EntropyView }};
}

void UnpackerModule::Initialize(ICore* Core)
{
    CoreRef = Core;

    if (MainWidget)
        MainWidget->SetCore(Core);

    if (EntropyView)
        EntropyView->SetCore(Core);
}

void UnpackerModule::Shutdown()
{
    CoreRef = nullptr;
    MainWidget = nullptr;
    EntropyView = nullptr;
}

void UnpackerModule::OnProcessAttached(const ProcessInfo& Info)
{
    Q_UNUSED(Info)
}

void UnpackerModule::OnProcessDetached()
{
}

void UnpackerModule::ContributeToToolBar(QToolBar* ToolBar)
{
    auto* OpenAction = new QAction(QIcon::fromTheme(QStringLiteral("document-open")),
        QStringLiteral("Open PE"), ToolBar);
    connect(OpenAction, &QAction::triggered, this, [this]() {
        if (!MainWidget)
            return;
        QString FilePath = QFileDialog::getOpenFileName(
            MainWidget,
            QStringLiteral("Open PE File"),
            QString(),
            QStringLiteral("PE Files (*.exe *.dll *.sys *.drv *.ocx);;All Files (*)"));
        if (!FilePath.isEmpty())
            MainWidget->LoadFile(FilePath);
    });
    ToolBar->addAction(OpenAction);

    auto* DumpAction = new QAction(QIcon::fromTheme(QStringLiteral("document-save")),
        QStringLiteral("Dump PE"), ToolBar);
    connect(DumpAction, &QAction::triggered, this, [this]() {
        if (MainWidget)
            MainWidget->OnDumpToFile();
    });
    ToolBar->addAction(DumpAction);

    auto* RebuildAction = new QAction(QIcon::fromTheme(QStringLiteral("view-refresh")),
        QStringLiteral("Rebuild IAT"), ToolBar);
    connect(RebuildAction, &QAction::triggered, this, [this]() {
        if (MainWidget)
            MainWidget->OnRebuildIat();
    });
    ToolBar->addAction(RebuildAction);
}

}
