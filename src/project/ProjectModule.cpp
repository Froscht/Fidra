#include "ProjectModule.h"
#include "ProjectWidget.h"
#include "ProjectManager.h"
#include "../analysis/AnalysisDatabase.h"
#include <QStyle>
#include <QApplication>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QFileDialog>
#include <QSettings>
#include <QFileInfo>

namespace Fidra {

ProjectModule::ProjectModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , MainWidget(nullptr)
    , Manager(nullptr)
    , Db(nullptr)
    , RecentMenu(nullptr)
{
}

ProjectModule::~ProjectModule() = default;

QString ProjectModule::Name() const
{
    return QStringLiteral("Project");
}

QString ProjectModule::Description() const
{
    return QStringLiteral("Project save/load manager for Fidra analysis state");
}

QIcon ProjectModule::Icon() const
{
    return QApplication::style()->standardIcon(QStyle::SP_DirIcon);
}

int ProjectModule::Priority() const
{
    return 5;
}

QWidget* ProjectModule::CreateMainWidget(QWidget* Parent)
{
    if (!Db) {
        Db = new AnalysisDatabase(this);
    }
    MainWidget = new ProjectWidget(Parent, CoreRef, Manager, Db);
    return MainWidget;
}

QList<QPair<QString, QWidget*>> ProjectModule::CreateDockWidgets(QWidget* Parent)
{
    Q_UNUSED(Parent);
    return {};
}

void ProjectModule::Initialize(ICore* Core)
{
    CoreRef = Core;
    Manager = new ProjectManager(this);
    Manager->SetCore(Core);
    Db = new AnalysisDatabase(this);
    Manager->SetDatabase(Db);
    CoreRef->Log(QStringLiteral("Project module initialized"));
}

void ProjectModule::Shutdown()
{
    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Project module shutdown"));
    }
}

void ProjectModule::OnProcessAttached(const ProcessInfo& Info)
{
    if (MainWidget) {
        MainWidget->OnProcessAttached(Info);
    }
}

void ProjectModule::OnProcessDetached()
{
    if (MainWidget) {
        MainWidget->OnProcessDetached();
    }
}

void ProjectModule::OnAnalysisComplete(AnalysisDatabase* AnalysisDb, Address EntryPoint)
{
    Q_UNUSED(EntryPoint);
    if (AnalysisDb) {
        Db = AnalysisDb;
        if (Manager) Manager->SetDatabase(Db);
    }
}

void ProjectModule::ContributeToMenu(QMenuBar* MenuBar)
{
    QMenu* FileMenu = nullptr;
    for (QAction* Action : MenuBar->actions()) {
        if (Action->text().remove(QLatin1Char('&')) == QStringLiteral("File")) {
            FileMenu = Action->menu();
            break;
        }
    }

    if (!FileMenu) {
        FileMenu = MenuBar->addMenu(QStringLiteral("&File"));
    }

    QAction* FirstAction = nullptr;
    if (!FileMenu->actions().isEmpty()) {
        FirstAction = FileMenu->actions().first();
    }

    QAction* SaveAction = new QAction(QStringLiteral("Save Project"), this);
    SaveAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+S")));
    connect(SaveAction, &QAction::triggered, this, [this]() {
        if (!Manager) return;
        if (Manager->IsProjectLoaded()) {
            Manager->SaveProject(Manager->CurrentProjectPath());
        } else {
            QString Path = QFileDialog::getSaveFileName(
                nullptr,
                QStringLiteral("Save Fidra Project"),
                QString(),
                QStringLiteral("Fidra Projects (*.fidra);;All Files (*)")
            );
            if (!Path.isEmpty()) {
                if (!Path.endsWith(QStringLiteral(".fidra"), Qt::CaseInsensitive))
                    Path += QStringLiteral(".fidra");
                Manager->SaveProject(Path);
            }
        }
    });

    QAction* LoadAction = new QAction(QStringLiteral("Load Project"), this);
    LoadAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+O")));
    connect(LoadAction, &QAction::triggered, this, [this]() {
        if (!Manager) return;
        QString Path = QFileDialog::getOpenFileName(
            nullptr,
            QStringLiteral("Load Fidra Project"),
            QString(),
            QStringLiteral("Fidra Projects (*.fidra);;All Files (*)")
        );
        if (!Path.isEmpty()) {
            Manager->LoadProject(Path);
        }
    });

    RecentMenu = new QMenu(QStringLiteral("Recent Projects"), FileMenu);
    BuildRecentProjectsMenu();

    if (FirstAction) {
        FileMenu->insertAction(FirstAction, SaveAction);
        FileMenu->insertAction(FirstAction, LoadAction);
        FileMenu->insertMenu(FirstAction, RecentMenu);
        FileMenu->insertSeparator(FirstAction);
    } else {
        FileMenu->addAction(SaveAction);
        FileMenu->addAction(LoadAction);
        FileMenu->addMenu(RecentMenu);
        FileMenu->addSeparator();
    }

    if (Manager) {
        connect(Manager, &ProjectManager::ProjectSaved, this, [this](const QString&) {
            BuildRecentProjectsMenu();
        });
        connect(Manager, &ProjectManager::ProjectLoaded, this, [this](const QString&) {
            BuildRecentProjectsMenu();
        });
    }
}

void ProjectModule::BuildRecentProjectsMenu()
{
    if (!RecentMenu) return;
    RecentMenu->clear();

    QStringList RecentPaths;
    if (CoreRef && CoreRef->Settings()) {
        QSettings* Settings = CoreRef->Settings();
        int Count = Settings->beginReadArray(QStringLiteral("recent_projects"));
        for (int I = 0; I < Count; ++I) {
            Settings->setArrayIndex(I);
            QString Path = Settings->value(QStringLiteral("path")).toString();
            if (!Path.isEmpty()) {
                RecentPaths.append(Path);
            }
        }
        Settings->endArray();
    }

    if (RecentPaths.isEmpty()) {
        QAction* EmptyAction = RecentMenu->addAction(QStringLiteral("(No recent projects)"));
        EmptyAction->setEnabled(false);
        return;
    }

    for (const QString& Path : RecentPaths) {
        QFileInfo Fi(Path);
        QAction* Action = RecentMenu->addAction(
            QStringLiteral("%1 - %2").arg(Fi.baseName(), Fi.absoluteFilePath())
        );
        connect(Action, &QAction::triggered, this, [this, Path]() {
            if (Manager && QFile::exists(Path)) {
                Manager->LoadProject(Path);
            }
        });
    }

    RecentMenu->addSeparator();
    QAction* ClearAction = RecentMenu->addAction(QStringLiteral("Clear Recent Projects"));
    connect(ClearAction, &QAction::triggered, this, [this]() {
        if (CoreRef && CoreRef->Settings()) {
            CoreRef->Settings()->remove(QStringLiteral("recent_projects"));
        }
        BuildRecentProjectsMenu();
    });
}

ProjectManager* ProjectModule::GetProjectManager() const
{
    return Manager;
}

}
