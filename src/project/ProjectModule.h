#pragma once

#include <fidra/IModule.h>

namespace Fidra {

class ProjectWidget;
class ProjectManager;
class AnalysisDatabase;

class ProjectModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit ProjectModule(QObject* Parent = nullptr);
    ~ProjectModule() override;

    QString Name() const override;
    QString Description() const override;
    QIcon Icon() const override;
    int Priority() const override;

    QWidget* CreateMainWidget(QWidget* Parent) override;
    QList<QPair<QString, QWidget*>> CreateDockWidgets(QWidget* Parent) override;

    void Initialize(ICore* Core) override;
    void Shutdown() override;

    void ContributeToMenu(QMenuBar* MenuBar) override;

    void OnProcessAttached(const ProcessInfo& Info) override;
    void OnProcessDetached() override;
    void OnAnalysisComplete(AnalysisDatabase* Db, Address EntryPoint) override;

    ProjectManager* GetProjectManager() const;

private:
    void BuildRecentProjectsMenu();

    ICore* CoreRef;
    ProjectWidget* MainWidget;
    ProjectManager* Manager;
    AnalysisDatabase* Db;
    QMenu* RecentMenu;
};

}
