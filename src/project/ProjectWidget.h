#pragma once

#include <fidra/ICore.h>
#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QListWidget>
#include <QFileInfo>

namespace Fidra {

class ProjectManager;
class AnalysisDatabase;

class ProjectWidget : public QWidget {
    Q_OBJECT

public:
    explicit ProjectWidget(QWidget* Parent, ICore* Core, ProjectManager* Manager, AnalysisDatabase* Db);
    ~ProjectWidget() override;

    ProjectManager* GetManager() const;
    void SetDatabase(AnalysisDatabase* Db);

    void OnSave();
    void OnSaveAs();
    void OnLoad();
    void OnAnalysisComplete();

    void OnProcessAttached(const ProcessInfo& Info);
    void OnProcessDetached();

private slots:
    void OnSaveProject();
    void OnLoadProject();
    void OnExportDatabase();
    void OnImportDatabase();
    void OnRecentProjectClicked(QListWidgetItem* Item);
    void OnAutoSaveToggled(bool Checked);
    void OnProjectSaved(const QString& Path);
    void OnProjectLoaded(const QString& Path);
    void OnProjectError(const QString& Error);

private:
    void SetupUi();
    void UpdateProjectInfo();
    void LoadRecentProjects();
    void AddRecentProject(const QString& Path);
    void SaveRecentProjects();

    ICore* CoreRef;
    ProjectManager* ManagerRef;
    AnalysisDatabase* DbRef;

    QLabel* ProjectNameLabel;
    QLabel* BinaryPathLabel;
    QLabel* LastSavedLabel;
    QLabel* VersionLabel;
    QLabel* StatusLabel;

    QPushButton* SaveBtn;
    QPushButton* LoadBtn;
    QPushButton* ExportBtn;
    QPushButton* ImportBtn;

    QCheckBox* AutoSaveCheck;
    QListWidget* RecentList;

    QStringList RecentPaths;
};

}
