#include "ProjectWidget.h"
#include "ProjectManager.h"
#include "../analysis/AnalysisDatabase.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFileDialog>
#include <QMessageBox>
#include <QSettings>

namespace Fidra {

ProjectWidget::ProjectWidget(QWidget* Parent, ICore* Core, ProjectManager* Manager, AnalysisDatabase* Db)
    : QWidget(Parent)
    , CoreRef(Core)
    , ManagerRef(Manager)
    , DbRef(Db)
    , ProjectNameLabel(nullptr)
    , BinaryPathLabel(nullptr)
    , LastSavedLabel(nullptr)
    , VersionLabel(nullptr)
    , StatusLabel(nullptr)
    , SaveBtn(nullptr)
    , LoadBtn(nullptr)
    , ExportBtn(nullptr)
    , ImportBtn(nullptr)
    , AutoSaveCheck(nullptr)
    , RecentList(nullptr)
{
    SetupUi();
    LoadRecentProjects();
    UpdateProjectInfo();

    connect(ManagerRef, &ProjectManager::ProjectSaved, this, &ProjectWidget::OnProjectSaved);
    connect(ManagerRef, &ProjectManager::ProjectLoaded, this, &ProjectWidget::OnProjectLoaded);
    connect(ManagerRef, &ProjectManager::ProjectError, this, &ProjectWidget::OnProjectError);
}

ProjectWidget::~ProjectWidget() = default;

ProjectManager* ProjectWidget::GetManager() const
{
    return ManagerRef;
}

void ProjectWidget::SetDatabase(AnalysisDatabase* Db)
{
    DbRef = Db;
}

void ProjectWidget::OnSave()
{
    if (ManagerRef->IsProjectLoaded()) {
        StatusLabel->setText(QStringLiteral("Saving..."));
        ManagerRef->SaveProject(ManagerRef->CurrentProjectPath());
    } else {
        OnSaveAs();
    }
}

void ProjectWidget::OnSaveAs()
{
    OnSaveProject();
}

void ProjectWidget::OnLoad()
{
    OnLoadProject();
}

void ProjectWidget::OnAnalysisComplete()
{
    UpdateProjectInfo();
}

void ProjectWidget::SetupUi()
{
    QVBoxLayout* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(8, 8, 8, 8);
    MainLayout->setSpacing(8);

    QGroupBox* InfoGroup = new QGroupBox(QStringLiteral("Project Info"), this);
    QVBoxLayout* InfoLayout = new QVBoxLayout(InfoGroup);

    ProjectNameLabel = new QLabel(QStringLiteral("Name: (none)"), this);
    BinaryPathLabel = new QLabel(QStringLiteral("Binary: (none)"), this);
    LastSavedLabel = new QLabel(QStringLiteral("Last Saved: (never)"), this);
    VersionLabel = new QLabel(QStringLiteral("Version: -"), this);

    ProjectNameLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    BinaryPathLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    BinaryPathLabel->setWordWrap(true);

    InfoLayout->addWidget(ProjectNameLabel);
    InfoLayout->addWidget(BinaryPathLabel);
    InfoLayout->addWidget(LastSavedLabel);
    InfoLayout->addWidget(VersionLabel);
    MainLayout->addWidget(InfoGroup);

    QGroupBox* ActionsGroup = new QGroupBox(QStringLiteral("Actions"), this);
    QVBoxLayout* ActionsLayout = new QVBoxLayout(ActionsGroup);

    QHBoxLayout* Row1 = new QHBoxLayout();
    SaveBtn = new QPushButton(QStringLiteral("Save Project"), this);
    LoadBtn = new QPushButton(QStringLiteral("Load Project"), this);
    Row1->addWidget(SaveBtn);
    Row1->addWidget(LoadBtn);
    ActionsLayout->addLayout(Row1);

    QHBoxLayout* Row2 = new QHBoxLayout();
    ExportBtn = new QPushButton(QStringLiteral("Export JSON"), this);
    ImportBtn = new QPushButton(QStringLiteral("Import JSON"), this);
    Row2->addWidget(ExportBtn);
    Row2->addWidget(ImportBtn);
    ActionsLayout->addLayout(Row2);

    AutoSaveCheck = new QCheckBox(QStringLiteral("Auto-save every 5 minutes"), this);
    ActionsLayout->addWidget(AutoSaveCheck);

    MainLayout->addWidget(ActionsGroup);

    QGroupBox* RecentGroup = new QGroupBox(QStringLiteral("Recent Projects"), this);
    QVBoxLayout* RecentLayout = new QVBoxLayout(RecentGroup);
    RecentList = new QListWidget(this);
    RecentList->setMaximumHeight(200);
    RecentLayout->addWidget(RecentList);
    MainLayout->addWidget(RecentGroup);

    StatusLabel = new QLabel(this);
    StatusLabel->setStyleSheet(QStringLiteral("QLabel { color: #888; font-style: italic; }"));
    MainLayout->addWidget(StatusLabel);

    MainLayout->addStretch();

    connect(SaveBtn, &QPushButton::clicked, this, &ProjectWidget::OnSaveProject);
    connect(LoadBtn, &QPushButton::clicked, this, &ProjectWidget::OnLoadProject);
    connect(ExportBtn, &QPushButton::clicked, this, &ProjectWidget::OnExportDatabase);
    connect(ImportBtn, &QPushButton::clicked, this, &ProjectWidget::OnImportDatabase);
    connect(AutoSaveCheck, &QCheckBox::toggled, this, &ProjectWidget::OnAutoSaveToggled);
    connect(RecentList, &QListWidget::itemDoubleClicked, this, &ProjectWidget::OnRecentProjectClicked);
}

void ProjectWidget::UpdateProjectInfo()
{
    if (ManagerRef->IsProjectLoaded()) {
        ProjectInfo PInfo = ManagerRef->GetProjectInfo();
        ProjectNameLabel->setText(QStringLiteral("Name: %1").arg(PInfo.Name));
        BinaryPathLabel->setText(QStringLiteral("Binary: %1").arg(PInfo.BinaryPath));
        LastSavedLabel->setText(QStringLiteral("Last Saved: %1").arg(PInfo.LastModified));
        VersionLabel->setText(QStringLiteral("Version: %1").arg(PInfo.Version));
    } else {
        ProjectNameLabel->setText(QStringLiteral("Name: (none)"));
        BinaryPathLabel->setText(QStringLiteral("Binary: (none)"));
        LastSavedLabel->setText(QStringLiteral("Last Saved: (never)"));
        VersionLabel->setText(QStringLiteral("Version: -"));
    }
}

void ProjectWidget::LoadRecentProjects()
{
    RecentPaths.clear();
    RecentList->clear();

    if (CoreRef && CoreRef->Settings()) {
        QSettings* Settings = CoreRef->Settings();
        int Count = Settings->beginReadArray(QStringLiteral("recent_projects"));
        for (int I = 0; I < Count; ++I) {
            Settings->setArrayIndex(I);
            QString Path = Settings->value(QStringLiteral("path")).toString();
            if (!Path.isEmpty()) {
                RecentPaths.append(Path);
                QFileInfo Fi(Path);
                RecentList->addItem(QStringLiteral("%1 - %2").arg(Fi.baseName(), Fi.absoluteFilePath()));
            }
        }
        Settings->endArray();
    }
}

void ProjectWidget::AddRecentProject(const QString& Path)
{
    RecentPaths.removeAll(Path);
    RecentPaths.prepend(Path);
    while (RecentPaths.size() > 10) {
        RecentPaths.removeLast();
    }
    SaveRecentProjects();

    RecentList->clear();
    for (const QString& P : RecentPaths) {
        QFileInfo Fi(P);
        RecentList->addItem(QStringLiteral("%1 - %2").arg(Fi.baseName(), Fi.absoluteFilePath()));
    }
}

void ProjectWidget::SaveRecentProjects()
{
    if (!CoreRef || !CoreRef->Settings()) {
        return;
    }

    QSettings* Settings = CoreRef->Settings();
    Settings->beginWriteArray(QStringLiteral("recent_projects"), RecentPaths.size());
    for (int I = 0; I < RecentPaths.size(); ++I) {
        Settings->setArrayIndex(I);
        Settings->setValue(QStringLiteral("path"), RecentPaths[I]);
    }
    Settings->endArray();
}

void ProjectWidget::OnSaveProject()
{
    QString DefaultPath;
    if (ManagerRef->IsProjectLoaded()) {
        DefaultPath = ManagerRef->CurrentProjectPath();
    }

    QString Path = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("Save Fidra Project"),
        DefaultPath,
        QStringLiteral("Fidra Projects (*.fidra);;All Files (*)")
    );

    if (Path.isEmpty()) {
        return;
    }

    if (!Path.endsWith(QStringLiteral(".fidra"), Qt::CaseInsensitive)) {
        Path += QStringLiteral(".fidra");
    }

    StatusLabel->setText(QStringLiteral("Saving..."));
    ManagerRef->SaveProject(Path);
}

void ProjectWidget::OnLoadProject()
{
    QString Path = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("Load Fidra Project"),
        QString(),
        QStringLiteral("Fidra Projects (*.fidra);;All Files (*)")
    );

    if (Path.isEmpty()) {
        return;
    }

    StatusLabel->setText(QStringLiteral("Loading..."));
    ManagerRef->LoadProject(Path);
}

void ProjectWidget::OnExportDatabase()
{
    QString Path = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("Export Database"),
        QString(),
        QStringLiteral("JSON Files (*.json);;All Files (*)")
    );

    if (Path.isEmpty()) {
        return;
    }

    StatusLabel->setText(QStringLiteral("Exporting..."));
    if (ManagerRef->ExportDatabase(Path)) {
        StatusLabel->setText(QStringLiteral("Database exported successfully"));
    }
}

void ProjectWidget::OnImportDatabase()
{
    QString Path = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("Import Database"),
        QString(),
        QStringLiteral("JSON Files (*.json);;All Files (*)")
    );

    if (Path.isEmpty()) {
        return;
    }

    StatusLabel->setText(QStringLiteral("Importing..."));
    if (ManagerRef->ImportDatabase(Path)) {
        StatusLabel->setText(QStringLiteral("Database imported successfully"));
        UpdateProjectInfo();
    }
}

void ProjectWidget::OnRecentProjectClicked(QListWidgetItem* Item)
{
    int Row = RecentList->row(Item);
    if (Row >= 0 && Row < RecentPaths.size()) {
        QString Path = RecentPaths[Row];
        if (QFile::exists(Path)) {
            StatusLabel->setText(QStringLiteral("Loading..."));
            ManagerRef->LoadProject(Path);
        } else {
            StatusLabel->setText(QStringLiteral("File not found: %1").arg(Path));
            RecentPaths.removeAt(Row);
            SaveRecentProjects();
            delete RecentList->takeItem(Row);
        }
    }
}

void ProjectWidget::OnAutoSaveToggled(bool Checked)
{
    if (Checked) {
        ManagerRef->StartAutoSave();
        StatusLabel->setText(QStringLiteral("Auto-save enabled"));
    } else {
        ManagerRef->StopAutoSave();
        StatusLabel->setText(QStringLiteral("Auto-save disabled"));
    }
}

void ProjectWidget::OnProjectSaved(const QString& Path)
{
    StatusLabel->setText(QStringLiteral("Project saved: %1").arg(QFileInfo(Path).fileName()));
    AddRecentProject(Path);
    UpdateProjectInfo();
}

void ProjectWidget::OnProjectLoaded(const QString& Path)
{
    StatusLabel->setText(QStringLiteral("Project loaded: %1").arg(QFileInfo(Path).fileName()));
    AddRecentProject(Path);
    UpdateProjectInfo();
}

void ProjectWidget::OnProjectError(const QString& Error)
{
    StatusLabel->setText(QStringLiteral("Error: %1").arg(Error));
    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Project error: %1").arg(Error), LogLevel::Error);
    }
}

void ProjectWidget::OnProcessAttached(const ProcessInfo& Info)
{
    Q_UNUSED(Info);
    SaveBtn->setEnabled(true);
    ExportBtn->setEnabled(true);
}

void ProjectWidget::OnProcessDetached()
{
    SaveBtn->setEnabled(true);
    ExportBtn->setEnabled(true);
}

}
