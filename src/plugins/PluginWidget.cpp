#include "PluginWidget.h"
#include "PluginLoader.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFileDialog>
#include <QFormLayout>
#include <QSplitter>
#include <QDir>

namespace Fidra {

PluginWidget::PluginWidget(QWidget* Parent, ICore* Core)
    : QWidget(Parent)
    , CoreRef(Core)
    , Loader(new PluginLoader(Core, this))
    , PluginTable(nullptr)
    , LoadButton(nullptr)
    , UnloadButton(nullptr)
    , RefreshButton(nullptr)
    , EnableToggle(nullptr)
    , InfoGroup(nullptr)
    , InfoName(nullptr)
    , InfoVersion(nullptr)
    , InfoAuthor(nullptr)
    , InfoType(nullptr)
    , InfoDescription(nullptr)
    , InfoPath(nullptr)
    , DirEdit(nullptr)
    , BrowseButton(nullptr)
    , StatusLabel(nullptr)
{
    SetupUi();

    connect(Loader, &PluginLoader::PluginLoaded, this, [this](const QString&) {
        RefreshTable();
    });
    connect(Loader, &PluginLoader::PluginUnloaded, this, [this](const QString&) {
        RefreshTable();
    });
    connect(Loader, &PluginLoader::ErrorOccurred, this, [this](const QString& Name, const QString& Error) {
        if (CoreRef) {
            CoreRef->Log(QStringLiteral("[Plugin Error] ") + Name + QStringLiteral(": ") + Error, LogLevel::Error);
        }
    });

    Loader->ScanDefaultDirectories();
    RefreshTable();
}

void PluginWidget::SetupUi()
{
    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(4, 4, 4, 4);
    MainLayout->setSpacing(4);

    auto* DirLayout = new QHBoxLayout();
    DirLayout->setSpacing(4);
    auto* DirLabel = new QLabel(QStringLiteral("Plugin Directory:"), this);
    DirEdit = new QLineEdit(this);
    QStringList Paths = Loader->GetSearchPaths();
    if (!Paths.isEmpty()) {
        DirEdit->setText(Paths.first());
    }
    DirEdit->setReadOnly(true);
    BrowseButton = new QPushButton(QStringLiteral("Browse..."), this);
    DirLayout->addWidget(DirLabel);
    DirLayout->addWidget(DirEdit, 1);
    DirLayout->addWidget(BrowseButton);
    MainLayout->addLayout(DirLayout);

    auto* ButtonLayout = new QHBoxLayout();
    ButtonLayout->setSpacing(4);

    LoadButton = new QPushButton(QStringLiteral("Load Plugin..."), this);
    UnloadButton = new QPushButton(QStringLiteral("Unload Plugin"), this);
    RefreshButton = new QPushButton(QStringLiteral("Refresh"), this);
    EnableToggle = new QCheckBox(QStringLiteral("Enabled"), this);
    EnableToggle->setEnabled(false);

    ButtonLayout->addWidget(LoadButton);
    ButtonLayout->addWidget(UnloadButton);
    ButtonLayout->addWidget(RefreshButton);
    ButtonLayout->addWidget(EnableToggle);
    ButtonLayout->addStretch();

    MainLayout->addLayout(ButtonLayout);

    auto* Splitter = new QSplitter(Qt::Vertical, this);

    PluginTable = new QTableWidget(this);
    PluginTable->setColumnCount(6);
    PluginTable->setHorizontalHeaderLabels({
        QStringLiteral("Name"),
        QStringLiteral("Version"),
        QStringLiteral("Author"),
        QStringLiteral("Type"),
        QStringLiteral("Status"),
        QStringLiteral("Path")
    });
    PluginTable->horizontalHeader()->setStretchLastSection(true);
    PluginTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    PluginTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    PluginTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    PluginTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    PluginTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    PluginTable->verticalHeader()->setVisible(false);
    PluginTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    PluginTable->setSelectionMode(QAbstractItemView::SingleSelection);
    PluginTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    PluginTable->setAlternatingRowColors(true);

    Splitter->addWidget(PluginTable);

    InfoGroup = new QGroupBox(QStringLiteral("Plugin Details"), this);
    auto* InfoLayout = new QFormLayout(InfoGroup);
    InfoLayout->setContentsMargins(8, 8, 8, 8);
    InfoLayout->setSpacing(4);

    InfoName = new QLabel(QStringLiteral("-"), InfoGroup);
    InfoVersion = new QLabel(QStringLiteral("-"), InfoGroup);
    InfoAuthor = new QLabel(QStringLiteral("-"), InfoGroup);
    InfoType = new QLabel(QStringLiteral("-"), InfoGroup);
    InfoDescription = new QLabel(QStringLiteral("-"), InfoGroup);
    InfoDescription->setWordWrap(true);
    InfoPath = new QLabel(QStringLiteral("-"), InfoGroup);
    InfoPath->setWordWrap(true);

    InfoLayout->addRow(QStringLiteral("Name:"), InfoName);
    InfoLayout->addRow(QStringLiteral("Version:"), InfoVersion);
    InfoLayout->addRow(QStringLiteral("Author:"), InfoAuthor);
    InfoLayout->addRow(QStringLiteral("Type:"), InfoType);
    InfoLayout->addRow(QStringLiteral("Description:"), InfoDescription);
    InfoLayout->addRow(QStringLiteral("File Path:"), InfoPath);

    Splitter->addWidget(InfoGroup);
    Splitter->setStretchFactor(0, 3);
    Splitter->setStretchFactor(1, 1);

    MainLayout->addWidget(Splitter, 1);

    StatusLabel = new QLabel(QStringLiteral("No plugins loaded"), this);
    MainLayout->addWidget(StatusLabel);

    connect(LoadButton, &QPushButton::clicked, this, &PluginWidget::OnLoadPlugin);
    connect(UnloadButton, &QPushButton::clicked, this, &PluginWidget::OnUnloadPlugin);
    connect(RefreshButton, &QPushButton::clicked, this, &PluginWidget::OnRefreshScan);
    connect(BrowseButton, &QPushButton::clicked, this, &PluginWidget::OnBrowseDirectory);
    connect(EnableToggle, &QCheckBox::toggled, this, &PluginWidget::OnToggleEnabled);
    connect(PluginTable, &QTableWidget::currentCellChanged, this, [this](int Row, int, int, int) {
        UpdateInfoPanel(Row);
    });
}

void PluginWidget::RefreshTable()
{
    QVector<PluginInfo> LoadedList = Loader->GetLoadedPlugins();
    PluginTable->setRowCount(LoadedList.size());

    for (int I = 0; I < LoadedList.size(); ++I) {
        const PluginInfo& Info = LoadedList[I];
        PluginTable->setItem(I, 0, new QTableWidgetItem(Info.Name));
        PluginTable->setItem(I, 1, new QTableWidgetItem(Info.Version));
        PluginTable->setItem(I, 2, new QTableWidgetItem(Info.Author));
        PluginTable->setItem(I, 3, new QTableWidgetItem(PluginTypeString(static_cast<int>(Info.Type))));

        QString StatusText;
        if (Info.IsLoaded && Info.Enabled) {
            StatusText = QStringLiteral("Active");
        } else if (Info.IsLoaded && !Info.Enabled) {
            StatusText = QStringLiteral("Disabled");
        } else {
            StatusText = QStringLiteral("Unloaded");
        }
        PluginTable->setItem(I, 4, new QTableWidgetItem(StatusText));
        PluginTable->setItem(I, 5, new QTableWidgetItem(Info.FilePath));
    }

    StatusLabel->setText(QStringLiteral("%1 plugin(s) loaded").arg(LoadedList.size()));

    int CurrentRow = PluginTable->currentRow();
    UpdateInfoPanel(CurrentRow);
}

void PluginWidget::OnLoadPlugin()
{
    QString Filter = QStringLiteral("Plugin Files (*.so);;All Files (*)");
    QString Path = QFileDialog::getOpenFileName(this, QStringLiteral("Load Plugin"), QString(), Filter);
    if (!Path.isEmpty()) {
        Loader->LoadPlugin(Path);
    }
}

void PluginWidget::OnUnloadPlugin()
{
    int Row = PluginTable->currentRow();
    if (Row < 0) return;
    auto* Item = PluginTable->item(Row, 0);
    if (Item) {
        Loader->UnloadPlugin(Item->text());
    }
}

void PluginWidget::OnRefreshScan()
{
    QStringList Paths = Loader->GetSearchPaths();
    for (const QString& Dir : Paths) {
        QDir Directory(Dir);
        if (Directory.exists()) {
            QStringList Found = Loader->ScanDirectory(Dir);
            for (const QString& PluginPath : Found) {
                Loader->LoadPlugin(PluginPath);
            }
        }
    }
    RefreshTable();
}

void PluginWidget::OnBrowseDirectory()
{
    QString Dir = QFileDialog::getExistingDirectory(this, QStringLiteral("Select Plugin Directory"));
    if (!Dir.isEmpty()) {
        Loader->AddSearchPath(Dir);
        DirEdit->setText(Dir);
        QStringList Found = Loader->ScanDirectory(Dir);
        for (const QString& PluginPath : Found) {
            Loader->LoadPlugin(PluginPath);
        }
        RefreshTable();
    }
}

void PluginWidget::OnSelectionChanged()
{
    int Row = PluginTable->currentRow();
    UpdateInfoPanel(Row);
}

void PluginWidget::OnToggleEnabled()
{
    int Row = PluginTable->currentRow();
    if (Row < 0) return;
    auto* Item = PluginTable->item(Row, 0);
    if (Item) {
        Loader->SetPluginEnabled(Item->text(), EnableToggle->isChecked());
        RefreshTable();
    }
}

void PluginWidget::UpdateInfoPanel(int Row)
{
    QVector<PluginInfo> LoadedList = Loader->GetLoadedPlugins();

    if (Row < 0 || Row >= LoadedList.size()) {
        InfoName->setText(QStringLiteral("-"));
        InfoVersion->setText(QStringLiteral("-"));
        InfoAuthor->setText(QStringLiteral("-"));
        InfoType->setText(QStringLiteral("-"));
        InfoDescription->setText(QStringLiteral("-"));
        InfoPath->setText(QStringLiteral("-"));
        EnableToggle->setEnabled(false);
        EnableToggle->setChecked(false);
        return;
    }

    const PluginInfo& Info = LoadedList[Row];
    InfoName->setText(Info.Name);
    InfoVersion->setText(Info.Version);
    InfoAuthor->setText(Info.Author);
    InfoType->setText(PluginTypeString(static_cast<int>(Info.Type)));
    InfoDescription->setText(Info.Description);
    InfoPath->setText(Info.FilePath);

    EnableToggle->setEnabled(true);
    EnableToggle->blockSignals(true);
    EnableToggle->setChecked(Info.Enabled);
    EnableToggle->blockSignals(false);
}

QString PluginWidget::PluginTypeString(int TypeValue) const
{
    switch (static_cast<PluginType>(TypeValue)) {
        case PluginType::Analysis: return QStringLiteral("Analysis");
        case PluginType::UI: return QStringLiteral("UI");
        case PluginType::Import: return QStringLiteral("Import");
        case PluginType::Export: return QStringLiteral("Export");
        case PluginType::Custom: return QStringLiteral("Custom");
    }
    return QStringLiteral("Unknown");
}

}
