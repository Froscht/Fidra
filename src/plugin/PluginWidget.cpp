#include "PluginWidget.h"
#include "PluginManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFileDialog>
#include <QDesktopServices>
#include <QUrl>
#include <QStandardPaths>
#include <QDir>
#include <QMimeData>
#include <QFileInfo>

namespace Fidra {

PluginWidget::PluginWidget(QWidget* Parent, ICore* Core)
    : QWidget(Parent)
    , CoreRef(Core)
    , Manager(new PluginManager(Core, this))
    , PluginTable(nullptr)
    , ScanButton(nullptr)
    , LoadButton(nullptr)
    , UnloadButton(nullptr)
    , OpenDirButton(nullptr)
    , StatusLabel(nullptr)
{
    setAcceptDrops(true);
    SetupUi();

    connect(Manager, &PluginManager::PluginLoaded, this, [this](const QString&) {
        RefreshTable();
    });
    connect(Manager, &PluginManager::PluginUnloaded, this, [this](const QString&) {
        RefreshTable();
    });
    connect(Manager, &PluginManager::LogMessage, this, [this](const QString& Msg) {
        if (CoreRef) CoreRef->Log(Msg);
    });

    Manager->ScanDefaultDirectories();
    RefreshTable();
}

void PluginWidget::SetupUi()
{
    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(4, 4, 4, 4);
    MainLayout->setSpacing(4);

    auto* ButtonLayout = new QHBoxLayout();
    ButtonLayout->setSpacing(4);

    ScanButton = new QPushButton(QStringLiteral("Scan Folder..."), this);
    LoadButton = new QPushButton(QStringLiteral("Load..."), this);
    UnloadButton = new QPushButton(QStringLiteral("Unload"), this);
    OpenDirButton = new QPushButton(QStringLiteral("Open Plugin Dir"), this);

    ButtonLayout->addWidget(ScanButton);
    ButtonLayout->addWidget(LoadButton);
    ButtonLayout->addWidget(UnloadButton);
    ButtonLayout->addWidget(OpenDirButton);
    ButtonLayout->addStretch();

    MainLayout->addLayout(ButtonLayout);

    PluginTable = new QTableWidget(this);
    PluginTable->setColumnCount(6);
    PluginTable->setHorizontalHeaderLabels({
        QStringLiteral("Name"),
        QStringLiteral("Version"),
        QStringLiteral("Author"),
        QStringLiteral("Description"),
        QStringLiteral("Status"),
        QStringLiteral("Path")
    });
    PluginTable->horizontalHeader()->setStretchLastSection(true);
    PluginTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    PluginTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    PluginTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    PluginTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    PluginTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    PluginTable->verticalHeader()->setVisible(false);
    PluginTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    PluginTable->setSelectionMode(QAbstractItemView::SingleSelection);
    PluginTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    PluginTable->setAlternatingRowColors(true);

    MainLayout->addWidget(PluginTable);

    StatusLabel = new QLabel(QStringLiteral("No plugins loaded"), this);
    MainLayout->addWidget(StatusLabel);

    connect(ScanButton, &QPushButton::clicked, this, &PluginWidget::OnScanFolder);
    connect(LoadButton, &QPushButton::clicked, this, &PluginWidget::OnLoadPlugin);
    connect(UnloadButton, &QPushButton::clicked, this, &PluginWidget::OnUnloadPlugin);
    connect(OpenDirButton, &QPushButton::clicked, this, &PluginWidget::OnOpenPluginDir);
}

void PluginWidget::RefreshTable()
{
    QVector<PluginInfo> Plugins = Manager->GetPlugins();
    PluginTable->setRowCount(Plugins.size());

    for (int I = 0; I < Plugins.size(); ++I) {
        const PluginInfo& Info = Plugins[I];
        PluginTable->setItem(I, 0, new QTableWidgetItem(Info.Name));
        PluginTable->setItem(I, 1, new QTableWidgetItem(Info.Version));
        PluginTable->setItem(I, 2, new QTableWidgetItem(Info.Author));
        PluginTable->setItem(I, 3, new QTableWidgetItem(Info.Description));
        PluginTable->setItem(I, 4, new QTableWidgetItem(Info.Loaded ? QStringLiteral("Loaded") : QStringLiteral("Unloaded")));
        PluginTable->setItem(I, 5, new QTableWidgetItem(Info.FilePath));
    }

    StatusLabel->setText(QStringLiteral("%1 plugin(s) loaded").arg(Plugins.size()));
}

void PluginWidget::OnScanFolder()
{
    QString Dir = QFileDialog::getExistingDirectory(this, QStringLiteral("Select Plugin Directory"));
    if (!Dir.isEmpty()) {
        Manager->ScanDirectory(Dir);
    }
}

void PluginWidget::OnLoadPlugin()
{
    QString Filter = QStringLiteral("Plugin Files (*.so);;All Files (*)");
    QString Path = QFileDialog::getOpenFileName(this, QStringLiteral("Load Plugin"), QString(), Filter);
    if (!Path.isEmpty()) {
        Manager->LoadPlugin(Path);
    }
}

void PluginWidget::OnUnloadPlugin()
{
    int Row = PluginTable->currentRow();
    if (Row < 0) return;
    auto* Item = PluginTable->item(Row, 0);
    if (Item) {
        Manager->UnloadPlugin(Item->text());
    }
}

void PluginWidget::OnOpenPluginDir()
{
    QString ConfigPath = QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation);
    QString PluginDir = ConfigPath + QStringLiteral("/fidra/plugins");
    QDir Dir(PluginDir);
    if (!Dir.exists()) {
        Dir.mkpath(PluginDir);
    }
    QDesktopServices::openUrl(QUrl::fromLocalFile(PluginDir));
}

void PluginWidget::dragEnterEvent(QDragEnterEvent* Event)
{
    if (!Event->mimeData()->hasUrls()) {
        Event->ignore();
        return;
    }

    for (const QUrl& Url : Event->mimeData()->urls()) {
        if (Url.isLocalFile() && Url.toLocalFile().endsWith(QStringLiteral(".so"))) {
            Event->acceptProposedAction();
            return;
        }
    }
    Event->ignore();
}

void PluginWidget::dragMoveEvent(QDragMoveEvent* Event)
{
    if (Event->mimeData()->hasUrls()) {
        Event->acceptProposedAction();
    }
}

void PluginWidget::dropEvent(QDropEvent* Event)
{
    if (!Event->mimeData()->hasUrls()) {
        Event->ignore();
        return;
    }

    for (const QUrl& Url : Event->mimeData()->urls()) {
        if (!Url.isLocalFile()) continue;
        QString FilePath = Url.toLocalFile();
        if (!FilePath.endsWith(QStringLiteral(".so"))) continue;

        QString ConfigPath = QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation);
        QString PluginDir = ConfigPath + QStringLiteral("/fidra/plugins");
        QDir Dir(PluginDir);
        if (!Dir.exists()) {
            Dir.mkpath(PluginDir);
        }

        QFileInfo SourceInfo(FilePath);
        QString DestPath = PluginDir + QStringLiteral("/") + SourceInfo.fileName();

        if (QFile::exists(DestPath)) {
            QFile::remove(DestPath);
        }
        QFile::copy(FilePath, DestPath);

        Manager->LoadPlugin(DestPath);
    }

    Event->acceptProposedAction();
}

}
