#pragma once

#include <QWidget>
#include <QTabWidget>
#include <QTreeWidget>
#include <QTableWidget>
#include <QToolBar>
#include <QVBoxLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QHeaderView>
#include <QTreeWidgetItem>
#include <QTableWidgetItem>
#include <QAction>
#include <memory>

#include "PeParser.h"

namespace Fidra {

class ICore;
class IatRebuilder;

class UnpackerWidget : public QWidget {
    Q_OBJECT

public:
    explicit UnpackerWidget(QWidget* Parent = nullptr);
    ~UnpackerWidget() override;

    void SetCore(ICore* Core);
    void LoadFile(const QString& FilePath);
    void LoadFromMemory(const QByteArray& Data, const QString& Name);

public slots:
    void OnOpenFile();
    void OnDumpToFile();
    void OnRebuildIat();

private:
    void SetupUi();
    void CreateToolBar();
    void PopulateHeaders();
    void PopulateSections();
    void PopulateImports();
    void PopulateExports();
    void PopulateResources();
    void PopulateTlsCallbacks();
    void PopulateRichHeader();
    void ClearAll();

    QString FormatHex(uint64_t Value, int Width = 8);
    void AddHeaderField(QTreeWidgetItem* Parent, const QString& Field, const QString& Value, const QString& Desc = {});

    ICore* CoreRef;
    QTabWidget* TabWidget;
    QToolBar* ToolBar;

    QTreeWidget* HeadersTree;
    QTableWidget* SectionsTable;
    QTreeWidget* ImportsTree;
    QTableWidget* ExportsTable;
    QTreeWidget* ResourcesTree;
    QTreeWidget* TlsTree;
    QTreeWidget* RichTree;

    std::unique_ptr<PeParser> Parser;
    std::unique_ptr<IatRebuilder> Rebuilder;
    QString CurrentFilePath;
};

}
