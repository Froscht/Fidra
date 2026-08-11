#pragma once

#include <fidra/ICore.h>
#include <QWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <QDragEnterEvent>
#include <QDropEvent>

namespace Fidra {

class PluginManager;

class PluginWidget : public QWidget {
    Q_OBJECT

public:
    explicit PluginWidget(QWidget* Parent, ICore* Core);

    PluginManager* GetManager() const { return Manager; }

protected:
    void dragEnterEvent(QDragEnterEvent* Event) override;
    void dragMoveEvent(QDragMoveEvent* Event) override;
    void dropEvent(QDropEvent* Event) override;

private:
    void SetupUi();
    void RefreshTable();
    void OnScanFolder();
    void OnLoadPlugin();
    void OnUnloadPlugin();
    void OnOpenPluginDir();

    ICore* CoreRef;
    PluginManager* Manager;
    QTableWidget* PluginTable;
    QPushButton* ScanButton;
    QPushButton* LoadButton;
    QPushButton* UnloadButton;
    QPushButton* OpenDirButton;
    QLabel* StatusLabel;
};

}
