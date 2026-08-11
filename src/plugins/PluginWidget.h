#pragma once

#include <fidra/ICore.h>
#include <QWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QCheckBox>

namespace Fidra {

class PluginLoader;

class PluginWidget : public QWidget {
    Q_OBJECT

public:
    explicit PluginWidget(QWidget* Parent, ICore* Core);

    PluginLoader* GetLoader() const { return Loader; }

private:
    void SetupUi();
    void RefreshTable();
    void OnLoadPlugin();
    void OnUnloadPlugin();
    void OnRefreshScan();
    void OnBrowseDirectory();
    void OnSelectionChanged();
    void OnToggleEnabled();
    void UpdateInfoPanel(int Row);
    QString PluginTypeString(int TypeValue) const;

    ICore* CoreRef;
    PluginLoader* Loader;

    QTableWidget* PluginTable;
    QPushButton* LoadButton;
    QPushButton* UnloadButton;
    QPushButton* RefreshButton;
    QCheckBox* EnableToggle;

    QGroupBox* InfoGroup;
    QLabel* InfoName;
    QLabel* InfoVersion;
    QLabel* InfoAuthor;
    QLabel* InfoType;
    QLabel* InfoDescription;
    QLabel* InfoPath;

    QLineEdit* DirEdit;
    QPushButton* BrowseButton;
    QLabel* StatusLabel;
};

}
