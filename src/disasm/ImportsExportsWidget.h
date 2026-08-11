#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QTabWidget>
#include <QTreeWidget>
#include <QLineEdit>

namespace Fidra {

class AnalysisDatabase;

class ImportsExportsWidget : public QWidget {
    Q_OBJECT

public:
    explicit ImportsExportsWidget(QWidget* Parent = nullptr);
    ~ImportsExportsWidget() override;

    void LoadFromDatabase(AnalysisDatabase* Db);

signals:
    void NavigateToAddress(Address Addr);

private slots:
    void OnImportDoubleClicked(QTreeWidgetItem* Item, int Column);
    void OnExportDoubleClicked(QTreeWidgetItem* Item, int Column);
    void OnFilterChanged(const QString& Text);

private:
    void PopulateImports(AnalysisDatabase* Db);
    void PopulateExports(AnalysisDatabase* Db);
    void FilterImports(const QString& Text);
    void FilterExports(const QString& Text);

    QTabWidget* TabWidget;
    QTreeWidget* ImportsTree;
    QTreeWidget* ExportsTree;
    QLineEdit* FilterInput;
    int TotalImportCount;
    int TotalExportCount;
};

}
