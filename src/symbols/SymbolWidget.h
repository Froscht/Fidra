#pragma once

#include <fidra/ICore.h>
#include "SymbolResolver.h"
#include <QWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>

namespace Fidra {

class AnalysisDatabase;

class SymbolWidget : public QWidget {
    Q_OBJECT

public:
    explicit SymbolWidget(QWidget* Parent, SymbolResolver* Resolver, ICore* Core);

    void SetDatabase(AnalysisDatabase* Db);
    void RefreshTable();

private:
    void SetupUi();
    void OnLoadSymFile();
    void OnFetchSymbols();
    void OnExportSymbols();
    void OnSetServer();
    void OnTestConnection();
    void OnFilterChanged(const QString& Text);
    void UpdateStats();

    ICore* CoreRef;
    SymbolResolver* ResolverRef;
    AnalysisDatabase* DatabaseRef;

    QTableWidget* SymbolTable;
    QPushButton* LoadButton;
    QPushButton* FetchButton;
    QPushButton* ExportButton;
    QPushButton* SetServerButton;
    QPushButton* TestButton;
    QLineEdit* FilterEdit;
    QLineEdit* ServerUrlEdit;
    QLabel* StatsLabel;
};

}
