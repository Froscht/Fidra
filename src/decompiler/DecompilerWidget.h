#pragma once

#include <fidra/ICore.h>
#include <fidra/Types.h>
#include <QWidget>
#include <QTextEdit>
#include <QTabWidget>
#include <QPushButton>
#include <QComboBox>
#include <QCheckBox>
#include <QLabel>

namespace Fidra {

class AnalysisDatabase;

class DecompilerWidget : public QWidget {
    Q_OBJECT

public:
    explicit DecompilerWidget(QWidget* Parent = nullptr, ICore* Core = nullptr);

    void DecompileFunction(Address Addr, AnalysisDatabase* Db);
    void SetDatabase(AnalysisDatabase* Db);
    void NavigateToAddress(Address Addr);

signals:
    void StatusMessage(const QString& Msg);

private:
    void SetupUi();

    ICore* CoreRef;
    AnalysisDatabase* DbRef;

    QTabWidget* OutputTabs;
    QTextEdit* PseudoCEdit;
    QTextEdit* IrEdit;

    QPushButton* DecompileButton;
    QComboBox* OptLevelCombo;
    QCheckBox* ShowAddressesCheck;
    QCheckBox* ShowTypesCheck;
    QLabel* StatusLabel;
    QLabel* ComplexityLabel;

    Address CurrentAddr;
};

}
