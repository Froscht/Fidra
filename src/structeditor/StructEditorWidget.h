#pragma once

#include <fidra/ICore.h>
#include "StructTypes.h"
#include <QWidget>
#include <QTreeWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QTimer>
#include <QSplitter>
#include <QToolBar>
#include <QSpinBox>

namespace Fidra {

class StructEditorWidget : public QWidget {
    Q_OBJECT

public:
    explicit StructEditorWidget(QWidget* Parent, ICore* Core);
    ~StructEditorWidget() override;

    void OnProcessAttached(const ProcessInfo& Info);
    void OnProcessDetached();

private slots:
    void OnAddStruct();
    void OnDeleteStruct();
    void OnAddEnum();
    void OnAddField();
    void OnDeleteField();
    void OnStructTreeItemChanged(QTreeWidgetItem* Current, QTreeWidgetItem* Previous);
    void OnFieldCellChanged(int Row, int Column);
    void OnFieldContextMenu(const QPoint& Pos);
    void OnBaseAddressChanged();
    void OnRefreshLiveValues();
    void OnAutoRefreshToggled(bool Enabled);
    void OnRefreshIntervalChanged(int Ms);
    void OnExportJson();
    void OnImportJson();
    void OnGenerateHeader();

private:
    void SetupUi();
    void SetupToolBar();
    void RefreshStructTree();
    void RefreshFieldTable();
    void ReadLiveValues();
    QString FormatLiveValue(const StructField& Field, const uint8_t* Data, int DataSize);
    void ChangeFieldType(int Row, StructFieldType NewType);
    void InsertPaddingAtRow(int Row);
    void ConvertToArray(int Row);
    void FollowPointer(int Row);
    QStringList GetAllTypeStrings() const;
    void PopulateTypeCombo(QComboBox* Combo, StructFieldType CurrentType);
    QString GenerateHeaderText() const;
    void SortFieldsByOffset();

    ICore* CoreRef;
    TypeDatabase* Database;
    QUuid CurrentStructId;
    bool ProcessAttached;
    Address BaseAddress;
    QByteArray LiveBuffer;
    bool UpdatingTable;

    QSplitter* MainSplitter;
    QTreeWidget* StructTree;
    QTableWidget* FieldTable;
    QToolBar* ToolBar;
    QLineEdit* BaseAddressEdit;
    QPushButton* RefreshBtn;
    QSpinBox* RefreshIntervalSpin;
    QPushButton* AutoRefreshBtn;
    QLabel* StatusLabel;
    QTimer* AutoRefreshTimer;
};

}
