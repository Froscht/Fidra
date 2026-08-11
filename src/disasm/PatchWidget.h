#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QTreeWidget>
#include <QToolBar>
#include <QDialog>
#include <QLineEdit>
#include <QTextEdit>
#include <QSpinBox>
#include <QLabel>
#include <QDialogButtonBox>

namespace Fidra {

class AnalysisDatabase;
class PatchEngine;

class PatchBytesDialog : public QDialog {
    Q_OBJECT

public:
    explicit PatchBytesDialog(QWidget* Parent = nullptr);

    Address GetAddress() const;
    QByteArray GetBytes() const;
    QString GetDescription() const;

    void SetAddress(Address Addr);

private:
    QLineEdit* AddressEdit;
    QLineEdit* BytesEdit;
    QLineEdit* DescEdit;
};

class NopOutDialog : public QDialog {
    Q_OBJECT

public:
    explicit NopOutDialog(QWidget* Parent = nullptr);

    Address GetAddress() const;
    int GetSize() const;

    void SetAddress(Address Addr);

private:
    QLineEdit* AddressEdit;
    QSpinBox* SizeBox;
};

class AssembleDialog : public QDialog {
    Q_OBJECT

public:
    explicit AssembleDialog(PatchEngine* Engine, QWidget* Parent = nullptr);

    Address GetAddress() const;
    QByteArray GetAssembledBytes() const;
    QString GetDescription() const;

    void SetAddress(Address Addr);

private slots:
    void OnAssemble();

private:
    PatchEngine* EnginePtr;
    QLineEdit* AddressEdit;
    QTextEdit* AsmEdit;
    QLabel* PreviewLabel;
    QLineEdit* DescEdit;
    QByteArray AssembledBytes;
};

class PatchWidget : public QWidget {
    Q_OBJECT

public:
    explicit PatchWidget(QWidget* Parent = nullptr);
    ~PatchWidget() override;

    void SetAnalysisDatabase(AnalysisDatabase* Db);
    PatchEngine* GetPatchEngine() const;

signals:
    void NavigateToAddress(Address Addr);

private slots:
    void OnPatchBytes();
    void OnNopOut();
    void OnAssemble();
    void OnRevert();
    void OnRevertAll();
    void OnSaveBinary();
    void OnExport();
    void OnImport();
    void OnItemDoubleClicked(QTreeWidgetItem* Item, int Column);
    void OnContextMenu(const QPoint& Pos);
    void OnPatchApplied(Address Addr, const QString& Desc);
    void OnPatchReverted(int Index);

private:
    void RefreshList();
    QString FormatAddress(Address Addr) const;
    QString FormatBytes(const QByteArray& Bytes) const;

    QTreeWidget* TreeWidget;
    QToolBar* ToolBar;
    PatchEngine* Engine;
    AnalysisDatabase* AnalysisDb;
};

}
