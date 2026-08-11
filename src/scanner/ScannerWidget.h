#pragma once

#include <fidra/ICore.h>
#include <QWidget>
#include <QTableWidget>
#include <QTableView>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QProgressBar>
#include <QLabel>
#include <QTimer>
#include <QVariant>

namespace Fidra {

class ScanEngine;
class AddressList;

class ScannerWidget : public QWidget {
    Q_OBJECT

public:
    explicit ScannerWidget(QWidget* Parent, ICore* Core);
    ~ScannerWidget() override;

    AddressList* GetAddressList() const;
    void OnProcessAttached(const ProcessInfo& Info);
    void OnProcessDetached();

private slots:
    void OnFirstScan();
    void OnNextScan();
    void OnNewScan();
    void OnScanTypeChanged(int Index);
    void OnScanProgressUpdate(int Percent);
    void OnScanFinished(int Count);
    void OnResultDoubleClicked(int Row, int Column);
    void OnResultContextMenu(const QPoint& Pos);
    void OnSaveList();
    void OnLoadList();

private:
    QVariant ParseValue(const QString& Text);
    QVariant ParseValue2(const QString& Text);
    ValueType GetSelectedValueType() const;
    ScanType GetSelectedScanType() const;
    void PopulateResults();
    void AddSelectedToAddressList();
    QString FormatAddress(Address Addr) const;
    QString FormatValueBytes(const QByteArray& Data, ValueType Type) const;

    ICore* CoreRef;
    ScanEngine* Engine;
    AddressList* Addresses;

    QLineEdit* ValueInput;
    QLineEdit* Value2Input;
    QLabel* Value2Label;
    QComboBox* ScanTypeCombo;
    QComboBox* ValueTypeCombo;
    QPushButton* FirstScanBtn;
    QPushButton* NextScanBtn;
    QPushButton* NewScanBtn;
    QProgressBar* ScanProgress;
    QLabel* FoundLabel;
    QTableWidget* ResultsTable;
    QTableView* AddressTableView;
    QPushButton* SaveListBtn;
    QPushButton* LoadListBtn;
    QTimer* FreezeTimer;

    bool ScanInProgress;
};

}
