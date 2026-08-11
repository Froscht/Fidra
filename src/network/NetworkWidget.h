#pragma once

#include <fidra/Types.h>
#include <fidra/ICore.h>
#include "PacketModel.h"
#include "PacketCapture.h"
#include "ProtocolDissector.h"

#include <QWidget>
#include <QTableView>
#include <QTreeWidget>
#include <QTextEdit>
#include <QSplitter>
#include <QToolBar>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QAction>

namespace Fidra {

class NetworkWidget : public QWidget {
    Q_OBJECT

public:
    explicit NetworkWidget(QWidget* Parent = nullptr);
    ~NetworkWidget() override;

    void SetCore(ICore* Core);

public slots:
    void OnStartStopCapture();
    void OnClearPackets();
    void OnSavePcap();
    void OnLoadPcap();

private slots:
    void OnPacketCaptured(const NetworkPacket& Packet);
    void OnPacketSelected(const QModelIndex& Index);
    void OnFilterApplied();
    void OnCaptureError(const QString& Message);
    void UpdateStatusLabel();

private:
    void SetupUi();
    void SetupToolbar();
    void PopulateInterfaces();
    void ShowPacketDetail(int Row);
    void ShowHexDump(const QByteArray& Data);
    void AddFieldsToTree(QTreeWidgetItem* Parent, const QList<DissectedField>& Fields);
    void HighlightHexRange(int Offset, int Length);

    ICore* CoreRef;

    QToolBar* ToolBar;
    QAction* StartStopAction;
    QComboBox* InterfaceCombo;
    QLineEdit* FilterInput;
    QPushButton* FilterApplyBtn;
    QPushButton* FilterClearBtn;
    QLabel* StatusLabel;

    QSplitter* MainSplitter;
    QSplitter* BottomSplitter;

    QTableView* PacketTable;
    QTreeWidget* DetailTree;
    QTextEdit* HexView;

    PacketModel* Model;
    PacketCapture* Capture;

    bool CaptureActive;
    int PacketCount;
};

}
