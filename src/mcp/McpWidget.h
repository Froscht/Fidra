#pragma once

#include "McpServer.h"
#include "McpToolRegistry.h"
#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QSpinBox>
#include <QTableWidget>
#include <QTextEdit>
#include <QListWidget>
#include <QCheckBox>
#include <QGroupBox>
#include <QTimer>

namespace Fidra {

class McpWidget : public QWidget {
    Q_OBJECT

public:
    explicit McpWidget(QWidget* Parent = nullptr);
    ~McpWidget() override;

    void SetServer(McpServer* Server);
    void SetToolRegistry(McpToolRegistry* Registry);

private slots:
    void OnStartStopClicked();
    void OnStdioToggled(bool Checked);
    void OnClearLogClicked();
    void OnServerStarted(uint16_t Port);
    void OnServerStopped();
    void OnClientConnected(const QString& Address);
    void OnClientDisconnected(const QString& Address);
    void OnRequestReceived(const QString& ClientAddress, const QString& Method);
    void OnResponseSent(const QString& ClientAddress, const QString& Method, bool IsError);
    void OnLogMessage(const QString& Message);
    void OnToolEnabledChanged(const QString& Name, bool Enabled);
    void RefreshToolTable();
    void RefreshClientList();

private:
    void SetupUi();
    void UpdateServerStatus();

    McpServer* ServerRef;
    McpToolRegistry* ToolRegistryRef;

    QLabel* StatusLabel;
    QLabel* PortLabel;
    QPushButton* StartStopButton;
    QSpinBox* PortSpinBox;
    QCheckBox* StdioCheckBox;

    QListWidget* ClientList;
    QTextEdit* RequestLogView;
    QTableWidget* ToolTable;

    QPushButton* ClearLogButton;
    QLabel* ClientCountLabel;
    QLabel* RequestCountLabel;

    int TotalRequests;
};

}
