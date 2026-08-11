#pragma once

#include "McpProtocol.h"
#include "McpToolRegistry.h"
#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QList>
#include <QMap>
#include <QSocketNotifier>
#include <QTimer>

namespace Fidra {

struct McpClientInfo {
    QTcpSocket* Socket;
    McpProtocol Protocol;
    QString Address;
    uint16_t Port;
    QDateTime ConnectedAt;
};

class McpServer : public QObject {
    Q_OBJECT

public:
    explicit McpServer(QObject* Parent = nullptr);
    ~McpServer() override;

    void SetToolRegistry(McpToolRegistry* Registry);
    McpToolRegistry* GetToolRegistry() const;

    bool StartTcp(uint16_t Port = 3333);
    void StopTcp();
    bool IsTcpRunning() const;
    uint16_t TcpPort() const;

    void StartStdio();
    void StopStdio();
    bool IsStdioRunning() const;

    QList<McpClientInfo> GetConnectedClients() const;

    struct RequestLogEntry {
        QDateTime Timestamp;
        QString ClientAddress;
        QString Method;
        QJsonValue Params;
        QJsonValue Response;
        bool IsError;
    };

    QList<RequestLogEntry> GetRequestLog() const;
    void ClearRequestLog();

signals:
    void TcpStarted(uint16_t Port);
    void TcpStopped();
    void ClientConnected(const QString& Address);
    void ClientDisconnected(const QString& Address);
    void RequestReceived(const QString& ClientAddress, const QString& Method);
    void ResponseSent(const QString& ClientAddress, const QString& Method, bool IsError);
    void LogMessage(const QString& Message);

private slots:
    void OnNewConnection();
    void OnClientData();
    void OnClientDisconnected();

private:
    void ProcessRequests(McpClientInfo& Client);
    JsonRpcResponse HandleRequest(const JsonRpcRequest& Request);

    JsonRpcResponse HandleInitialize(const JsonRpcRequest& Request);
    JsonRpcResponse HandleToolsList(const JsonRpcRequest& Request);
    JsonRpcResponse HandleToolsCall(const JsonRpcRequest& Request);
    JsonRpcResponse HandlePing(const JsonRpcRequest& Request);

    void SendResponse(QTcpSocket* Socket, const QByteArray& Data);
    void SendStdioResponse(const QByteArray& Data);

    void AddLogEntry(const QString& ClientAddress, const QString& Method,
                     const QJsonValue& Params, const QJsonValue& Response, bool IsError);

    void ReadStdin();

    QTcpServer* TcpServerInstance;
    QMap<QTcpSocket*, McpClientInfo> Clients;
    McpToolRegistry* ToolRegistryRef;

    bool StdioActive;
    QSocketNotifier* StdinNotifier;
    McpProtocol StdioProtocol;

    QList<RequestLogEntry> RequestLog;
    static constexpr int MaxLogEntries = 500;

    bool Initialized;
    QString ServerName;
    QString ServerVersion;
};

}
