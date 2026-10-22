#pragma once

#include "McpProtocol.h"
#include "McpToolRegistry.h"
#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QList>
#include <QMap>
#include <QSet>
#include <QSocketNotifier>
#include <QTimer>
#include <QUuid>

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
    bool StartTcpAuto(uint16_t StartPort = 3333, int MaxAttempts = 100);
    void StopTcp();
    bool IsTcpRunning() const;
    uint16_t TcpPort() const;

    bool StartSse(uint16_t Port = 3334);
    bool StartSseAuto(uint16_t StartPort = 3334, int MaxAttempts = 100);
    void StopSse();
    bool IsSseRunning() const;
    uint16_t SsePort() const;

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
    void SseStarted(uint16_t Port);
    void SseStopped();
    void ClientConnected(const QString& Address);
    void ClientDisconnected(const QString& Address);
    void RequestReceived(const QString& ClientAddress, const QString& Method);
    void ResponseSent(const QString& ClientAddress, const QString& Method, bool IsError);
    void LogMessage(const QString& Message);

private slots:
    void OnNewConnection();
    void OnClientData();
    void OnClientDisconnected();
    void OnNewSseConnection();
    void OnSseClientData();
    void OnSseClientDisconnected();

private:
    void ProcessRequests(McpClientInfo& Client);
    JsonRpcResponse HandleRequest(const JsonRpcRequest& Request);

    JsonRpcResponse HandleInitialize(const JsonRpcRequest& Request);
    JsonRpcResponse HandleToolsList(const JsonRpcRequest& Request);
    JsonRpcResponse HandleToolsCall(const JsonRpcRequest& Request);
    JsonRpcResponse HandlePing(const JsonRpcRequest& Request);

    void SendResponse(QTcpSocket* Socket, const QByteArray& Data);
    void SendStdioResponse(const QByteArray& Data);
    void SendSseEvent(QTcpSocket* SseSocket, const QString& Event, const QByteArray& Data);

    void AddLogEntry(const QString& ClientAddress, const QString& Method,
                     const QJsonValue& Params, const QJsonValue& Response, bool IsError);

    void ReadStdin();
    void HandleSseHttp(QTcpSocket* Socket);

    QTcpServer* TcpServerInstance;
    QMap<QTcpSocket*, McpClientInfo> Clients;
    McpToolRegistry* ToolRegistryRef;

    bool StdioActive;
    QSocketNotifier* StdinNotifier;
    McpProtocol StdioProtocol;

    QTcpServer* SseServerInstance;
    QMap<QTcpSocket*, QByteArray> SseBuffers;
    QMap<QString, QTcpSocket*> SseSessions;
    QMap<QTcpSocket*, QString> SseSocketToSession;
    QSet<QTcpSocket*> SseStreamSockets;

    QList<RequestLogEntry> RequestLog;
    static constexpr int MaxLogEntries = 500;

    bool Initialized;
    QString ServerName;
    QString ServerVersion;
};

}
