#include "McpServer.h"
#include <QCoreApplication>
#include <QJsonDocument>
#include <QFile>
#include <cstdio>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#include <unistd.h>
#endif

namespace Fidra {

McpServer::McpServer(QObject* Parent)
    : QObject(Parent)
    , TcpServerInstance(nullptr)
    , ToolRegistryRef(nullptr)
    , StdioActive(false)
    , StdinNotifier(nullptr)
    , Initialized(false)
    , ServerName(QStringLiteral("Fidra MCP Server"))
    , ServerVersion(QStringLiteral("1.0.0")) {
}

McpServer::~McpServer() {
    StopTcp();
    StopStdio();
}

void McpServer::SetToolRegistry(McpToolRegistry* Registry) {
    ToolRegistryRef = Registry;
}

McpToolRegistry* McpServer::GetToolRegistry() const {
    return ToolRegistryRef;
}

bool McpServer::StartTcp(uint16_t Port) {
    if (TcpServerInstance && TcpServerInstance->isListening()) {
        return true;
    }

    if (!TcpServerInstance) {
        TcpServerInstance = new QTcpServer(this);
        connect(TcpServerInstance, &QTcpServer::newConnection, this, &McpServer::OnNewConnection);
    }

    if (!TcpServerInstance->listen(QHostAddress::LocalHost, Port)) {
        emit LogMessage(QStringLiteral("Failed to start TCP server on port ") +
                        QString::number(Port) + QStringLiteral(": ") +
                        TcpServerInstance->errorString());
        return false;
    }

    emit LogMessage(QStringLiteral("MCP TCP server started on port ") + QString::number(Port));
    emit TcpStarted(Port);
    return true;
}

void McpServer::StopTcp() {
    if (!TcpServerInstance) return;

    QList<QTcpSocket*> Sockets = Clients.keys();
    for (QTcpSocket* Socket : Sockets) {
        Socket->close();
    }
    Clients.clear();

    TcpServerInstance->close();
    emit LogMessage(QStringLiteral("MCP TCP server stopped"));
    emit TcpStopped();
}

bool McpServer::IsTcpRunning() const {
    return TcpServerInstance && TcpServerInstance->isListening();
}

uint16_t McpServer::TcpPort() const {
    if (TcpServerInstance && TcpServerInstance->isListening()) {
        return TcpServerInstance->serverPort();
    }
    return 0;
}

void McpServer::StartStdio() {
    if (StdioActive) return;

#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif

    StdioProtocol.SetTransport(McpProtocol::Transport::Stdio);

    StdinNotifier = new QSocketNotifier(fileno(stdin), QSocketNotifier::Read, this);
    connect(StdinNotifier, &QSocketNotifier::activated, this, [this]() {
        ReadStdin();
    });

    StdioActive = true;
    emit LogMessage(QStringLiteral("MCP stdio transport started"));
}

void McpServer::StopStdio() {
    if (!StdioActive) return;

    if (StdinNotifier) {
        StdinNotifier->setEnabled(false);
        delete StdinNotifier;
        StdinNotifier = nullptr;
    }

    StdioActive = false;
    emit LogMessage(QStringLiteral("MCP stdio transport stopped"));
}

bool McpServer::IsStdioRunning() const {
    return StdioActive;
}

QList<McpClientInfo> McpServer::GetConnectedClients() const {
    return Clients.values();
}

QList<McpServer::RequestLogEntry> McpServer::GetRequestLog() const {
    return RequestLog;
}

void McpServer::ClearRequestLog() {
    RequestLog.clear();
}

void McpServer::OnNewConnection() {
    while (TcpServerInstance->hasPendingConnections()) {
        QTcpSocket* Socket = TcpServerInstance->nextPendingConnection();

        McpClientInfo Client;
        Client.Socket = Socket;
        Client.Protocol.SetTransport(McpProtocol::Transport::Tcp);
        Client.Address = Socket->peerAddress().toString();
        Client.Port = Socket->peerPort();
        Client.ConnectedAt = QDateTime::currentDateTime();

        Clients.insert(Socket, Client);

        connect(Socket, &QTcpSocket::readyRead, this, &McpServer::OnClientData);
        connect(Socket, &QTcpSocket::disconnected, this, &McpServer::OnClientDisconnected);

        QString ClientAddr = Client.Address + QStringLiteral(":") + QString::number(Client.Port);
        emit ClientConnected(ClientAddr);
        emit LogMessage(QStringLiteral("Client connected: ") + ClientAddr);
    }
}

void McpServer::OnClientData() {
    QTcpSocket* Socket = qobject_cast<QTcpSocket*>(sender());
    if (!Socket) return;

    auto It = Clients.find(Socket);
    if (It == Clients.end()) return;

    QByteArray Data = Socket->readAll();
    It->Protocol.Feed(Data);
    ProcessRequests(*It);
}

void McpServer::OnClientDisconnected() {
    QTcpSocket* Socket = qobject_cast<QTcpSocket*>(sender());
    if (!Socket) return;

    auto It = Clients.find(Socket);
    if (It != Clients.end()) {
        QString ClientAddr = It->Address + QStringLiteral(":") + QString::number(It->Port);
        emit ClientDisconnected(ClientAddr);
        emit LogMessage(QStringLiteral("Client disconnected: ") + ClientAddr);
        Clients.erase(It);
    }

    Socket->deleteLater();
}

void McpServer::ProcessRequests(McpClientInfo& Client) {
    QList<JsonRpcRequest> Requests = Client.Protocol.TakeRequests();

    for (const JsonRpcRequest& Request : Requests) {
        QString ClientAddr = Client.Address + QStringLiteral(":") + QString::number(Client.Port);
        emit RequestReceived(ClientAddr, Request.Method);

        if (Request.IsNotification) {
            HandleRequest(Request);
            continue;
        }

        JsonRpcResponse Response = HandleRequest(Request);
        QByteArray ResponseJson = McpProtocol::SerializeResponse(Response);

        AddLogEntry(ClientAddr, Request.Method, Request.Params,
                    Response.IsError ? QJsonValue(Response.Error) : Response.Result,
                    Response.IsError);

        SendResponse(Client.Socket, ResponseJson);
        emit ResponseSent(ClientAddr, Request.Method, Response.IsError);
    }
}

JsonRpcResponse McpServer::HandleRequest(const JsonRpcRequest& Request) {
    if (Request.Method == QStringLiteral("initialize")) {
        return HandleInitialize(Request);
    } else if (Request.Method == QStringLiteral("ping")) {
        return HandlePing(Request);
    } else if (Request.Method == QStringLiteral("tools/list")) {
        return HandleToolsList(Request);
    } else if (Request.Method == QStringLiteral("tools/call")) {
        return HandleToolsCall(Request);
    } else if (Request.Method == QStringLiteral("notifications/initialized")) {
        return McpProtocol::MakeResult(Request.Id, QJsonObject());
    }

    return McpProtocol::MakeError(Request.Id, JsonRpcErrorCode::MethodNotFound,
                                   QStringLiteral("Method not found: ") + Request.Method);
}

JsonRpcResponse McpServer::HandleInitialize(const JsonRpcRequest& Request) {
    Initialized = true;

    QJsonObject Result;
    Result[QStringLiteral("protocolVersion")] = QStringLiteral("2024-11-05");

    QJsonObject Capabilities;

    QJsonObject ToolsCap;
    ToolsCap[QStringLiteral("listChanged")] = true;
    Capabilities[QStringLiteral("tools")] = ToolsCap;

    Result[QStringLiteral("capabilities")] = Capabilities;

    QJsonObject ServerInfo;
    ServerInfo[QStringLiteral("name")] = ServerName;
    ServerInfo[QStringLiteral("version")] = ServerVersion;
    Result[QStringLiteral("serverInfo")] = ServerInfo;

    Q_UNUSED(Request);
    return McpProtocol::MakeResult(Request.Id, Result);
}

JsonRpcResponse McpServer::HandleToolsList(const JsonRpcRequest& Request) {
    if (!ToolRegistryRef) {
        return McpProtocol::MakeError(Request.Id, JsonRpcErrorCode::InternalError,
                                       QStringLiteral("Tool registry not available"));
    }

    QJsonObject Result;
    Result[QStringLiteral("tools")] = ToolRegistryRef->GetToolList();
    return McpProtocol::MakeResult(Request.Id, Result);
}

JsonRpcResponse McpServer::HandleToolsCall(const JsonRpcRequest& Request) {
    if (!ToolRegistryRef) {
        return McpProtocol::MakeError(Request.Id, JsonRpcErrorCode::InternalError,
                                       QStringLiteral("Tool registry not available"));
    }

    QJsonObject Params = Request.Params.toObject();
    QString ToolName = Params.value(QStringLiteral("name")).toString();
    QJsonObject Arguments = Params.value(QStringLiteral("arguments")).toObject();

    if (ToolName.isEmpty()) {
        return McpProtocol::MakeError(Request.Id, JsonRpcErrorCode::InvalidParams,
                                       QStringLiteral("Missing tool name"));
    }

    if (!ToolRegistryRef->HasTool(ToolName)) {
        return McpProtocol::MakeError(Request.Id, JsonRpcErrorCode::InvalidParams,
                                       QStringLiteral("Unknown tool: ") + ToolName);
    }

    QJsonValue ToolResult = ToolRegistryRef->CallTool(ToolName, Arguments);

    QJsonObject Result;
    QJsonArray Content;

    QJsonObject TextContent;
    TextContent[QStringLiteral("type")] = QStringLiteral("text");

    QJsonDocument ResultDoc;
    if (ToolResult.isObject()) {
        ResultDoc = QJsonDocument(ToolResult.toObject());
    } else if (ToolResult.isArray()) {
        ResultDoc = QJsonDocument(ToolResult.toArray());
    } else {
        QJsonObject Wrapper;
        Wrapper[QStringLiteral("value")] = ToolResult;
        ResultDoc = QJsonDocument(Wrapper);
    }

    TextContent[QStringLiteral("text")] = QString::fromUtf8(ResultDoc.toJson(QJsonDocument::Indented));
    Content.append(TextContent);

    Result[QStringLiteral("content")] = Content;

    bool IsToolError = false;
    if (ToolResult.isObject()) {
        QJsonObject ResultObj = ToolResult.toObject();
        if (ResultObj.contains(QStringLiteral("error"))) {
            IsToolError = true;
        }
    }
    Result[QStringLiteral("isError")] = IsToolError;

    return McpProtocol::MakeResult(Request.Id, Result);
}

JsonRpcResponse McpServer::HandlePing(const JsonRpcRequest& Request) {
    return McpProtocol::MakeResult(Request.Id, QJsonObject());
}

void McpServer::SendResponse(QTcpSocket* Socket, const QByteArray& Data) {
    if (!Socket || Socket->state() != QAbstractSocket::ConnectedState) return;

    QByteArray ToSend = Data + "\n";
    Socket->write(ToSend);
    Socket->flush();
}

void McpServer::SendStdioResponse(const QByteArray& Data) {
    QByteArray Framed = McpProtocol::FrameMessage(Data);
    fwrite(Framed.constData(), 1, static_cast<size_t>(Framed.size()), stdout);
    fflush(stdout);
}

void McpServer::AddLogEntry(const QString& ClientAddress, const QString& Method,
                             const QJsonValue& Params, const QJsonValue& Response, bool IsError) {
    RequestLogEntry Entry;
    Entry.Timestamp = QDateTime::currentDateTime();
    Entry.ClientAddress = ClientAddress;
    Entry.Method = Method;
    Entry.Params = Params;
    Entry.Response = Response;
    Entry.IsError = IsError;

    RequestLog.append(Entry);

    while (RequestLog.size() > MaxLogEntries) {
        RequestLog.removeFirst();
    }
}

void McpServer::ReadStdin() {
    char Buf[8192];

#ifdef _WIN32
    int BytesRead = _read(_fileno(stdin), Buf, sizeof(Buf));
#else
    ssize_t BytesRead = read(fileno(stdin), Buf, sizeof(Buf));
#endif

    if (BytesRead <= 0) {
        StopStdio();
        return;
    }

    StdioProtocol.Feed(QByteArray(Buf, static_cast<int>(BytesRead)));

    QList<JsonRpcRequest> Requests = StdioProtocol.TakeRequests();
    for (const JsonRpcRequest& Request : Requests) {
        emit RequestReceived(QStringLiteral("stdio"), Request.Method);

        if (Request.IsNotification) {
            HandleRequest(Request);
            continue;
        }

        JsonRpcResponse Response = HandleRequest(Request);
        QByteArray ResponseJson = McpProtocol::SerializeResponse(Response);

        AddLogEntry(QStringLiteral("stdio"), Request.Method, Request.Params,
                    Response.IsError ? QJsonValue(Response.Error) : Response.Result,
                    Response.IsError);

        SendStdioResponse(ResponseJson);
        emit ResponseSent(QStringLiteral("stdio"), Request.Method, Response.IsError);
    }
}

}
