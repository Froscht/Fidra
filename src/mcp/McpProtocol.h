#pragma once

#include <QByteArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <QString>
#include <QList>
#include <optional>

namespace Fidra {

enum class JsonRpcErrorCode {
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603
};

struct JsonRpcRequest {
    QString Jsonrpc;
    QString Method;
    QJsonValue Params;
    QJsonValue Id;
    bool IsNotification;
};

struct JsonRpcResponse {
    QJsonValue Id;
    QJsonValue Result;
    QJsonObject Error;
    bool IsError;
};

class McpProtocol {
public:
    McpProtocol();

    void Feed(const QByteArray& Data);
    QList<JsonRpcRequest> TakeRequests();
    bool HasPendingRequests() const;

    static QByteArray SerializeResponse(const JsonRpcResponse& Response);
    static QByteArray SerializeNotification(const QString& Method, const QJsonValue& Params);

    static JsonRpcResponse MakeResult(const QJsonValue& Id, const QJsonValue& Result);
    static JsonRpcResponse MakeError(const QJsonValue& Id, JsonRpcErrorCode Code, const QString& Message, const QJsonValue& Data = QJsonValue());

    static QByteArray FrameMessage(const QByteArray& Json);

    static std::optional<JsonRpcRequest> ParseRequest(const QJsonObject& Obj);
    static QList<JsonRpcRequest> ParseBatch(const QJsonArray& Arr);

    enum class Transport {
        Tcp,
        Stdio
    };

    void SetTransport(Transport T);
    Transport GetTransport() const;

private:
    bool TryExtractMessage(QByteArray& Message);

    QByteArray Buffer;
    QList<JsonRpcRequest> PendingRequests;
    Transport CurrentTransport;
};

}
