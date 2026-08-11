#include "McpProtocol.h"

namespace Fidra {

McpProtocol::McpProtocol()
    : CurrentTransport(Transport::Tcp) {
}

void McpProtocol::SetTransport(Transport T) {
    CurrentTransport = T;
}

McpProtocol::Transport McpProtocol::GetTransport() const {
    return CurrentTransport;
}

void McpProtocol::Feed(const QByteArray& Data) {
    Buffer.append(Data);

    QByteArray Message;
    while (TryExtractMessage(Message)) {
        QJsonParseError ParseErr;
        QJsonDocument Doc = QJsonDocument::fromJson(Message, &ParseErr);

        if (ParseErr.error != QJsonParseError::NoError) {
            continue;
        }

        if (Doc.isArray()) {
            QJsonArray Arr = Doc.array();
            QList<JsonRpcRequest> BatchReqs = ParseBatch(Arr);
            PendingRequests.append(BatchReqs);
        } else if (Doc.isObject()) {
            auto Req = ParseRequest(Doc.object());
            if (Req.has_value()) {
                PendingRequests.append(Req.value());
            }
        }
    }
}

QList<JsonRpcRequest> McpProtocol::TakeRequests() {
    QList<JsonRpcRequest> Taken;
    Taken.swap(PendingRequests);
    return Taken;
}

bool McpProtocol::HasPendingRequests() const {
    return !PendingRequests.isEmpty();
}

bool McpProtocol::TryExtractMessage(QByteArray& Message) {
    if (CurrentTransport == Transport::Stdio) {
        static const QByteArray ContentLengthHeader = "Content-Length: ";

        int HeaderEnd = Buffer.indexOf("\r\n\r\n");
        if (HeaderEnd < 0) {
            return false;
        }

        QByteArray HeaderSection = Buffer.left(HeaderEnd);
        int ContentLength = -1;

        QList<QByteArray> HeaderLines = HeaderSection.split('\n');
        for (const QByteArray& Line : HeaderLines) {
            QByteArray Trimmed = Line.trimmed();
            if (Trimmed.startsWith(ContentLengthHeader)) {
                bool Ok = false;
                ContentLength = Trimmed.mid(ContentLengthHeader.size()).toInt(&Ok);
                if (!Ok) {
                    ContentLength = -1;
                }
            }
        }

        if (ContentLength < 0) {
            Buffer.remove(0, HeaderEnd + 4);
            return false;
        }

        int BodyStart = HeaderEnd + 4;
        if (Buffer.size() < BodyStart + ContentLength) {
            return false;
        }

        Message = Buffer.mid(BodyStart, ContentLength);
        Buffer.remove(0, BodyStart + ContentLength);
        return true;
    } else {
        int NewlinePos = Buffer.indexOf('\n');
        if (NewlinePos < 0) {
            if (Buffer.startsWith("{") || Buffer.startsWith("[")) {
                QJsonParseError Err;
                QJsonDocument TestDoc = QJsonDocument::fromJson(Buffer, &Err);
                if (Err.error == QJsonParseError::NoError) {
                    Message = Buffer;
                    Buffer.clear();
                    return true;
                }
            }
            return false;
        }

        Message = Buffer.left(NewlinePos).trimmed();
        Buffer.remove(0, NewlinePos + 1);

        if (Message.isEmpty()) {
            return TryExtractMessage(Message);
        }

        return true;
    }
}

QByteArray McpProtocol::SerializeResponse(const JsonRpcResponse& Response) {
    QJsonObject Obj;
    Obj[QStringLiteral("jsonrpc")] = QStringLiteral("2.0");
    Obj[QStringLiteral("id")] = Response.Id;

    if (Response.IsError) {
        Obj[QStringLiteral("error")] = Response.Error;
    } else {
        Obj[QStringLiteral("result")] = Response.Result;
    }

    QJsonDocument Doc(Obj);
    return Doc.toJson(QJsonDocument::Compact);
}

QByteArray McpProtocol::SerializeNotification(const QString& Method, const QJsonValue& Params) {
    QJsonObject Obj;
    Obj[QStringLiteral("jsonrpc")] = QStringLiteral("2.0");
    Obj[QStringLiteral("method")] = Method;
    if (!Params.isNull() && !Params.isUndefined()) {
        Obj[QStringLiteral("params")] = Params;
    }

    QJsonDocument Doc(Obj);
    return Doc.toJson(QJsonDocument::Compact);
}

JsonRpcResponse McpProtocol::MakeResult(const QJsonValue& Id, const QJsonValue& Result) {
    JsonRpcResponse Resp;
    Resp.Id = Id;
    Resp.Result = Result;
    Resp.IsError = false;
    return Resp;
}

JsonRpcResponse McpProtocol::MakeError(const QJsonValue& Id, JsonRpcErrorCode Code, const QString& Message, const QJsonValue& Data) {
    JsonRpcResponse Resp;
    Resp.Id = Id;
    Resp.IsError = true;

    QJsonObject ErrObj;
    ErrObj[QStringLiteral("code")] = static_cast<int>(Code);
    ErrObj[QStringLiteral("message")] = Message;
    if (!Data.isNull() && !Data.isUndefined()) {
        ErrObj[QStringLiteral("data")] = Data;
    }
    Resp.Error = ErrObj;

    return Resp;
}

QByteArray McpProtocol::FrameMessage(const QByteArray& Json) {
    QByteArray Frame;
    Frame.append("Content-Length: ");
    Frame.append(QByteArray::number(Json.size()));
    Frame.append("\r\n\r\n");
    Frame.append(Json);
    return Frame;
}

std::optional<JsonRpcRequest> McpProtocol::ParseRequest(const QJsonObject& Obj) {
    JsonRpcRequest Req;
    Req.Jsonrpc = Obj.value(QStringLiteral("jsonrpc")).toString();
    Req.Method = Obj.value(QStringLiteral("method")).toString();
    Req.Params = Obj.value(QStringLiteral("params"));
    Req.Id = Obj.value(QStringLiteral("id"));
    Req.IsNotification = !Obj.contains(QStringLiteral("id"));

    if (Req.Method.isEmpty()) {
        return std::nullopt;
    }

    return Req;
}

QList<JsonRpcRequest> McpProtocol::ParseBatch(const QJsonArray& Arr) {
    QList<JsonRpcRequest> Requests;
    for (const QJsonValue& Val : Arr) {
        if (Val.isObject()) {
            auto Req = ParseRequest(Val.toObject());
            if (Req.has_value()) {
                Requests.append(Req.value());
            }
        }
    }
    return Requests;
}

}
