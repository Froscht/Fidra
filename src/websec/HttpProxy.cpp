#include "HttpProxy.h"

#include <QUrl>
#include <QHostAddress>
#include <QNetworkRequest>
#include <QEventLoop>
#include <QTimer>

namespace Fidra {

ProxyConnection::ProxyConnection(qintptr SocketDescriptor, bool InterceptEnabled, QObject* Parent)
    : QObject(Parent)
    , Descriptor(SocketDescriptor)
    , ClientSocket(nullptr)
    , RemoteSocket(nullptr)
    , Intercepting(InterceptEnabled)
    , IsTunnel(false) {
}

ProxyConnection::~ProxyConnection() {
    if (ClientSocket) {
        ClientSocket->close();
        ClientSocket->deleteLater();
    }
    if (RemoteSocket) {
        RemoteSocket->close();
        RemoteSocket->deleteLater();
    }
}

void ProxyConnection::Process() {
    ClientSocket = new QTcpSocket();
    if (!ClientSocket->setSocketDescriptor(Descriptor)) {
        emit Finished();
        return;
    }

    connect(ClientSocket, &QTcpSocket::readyRead, this, &ProxyConnection::OnClientReadyRead);
    connect(ClientSocket, &QTcpSocket::disconnected, this, &ProxyConnection::OnClientDisconnected);

    if (ClientSocket->bytesAvailable() > 0) {
        OnClientReadyRead();
    }
}

void ProxyConnection::OnClientReadyRead() {
    if (IsTunnel) {
        return;
    }

    ClientBuffer.append(ClientSocket->readAll());

    int HeaderEnd = ClientBuffer.indexOf("\r\n\r\n");
    if (HeaderEnd == -1) {
        return;
    }

    QString HeaderSection = QString::fromUtf8(ClientBuffer.left(HeaderEnd));
    QStringList HeaderLines = HeaderSection.split("\r\n");

    if (HeaderLines.isEmpty()) {
        emit Finished();
        return;
    }

    QStringList RequestLine = HeaderLines[0].split(' ');
    if (RequestLine.size() < 3) {
        emit Finished();
        return;
    }

    QString Method = RequestLine[0].toUpper();

    if (Method == QStringLiteral("CONNECT")) {
        QString HostPort = RequestLine[1];
        QString Host;
        quint16 Port = 443;
        int ColonIdx = HostPort.lastIndexOf(':');
        if (ColonIdx != -1) {
            Host = HostPort.left(ColonIdx);
            Port = HostPort.mid(ColonIdx + 1).toUShort();
        } else {
            Host = HostPort;
        }
        HandleConnectTunnel(Host, Port);
        return;
    }

    int ContentLength = 0;
    for (int I = 1; I < HeaderLines.size(); ++I) {
        if (HeaderLines[I].startsWith("Content-Length:", Qt::CaseInsensitive)) {
            ContentLength = HeaderLines[I].mid(15).trimmed().toInt();
            break;
        }
    }

    int TotalExpected = HeaderEnd + 4 + ContentLength;
    if (ClientBuffer.size() < TotalExpected) {
        return;
    }

    QByteArray FullRequest = ClientBuffer.left(TotalExpected);
    ClientBuffer.remove(0, TotalExpected);

    HandleHttpRequest(FullRequest);
}

void ProxyConnection::OnClientDisconnected() {
    emit Finished();
}

void ProxyConnection::HandleHttpRequest(const QByteArray& RawData) {
    int HeaderEnd = RawData.indexOf("\r\n\r\n");
    QString HeaderSection = QString::fromUtf8(RawData.left(HeaderEnd));
    QByteArray BodyData = RawData.mid(HeaderEnd + 4);

    QStringList HeaderLines = HeaderSection.split("\r\n");
    QStringList RequestLine = HeaderLines[0].split(' ');

    HttpRequest Req;
    Req.Method = RequestLine[0];
    Req.Url = RequestLine[1];
    Req.Body = BodyData;
    Req.StatusCode = 0;
    Req.ElapsedMs = 0;

    for (int I = 1; I < HeaderLines.size(); ++I) {
        int Colon = HeaderLines[I].indexOf(':');
        if (Colon != -1) {
            QString Key = HeaderLines[I].left(Colon).trimmed();
            QString Value = HeaderLines[I].mid(Colon + 1).trimmed();
            Req.Headers[Key] = Value;
        }
    }

    if (!Req.Url.startsWith("http://") && !Req.Url.startsWith("https://")) {
        QString Host = Req.Headers.value("Host", "");
        if (!Host.isEmpty()) {
            Req.Url = QStringLiteral("http://") + Host + Req.Url;
        }
    }

    ForwardRequest(Req);
}

void ProxyConnection::HandleConnectTunnel(const QString& Host, quint16 Port) {
    IsTunnel = true;

    RemoteSocket = new QTcpSocket(this);
    RemoteSocket->connectToHost(Host, Port);

    if (!RemoteSocket->waitForConnected(10000)) {
        QByteArray ErrorResponse = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        ClientSocket->write(ErrorResponse);
        ClientSocket->flush();
        emit Finished();
        return;
    }

    QByteArray ConnectResponse = "HTTP/1.1 200 Connection Established\r\n\r\n";
    ClientSocket->write(ConnectResponse);
    ClientSocket->flush();

    HttpRequest TunnelReq;
    TunnelReq.Method = QStringLiteral("CONNECT");
    TunnelReq.Url = Host + QStringLiteral(":") + QString::number(Port);
    TunnelReq.StatusCode = 200;
    TunnelReq.ElapsedMs = 0;
    emit RequestCaptured(TunnelReq);

    connect(ClientSocket, &QTcpSocket::readyRead, this, [this]() {
        if (RemoteSocket && RemoteSocket->state() == QAbstractSocket::ConnectedState) {
            RemoteSocket->write(ClientSocket->readAll());
        }
    });

    connect(RemoteSocket, &QTcpSocket::readyRead, this, [this]() {
        if (ClientSocket && ClientSocket->state() == QAbstractSocket::ConnectedState) {
            ClientSocket->write(RemoteSocket->readAll());
        }
    });

    connect(RemoteSocket, &QTcpSocket::disconnected, this, [this]() {
        if (ClientSocket) {
            ClientSocket->disconnectFromHost();
        }
        emit Finished();
    });

    connect(ClientSocket, &QTcpSocket::disconnected, this, [this]() {
        if (RemoteSocket) {
            RemoteSocket->disconnectFromHost();
        }
        emit Finished();
    });

    if (!ClientBuffer.isEmpty()) {
        QByteArray Remaining = ClientBuffer;
        ClientBuffer.clear();
        RemoteSocket->write(Remaining);
    }
}

void ProxyConnection::ForwardRequest(const HttpRequest& Req) {
    QUrl ParsedUrl(Req.Url);
    if (!ParsedUrl.isValid()) {
        QByteArray ErrorResponse = "HTTP/1.1 400 Bad Request\r\n\r\n";
        ClientSocket->write(ErrorResponse);
        ClientSocket->flush();
        emit Finished();
        return;
    }

    RemoteSocket = new QTcpSocket(this);
    QString Host = ParsedUrl.host();
    quint16 Port = ParsedUrl.port(80);

    RemoteSocket->connectToHost(Host, Port);
    if (!RemoteSocket->waitForConnected(10000)) {
        QByteArray ErrorResponse = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        ClientSocket->write(ErrorResponse);
        ClientSocket->flush();
        emit Finished();
        return;
    }

    QElapsedTimer Timer;
    Timer.start();

    QString Path = ParsedUrl.path();
    if (Path.isEmpty()) Path = "/";
    if (ParsedUrl.hasQuery()) {
        Path += "?" + ParsedUrl.query();
    }

    QByteArray OutgoingRequest;
    OutgoingRequest.append(Req.Method.toUtf8() + " " + Path.toUtf8() + " HTTP/1.1\r\n");

    QMap<QString, QString> OutHeaders = Req.Headers;
    OutHeaders["Host"] = Host;
    OutHeaders.remove("Proxy-Connection");

    for (auto It = OutHeaders.constBegin(); It != OutHeaders.constEnd(); ++It) {
        OutgoingRequest.append(It.key().toUtf8() + ": " + It.value().toUtf8() + "\r\n");
    }
    OutgoingRequest.append("\r\n");

    if (!Req.Body.isEmpty()) {
        OutgoingRequest.append(Req.Body);
    }

    RemoteSocket->write(OutgoingRequest);
    RemoteSocket->flush();

    QByteArray ResponseData;
    while (RemoteSocket->waitForReadyRead(15000)) {
        ResponseData.append(RemoteSocket->readAll());
        if (ResponseData.contains("\r\n\r\n")) {
            int RespHeaderEnd = ResponseData.indexOf("\r\n\r\n");
            QString RespHeaders = QString::fromUtf8(ResponseData.left(RespHeaderEnd));
            bool Chunked = RespHeaders.contains("Transfer-Encoding: chunked", Qt::CaseInsensitive);

            int RespContentLength = -1;
            for (const QString& Line : RespHeaders.split("\r\n")) {
                if (Line.startsWith("Content-Length:", Qt::CaseInsensitive)) {
                    RespContentLength = Line.mid(15).trimmed().toInt();
                    break;
                }
            }

            if (RespContentLength >= 0) {
                int BodyReceived = ResponseData.size() - (RespHeaderEnd + 4);
                while (BodyReceived < RespContentLength) {
                    if (!RemoteSocket->waitForReadyRead(10000)) break;
                    ResponseData.append(RemoteSocket->readAll());
                    BodyReceived = ResponseData.size() - (RespHeaderEnd + 4);
                }
                break;
            } else if (Chunked) {
                while (!ResponseData.endsWith("\r\n0\r\n\r\n")) {
                    if (!RemoteSocket->waitForReadyRead(10000)) break;
                    ResponseData.append(RemoteSocket->readAll());
                }
                break;
            } else {
                while (RemoteSocket->waitForReadyRead(2000)) {
                    ResponseData.append(RemoteSocket->readAll());
                }
                break;
            }
        }
    }

    qint64 Elapsed = Timer.elapsed();

    ClientSocket->write(ResponseData);
    ClientSocket->flush();
    ClientSocket->waitForBytesWritten(5000);

    HttpRequest CapturedReq = Req;
    CapturedReq.ElapsedMs = Elapsed;

    if (!ResponseData.isEmpty()) {
        int RespHeaderEnd = ResponseData.indexOf("\r\n\r\n");
        if (RespHeaderEnd != -1) {
            QString RespHeaderSection = QString::fromUtf8(ResponseData.left(RespHeaderEnd));
            CapturedReq.ResponseBody = ResponseData.mid(RespHeaderEnd + 4);

            QStringList RespLines = RespHeaderSection.split("\r\n");
            if (!RespLines.isEmpty()) {
                QStringList StatusParts = RespLines[0].split(' ');
                if (StatusParts.size() >= 2) {
                    CapturedReq.StatusCode = StatusParts[1].toInt();
                }
            }

            for (int I = 1; I < RespLines.size(); ++I) {
                int Colon = RespLines[I].indexOf(':');
                if (Colon != -1) {
                    QString Key = RespLines[I].left(Colon).trimmed();
                    QString Value = RespLines[I].mid(Colon + 1).trimmed();
                    CapturedReq.ResponseHeaders[Key] = Value;
                }
            }
        }
    }

    emit RequestCaptured(CapturedReq);
    emit Finished();
}

HttpProxy::HttpProxy(QObject* Parent)
    : QTcpServer(Parent)
    , Running(false)
    , InterceptEnabled(false)
    , CurrentPort(8080) {
}

HttpProxy::~HttpProxy() {
    StopProxy();
}

bool HttpProxy::StartProxy(quint16 Port) {
    if (Running) {
        StopProxy();
    }

    if (!listen(QHostAddress::LocalHost, Port)) {
        emit ErrorOccurred(QStringLiteral("Failed to start proxy on port %1: %2").arg(Port).arg(errorString()));
        return false;
    }

    CurrentPort = Port;
    Running = true;
    emit ProxyStarted(Port);
    return true;
}

void HttpProxy::StopProxy() {
    if (Running) {
        close();
        Running = false;
        emit ProxyStopped();
    }
}

bool HttpProxy::IsRunning() const {
    return Running;
}

quint16 HttpProxy::ProxyPort() const {
    return CurrentPort;
}

void HttpProxy::SetInterceptEnabled(bool Enabled) {
    InterceptEnabled = Enabled;
}

bool HttpProxy::IsInterceptEnabled() const {
    return InterceptEnabled;
}

QList<HttpRequest> HttpProxy::GetHistory() const {
    QMutexLocker Lock(&HistoryMutex);
    return History;
}

void HttpProxy::ClearHistory() {
    QMutexLocker Lock(&HistoryMutex);
    History.clear();
}

void HttpProxy::incomingConnection(qintptr SocketDescriptor) {
    QThread* WorkerThread = new QThread();
    ProxyConnection* Connection = new ProxyConnection(SocketDescriptor, InterceptEnabled);

    Connection->moveToThread(WorkerThread);

    connect(WorkerThread, &QThread::started, Connection, &ProxyConnection::Process);
    connect(Connection, &ProxyConnection::RequestCaptured, this, &HttpProxy::OnRequestCaptured, Qt::QueuedConnection);
    connect(Connection, &ProxyConnection::Finished, WorkerThread, &QThread::quit);
    connect(WorkerThread, &QThread::finished, Connection, &QObject::deleteLater);
    connect(WorkerThread, &QThread::finished, WorkerThread, &QObject::deleteLater);

    WorkerThread->start();
}

void HttpProxy::OnRequestCaptured(const HttpRequest& Request) {
    {
        QMutexLocker Lock(&HistoryMutex);
        History.append(Request);
    }
    emit RequestCaptured(Request);
}

}
