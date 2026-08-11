#pragma once

#include <fidra/Types.h>
#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QThread>
#include <QMutex>
#include <QElapsedTimer>

namespace Fidra {

class ProxyConnection : public QObject {
    Q_OBJECT

public:
    explicit ProxyConnection(qintptr SocketDescriptor, bool InterceptEnabled, QObject* Parent = nullptr);
    ~ProxyConnection() override;

public slots:
    void Process();

signals:
    void RequestCaptured(const HttpRequest& Request);
    void Finished();

private slots:
    void OnClientReadyRead();
    void OnClientDisconnected();

private:
    void HandleHttpRequest(const QByteArray& RawData);
    void HandleConnectTunnel(const QString& Host, quint16 Port);
    void ForwardRequest(const HttpRequest& Req);
    void RelayTunnel();

    qintptr Descriptor;
    QTcpSocket* ClientSocket;
    QTcpSocket* RemoteSocket;
    bool Intercepting;
    bool IsTunnel;
    QByteArray ClientBuffer;
};

class HttpProxy : public QTcpServer {
    Q_OBJECT

public:
    explicit HttpProxy(QObject* Parent = nullptr);
    ~HttpProxy() override;

    bool StartProxy(quint16 Port = 8080);
    void StopProxy();
    bool IsRunning() const;
    quint16 ProxyPort() const;

    void SetInterceptEnabled(bool Enabled);
    bool IsInterceptEnabled() const;

    QList<HttpRequest> GetHistory() const;
    void ClearHistory();

signals:
    void ProxyStarted(quint16 Port);
    void ProxyStopped();
    void RequestCaptured(const HttpRequest& Request);
    void ErrorOccurred(const QString& Error);

protected:
    void incomingConnection(qintptr SocketDescriptor) override;

private slots:
    void OnRequestCaptured(const HttpRequest& Request);

private:
    bool Running;
    bool InterceptEnabled;
    quint16 CurrentPort;
    QList<HttpRequest> History;
    mutable QMutex HistoryMutex;
};

}
