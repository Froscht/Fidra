#pragma once

#include <fidra/Types.h>
#include <QObject>
#include <QThread>
#include <QMutex>
#include <QByteArray>
#include <QStringList>
#include <QFile>
#include <atomic>

namespace Fidra {

class CaptureWorker : public QObject {
    Q_OBJECT

public:
    explicit CaptureWorker(QObject* Parent = nullptr);
    ~CaptureWorker() override;

    void SetInterface(const QString& InterfaceName);

public slots:
    void StartCapture();
    void StopCapture();

signals:
    void PacketReceived(const Fidra::NetworkPacket& Packet);
    void CaptureError(const QString& Error);
    void CaptureStopped();

private:
    void CaptureLoop();
    void CaptureRawSocket();
    void CaptureQtFallback();
    NetworkPacket ParseRawPacket(const QByteArray& Data);

    QString Interface;
    std::atomic<bool> Running;

#ifdef _WIN32
    void* RawSocket;
#else
    int RawSocket;
#endif
};

struct PcapGlobalHeader {
    uint32_t MagicNumber;
    uint16_t VersionMajor;
    uint16_t VersionMinor;
    int32_t ThisZone;
    uint32_t SigFigs;
    uint32_t SnapLen;
    uint32_t Network;
};

struct PcapPacketHeader {
    uint32_t TsSec;
    uint32_t TsUsec;
    uint32_t InclLen;
    uint32_t OrigLen;
};

class PacketCapture : public QObject {
    Q_OBJECT

public:
    explicit PacketCapture(QObject* Parent = nullptr);
    ~PacketCapture() override;

    void Start(const QString& InterfaceName);
    void Stop();
    bool IsCapturing() const;

    QStringList GetAvailableInterfaces() const;

    bool SaveToPcap(const QString& FilePath, const QList<NetworkPacket>& Packets);
    QList<NetworkPacket> LoadFromPcap(const QString& FilePath);

signals:
    void PacketCaptured(const Fidra::NetworkPacket& Packet);
    void CaptureStarted();
    void CaptureStopped();
    void Error(const QString& Message);

private:
    QThread* WorkerThread;
    CaptureWorker* Worker;
    std::atomic<bool> Capturing;
};

}

Q_DECLARE_METATYPE(Fidra::NetworkPacket)
