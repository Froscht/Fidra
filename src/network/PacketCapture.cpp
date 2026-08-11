#include "PacketCapture.h"
#include <QDateTime>
#include <QNetworkInterface>
#include <QUdpSocket>
#include <QDataStream>
#include <QTimer>
#include <QtEndian>

#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#endif

namespace Fidra {

CaptureWorker::CaptureWorker(QObject* Parent)
    : QObject(Parent)
    , Running(false)
#ifdef _WIN32
    , RawSocket(nullptr)
#else
    , RawSocket(-1)
#endif
{
}

CaptureWorker::~CaptureWorker() {
    StopCapture();
}

void CaptureWorker::SetInterface(const QString& InterfaceName) {
    Interface = InterfaceName;
}

void CaptureWorker::StartCapture() {
    Running = true;
    CaptureLoop();
}

void CaptureWorker::StopCapture() {
    Running = false;

#ifdef _WIN32
    if (RawSocket && RawSocket != reinterpret_cast<void*>(-1)) {
        closesocket(reinterpret_cast<uintptr_t>(RawSocket));
        RawSocket = nullptr;
    }
#else
    if (RawSocket >= 0) {
        close(RawSocket);
        RawSocket = -1;
    }
#endif
}

void CaptureWorker::CaptureLoop() {
#ifdef _WIN32
    CaptureRawSocket();
#else
    CaptureRawSocket();
#endif

    if (Running) {
        CaptureQtFallback();
    }
}

void CaptureWorker::CaptureRawSocket() {
#ifdef _WIN32
    WSADATA WsaData;
    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0) {
        emit CaptureError("WSAStartup failed");
        return;
    }

    SOCKET Sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (Sock == INVALID_SOCKET) {
        emit CaptureError(QString("Failed to create raw socket: %1").arg(WSAGetLastError()));
        return;
    }

    RawSocket = reinterpret_cast<void*>(Sock);

    struct sockaddr_in BindAddr;
    memset(&BindAddr, 0, sizeof(BindAddr));
    BindAddr.sin_family = AF_INET;
    BindAddr.sin_port = 0;

    if (!Interface.isEmpty()) {
        QHostAddress Addr(Interface);
        if (!Addr.isNull()) {
            QByteArray AddrBytes = Addr.toString().toUtf8();
            inet_pton(AF_INET, AddrBytes.constData(), &BindAddr.sin_addr);
        } else {
            QList<QNetworkInterface> Interfaces = QNetworkInterface::allInterfaces();
            for (const auto& Iface : Interfaces) {
                if (Iface.humanReadableName() == Interface || Iface.name() == Interface) {
                    QList<QNetworkAddressEntry> Entries = Iface.addressEntries();
                    for (const auto& Entry : Entries) {
                        if (Entry.ip().protocol() == QAbstractSocket::IPv4Protocol) {
                            QByteArray AddrStr = Entry.ip().toString().toUtf8();
                            inet_pton(AF_INET, AddrStr.constData(), &BindAddr.sin_addr);
                            break;
                        }
                    }
                    break;
                }
            }
        }
    } else {
        BindAddr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(Sock, reinterpret_cast<struct sockaddr*>(&BindAddr), sizeof(BindAddr)) == SOCKET_ERROR) {
        emit CaptureError(QString("Bind failed: %1").arg(WSAGetLastError()));
        closesocket(Sock);
        RawSocket = nullptr;
        return;
    }

    DWORD PromiscMode = RCVALL_ON;
    DWORD BytesReturned = 0;
    if (WSAIoctl(Sock, SIO_RCVALL, &PromiscMode, sizeof(PromiscMode),
                 nullptr, 0, &BytesReturned, nullptr, nullptr) == SOCKET_ERROR) {
        emit CaptureError(QString("SIO_RCVALL failed: %1 (requires admin)").arg(WSAGetLastError()));
        closesocket(Sock);
        RawSocket = nullptr;
        return;
    }

    char Buffer[65536];
    while (Running) {
        fd_set ReadSet;
        FD_ZERO(&ReadSet);
        FD_SET(Sock, &ReadSet);

        struct timeval Timeout;
        Timeout.tv_sec = 0;
        Timeout.tv_usec = 100000;

        int SelectResult = select(0, &ReadSet, nullptr, nullptr, &Timeout);
        if (SelectResult <= 0) continue;

        int RecvLen = recv(Sock, Buffer, sizeof(Buffer), 0);
        if (RecvLen > 0) {
            QByteArray Data(Buffer, RecvLen);
            NetworkPacket Pkt = ParseRawPacket(Data);
            Pkt.Data = Data;
            Pkt.Timestamp = QDateTime::currentMSecsSinceEpoch();
            emit PacketReceived(Pkt);
        }
    }

    PromiscMode = RCVALL_OFF;
    WSAIoctl(Sock, SIO_RCVALL, &PromiscMode, sizeof(PromiscMode),
             nullptr, 0, &BytesReturned, nullptr, nullptr);
    closesocket(Sock);
    RawSocket = nullptr;

    emit CaptureStopped();

#else
    int Sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (Sock < 0) {
        emit CaptureError("Failed to create raw socket (requires root)");
        return;
    }

    RawSocket = Sock;

    if (!Interface.isEmpty()) {
        struct ifreq Ifr;
        memset(&Ifr, 0, sizeof(Ifr));
        strncpy(Ifr.ifr_name, Interface.toUtf8().constData(), IFNAMSIZ - 1);

        if (ioctl(Sock, SIOCGIFINDEX, &Ifr) >= 0) {
            struct sockaddr_ll Sll;
            memset(&Sll, 0, sizeof(Sll));
            Sll.sll_family = AF_PACKET;
            Sll.sll_protocol = htons(ETH_P_ALL);
            Sll.sll_ifindex = Ifr.ifr_ifindex;

            bind(Sock, reinterpret_cast<struct sockaddr*>(&Sll), sizeof(Sll));
        }

        memset(&Ifr, 0, sizeof(Ifr));
        strncpy(Ifr.ifr_name, Interface.toUtf8().constData(), IFNAMSIZ - 1);
        ioctl(Sock, SIOCGIFFLAGS, &Ifr);
        Ifr.ifr_flags |= IFF_PROMISC;
        ioctl(Sock, SIOCSIFFLAGS, &Ifr);
    }

    char Buffer[65536];
    while (Running) {
        fd_set ReadSet;
        FD_ZERO(&ReadSet);
        FD_SET(Sock, &ReadSet);

        struct timeval Timeout;
        Timeout.tv_sec = 0;
        Timeout.tv_usec = 100000;

        int SelectResult = select(Sock + 1, &ReadSet, nullptr, nullptr, &Timeout);
        if (SelectResult <= 0) continue;

        ssize_t RecvLen = recv(Sock, Buffer, sizeof(Buffer), 0);
        if (RecvLen > 0) {
            QByteArray Data(Buffer, static_cast<int>(RecvLen));
            NetworkPacket Pkt = ParseRawPacket(Data);
            Pkt.Data = Data;
            Pkt.Timestamp = QDateTime::currentMSecsSinceEpoch();
            emit PacketReceived(Pkt);
        }
    }

    close(Sock);
    RawSocket = -1;

    emit CaptureStopped();
#endif
}

void CaptureWorker::CaptureQtFallback() {
    QUdpSocket Sock;
    if (!Sock.bind(QHostAddress::Any, 0, QUdpSocket::ShareAddress)) {
        emit CaptureError("Qt fallback socket bind failed");
        return;
    }

    while (Running) {
        if (Sock.waitForReadyRead(100)) {
            while (Sock.hasPendingDatagrams()) {
                QByteArray Datagram;
                Datagram.resize(static_cast<int>(Sock.pendingDatagramSize()));
                QHostAddress Sender;
                uint16_t SenderPort;
                Sock.readDatagram(Datagram.data(), Datagram.size(), &Sender, &SenderPort);

                NetworkPacket Pkt;
                Pkt.Timestamp = QDateTime::currentMSecsSinceEpoch();
                Pkt.Protocol = "UDP";
                Pkt.SourceAddress = Sender.toString();
                Pkt.SourcePort = SenderPort;
                Pkt.DestAddress = Sock.localAddress().toString();
                Pkt.DestPort = Sock.localPort();
                Pkt.Data = Datagram;
                Pkt.Outgoing = false;

                emit PacketReceived(Pkt);
            }
        }
    }

    Sock.close();
    emit CaptureStopped();
}

NetworkPacket CaptureWorker::ParseRawPacket(const QByteArray& Data) {
    NetworkPacket Pkt;
    Pkt.Timestamp = QDateTime::currentMSecsSinceEpoch();
    Pkt.Outgoing = false;
    Pkt.SourcePort = 0;
    Pkt.DestPort = 0;

    const uint8_t* Raw = reinterpret_cast<const uint8_t*>(Data.constData());
    int Len = Data.size();

#ifdef _WIN32
    if (Len < 20) return Pkt;

    uint8_t Version = (Raw[0] >> 4) & 0x0F;
    if (Version != 4) return Pkt;

    uint8_t Ihl = Raw[0] & 0x0F;
    int IpHeaderLen = Ihl * 4;
    if (IpHeaderLen < 20 || IpHeaderLen > Len) return Pkt;

    uint32_t SrcIp, DstIp;
    memcpy(&SrcIp, Raw + 12, 4);
    memcpy(&DstIp, Raw + 16, 4);

    uint8_t SrcBytes[4], DstBytes[4];
    memcpy(SrcBytes, &SrcIp, 4);
    memcpy(DstBytes, &DstIp, 4);

    Pkt.SourceAddress = QString("%1.%2.%3.%4").arg(SrcBytes[0]).arg(SrcBytes[1]).arg(SrcBytes[2]).arg(SrcBytes[3]);
    Pkt.DestAddress = QString("%1.%2.%3.%4").arg(DstBytes[0]).arg(DstBytes[1]).arg(DstBytes[2]).arg(DstBytes[3]);

    uint8_t Protocol = Raw[9];
    if (Protocol == 6) {
        Pkt.Protocol = "TCP";
        if (Len >= IpHeaderLen + 4) {
            uint16_t SrcPort, DstPort;
            memcpy(&SrcPort, Raw + IpHeaderLen, 2);
            memcpy(&DstPort, Raw + IpHeaderLen + 2, 2);
            Pkt.SourcePort = qFromBigEndian(SrcPort);
            Pkt.DestPort = qFromBigEndian(DstPort);
        }
    } else if (Protocol == 17) {
        Pkt.Protocol = "UDP";
        if (Len >= IpHeaderLen + 4) {
            uint16_t SrcPort, DstPort;
            memcpy(&SrcPort, Raw + IpHeaderLen, 2);
            memcpy(&DstPort, Raw + IpHeaderLen + 2, 2);
            Pkt.SourcePort = qFromBigEndian(SrcPort);
            Pkt.DestPort = qFromBigEndian(DstPort);
        }
    } else if (Protocol == 1) {
        Pkt.Protocol = "ICMP";
    } else {
        Pkt.Protocol = QString("IP/%1").arg(Protocol);
    }
#else
    if (Len < 14) return Pkt;

    uint16_t EtherType;
    memcpy(&EtherType, Raw + 12, 2);
    EtherType = qFromBigEndian(EtherType);

    if (EtherType == 0x0800 && Len >= 34) {
        int IpOffset = 14;
        uint8_t Ihl = Raw[IpOffset] & 0x0F;
        int IpHeaderLen = Ihl * 4;

        uint32_t SrcIp, DstIp;
        memcpy(&SrcIp, Raw + IpOffset + 12, 4);
        memcpy(&DstIp, Raw + IpOffset + 16, 4);

        uint8_t SrcBytes[4], DstBytes[4];
        memcpy(SrcBytes, &SrcIp, 4);
        memcpy(DstBytes, &DstIp, 4);

        Pkt.SourceAddress = QString("%1.%2.%3.%4").arg(SrcBytes[0]).arg(SrcBytes[1]).arg(SrcBytes[2]).arg(SrcBytes[3]);
        Pkt.DestAddress = QString("%1.%2.%3.%4").arg(DstBytes[0]).arg(DstBytes[1]).arg(DstBytes[2]).arg(DstBytes[3]);

        uint8_t Protocol = Raw[IpOffset + 9];
        int TransportOffset = IpOffset + IpHeaderLen;

        if (Protocol == 6) {
            Pkt.Protocol = "TCP";
            if (Len >= TransportOffset + 4) {
                uint16_t SrcPort, DstPort;
                memcpy(&SrcPort, Raw + TransportOffset, 2);
                memcpy(&DstPort, Raw + TransportOffset + 2, 2);
                Pkt.SourcePort = qFromBigEndian(SrcPort);
                Pkt.DestPort = qFromBigEndian(DstPort);
            }
        } else if (Protocol == 17) {
            Pkt.Protocol = "UDP";
            if (Len >= TransportOffset + 4) {
                uint16_t SrcPort, DstPort;
                memcpy(&SrcPort, Raw + TransportOffset, 2);
                memcpy(&DstPort, Raw + TransportOffset + 2, 2);
                Pkt.SourcePort = qFromBigEndian(SrcPort);
                Pkt.DestPort = qFromBigEndian(DstPort);
            }
        } else if (Protocol == 1) {
            Pkt.Protocol = "ICMP";
        } else {
            Pkt.Protocol = QString("IP/%1").arg(Protocol);
        }
    } else if (EtherType == 0x0806) {
        Pkt.Protocol = "ARP";
    } else if (EtherType == 0x86DD) {
        Pkt.Protocol = "IPv6";
    } else {
        Pkt.Protocol = QString("0x%1").arg(EtherType, 4, 16, QChar('0'));
    }
#endif

    return Pkt;
}

PacketCapture::PacketCapture(QObject* Parent)
    : QObject(Parent)
    , WorkerThread(nullptr)
    , Worker(nullptr)
    , Capturing(false) {
    qRegisterMetaType<Fidra::NetworkPacket>("Fidra::NetworkPacket");
}

PacketCapture::~PacketCapture() {
    Stop();
}

void PacketCapture::Start(const QString& InterfaceName) {
    if (Capturing) {
        Stop();
    }

    WorkerThread = new QThread(this);
    Worker = new CaptureWorker();
    Worker->SetInterface(InterfaceName);
    Worker->moveToThread(WorkerThread);

    connect(WorkerThread, &QThread::started, Worker, &CaptureWorker::StartCapture);
    connect(Worker, &CaptureWorker::PacketReceived, this, &PacketCapture::PacketCaptured, Qt::QueuedConnection);
    connect(Worker, &CaptureWorker::CaptureError, this, &PacketCapture::Error, Qt::QueuedConnection);
    connect(Worker, &CaptureWorker::CaptureStopped, this, [this]() {
        Capturing = false;
        emit CaptureStopped();
    }, Qt::QueuedConnection);

    Capturing = true;
    WorkerThread->start();
    emit CaptureStarted();
}

void PacketCapture::Stop() {
    if (Worker) {
        Worker->StopCapture();
    }

    if (WorkerThread) {
        WorkerThread->quit();
        WorkerThread->wait(3000);
        if (WorkerThread->isRunning()) {
            WorkerThread->terminate();
            WorkerThread->wait(1000);
        }
    }

    delete Worker;
    Worker = nullptr;

    if (WorkerThread) {
        delete WorkerThread;
        WorkerThread = nullptr;
    }

    Capturing = false;
}

bool PacketCapture::IsCapturing() const {
    return Capturing;
}

QStringList PacketCapture::GetAvailableInterfaces() const {
    QStringList Result;
    QList<QNetworkInterface> Interfaces = QNetworkInterface::allInterfaces();

    for (const auto& Iface : Interfaces) {
        if (Iface.flags() & QNetworkInterface::IsLoopBack) continue;
        if (!(Iface.flags() & QNetworkInterface::IsUp)) continue;
        if (!(Iface.flags() & QNetworkInterface::IsRunning)) continue;

        QList<QNetworkAddressEntry> Entries = Iface.addressEntries();
        for (const auto& Entry : Entries) {
            if (Entry.ip().protocol() == QAbstractSocket::IPv4Protocol) {
                Result.append(QString("%1 (%2)").arg(Iface.humanReadableName(), Entry.ip().toString()));
                break;
            }
        }
    }

    if (Result.isEmpty()) {
        Result.append("any");
    }

    return Result;
}

bool PacketCapture::SaveToPcap(const QString& FilePath, const QList<NetworkPacket>& Packets) {
    QFile File(FilePath);
    if (!File.open(QIODevice::WriteOnly)) {
        emit Error(QString("Cannot open file for writing: %1").arg(FilePath));
        return false;
    }

    PcapGlobalHeader GlobalHeader;
    GlobalHeader.MagicNumber = 0xA1B2C3D4;
    GlobalHeader.VersionMajor = 2;
    GlobalHeader.VersionMinor = 4;
    GlobalHeader.ThisZone = 0;
    GlobalHeader.SigFigs = 0;
    GlobalHeader.SnapLen = 65535;
    GlobalHeader.Network = 1;

    File.write(reinterpret_cast<const char*>(&GlobalHeader), sizeof(GlobalHeader));

    for (const auto& Pkt : Packets) {
        PcapPacketHeader PktHeader;
        PktHeader.TsSec = static_cast<uint32_t>(Pkt.Timestamp / 1000);
        PktHeader.TsUsec = static_cast<uint32_t>((Pkt.Timestamp % 1000) * 1000);
        PktHeader.InclLen = static_cast<uint32_t>(Pkt.Data.size());
        PktHeader.OrigLen = static_cast<uint32_t>(Pkt.Data.size());

        File.write(reinterpret_cast<const char*>(&PktHeader), sizeof(PktHeader));
        File.write(Pkt.Data);
    }

    File.close();
    return true;
}

QList<NetworkPacket> PacketCapture::LoadFromPcap(const QString& FilePath) {
    QList<NetworkPacket> Packets;

    QFile File(FilePath);
    if (!File.open(QIODevice::ReadOnly)) {
        emit Error(QString("Cannot open file: %1").arg(FilePath));
        return Packets;
    }

    PcapGlobalHeader GlobalHeader;
    if (File.read(reinterpret_cast<char*>(&GlobalHeader), sizeof(GlobalHeader)) != sizeof(GlobalHeader)) {
        emit Error("Invalid PCAP file: header too short");
        File.close();
        return Packets;
    }

    bool NeedSwap = false;
    if (GlobalHeader.MagicNumber == 0xD4C3B2A1) {
        NeedSwap = true;
    } else if (GlobalHeader.MagicNumber != 0xA1B2C3D4) {
        emit Error("Invalid PCAP file: bad magic number");
        File.close();
        return Packets;
    }

    while (!File.atEnd()) {
        PcapPacketHeader PktHeader;
        if (File.read(reinterpret_cast<char*>(&PktHeader), sizeof(PktHeader)) != sizeof(PktHeader)) {
            break;
        }

        uint32_t InclLen = NeedSwap ? qbswap(PktHeader.InclLen) : PktHeader.InclLen;
        uint32_t TsSec = NeedSwap ? qbswap(PktHeader.TsSec) : PktHeader.TsSec;
        uint32_t TsUsec = NeedSwap ? qbswap(PktHeader.TsUsec) : PktHeader.TsUsec;

        if (InclLen > 262144) {
            emit Error("Invalid PCAP packet: length too large");
            break;
        }

        QByteArray Data = File.read(InclLen);
        if (static_cast<uint32_t>(Data.size()) != InclLen) {
            break;
        }

        NetworkPacket Pkt;
        Pkt.Timestamp = static_cast<uint64_t>(TsSec) * 1000 + TsUsec / 1000;
        Pkt.Data = Data;
        Pkt.Outgoing = false;
        Pkt.SourcePort = 0;
        Pkt.DestPort = 0;

        if (Data.size() >= 34) {
            const uint8_t* Raw = reinterpret_cast<const uint8_t*>(Data.constData());
            uint16_t EtherType;
            memcpy(&EtherType, Raw + 12, 2);
            EtherType = qFromBigEndian(EtherType);

            if (EtherType == 0x0800) {
                int IpOffset = 14;
                uint8_t Ihl = Raw[IpOffset] & 0x0F;
                int IpHeaderLen = Ihl * 4;

                uint8_t SrcBytes[4], DstBytes[4];
                memcpy(SrcBytes, Raw + IpOffset + 12, 4);
                memcpy(DstBytes, Raw + IpOffset + 16, 4);

                Pkt.SourceAddress = QString("%1.%2.%3.%4").arg(SrcBytes[0]).arg(SrcBytes[1]).arg(SrcBytes[2]).arg(SrcBytes[3]);
                Pkt.DestAddress = QString("%1.%2.%3.%4").arg(DstBytes[0]).arg(DstBytes[1]).arg(DstBytes[2]).arg(DstBytes[3]);

                uint8_t Protocol = Raw[IpOffset + 9];
                int TransportOffset = IpOffset + IpHeaderLen;

                if (Protocol == 6) {
                    Pkt.Protocol = "TCP";
                    if (Data.size() >= TransportOffset + 4) {
                        uint16_t SrcPort, DstPort;
                        memcpy(&SrcPort, Raw + TransportOffset, 2);
                        memcpy(&DstPort, Raw + TransportOffset + 2, 2);
                        Pkt.SourcePort = qFromBigEndian(SrcPort);
                        Pkt.DestPort = qFromBigEndian(DstPort);
                    }
                } else if (Protocol == 17) {
                    Pkt.Protocol = "UDP";
                    if (Data.size() >= TransportOffset + 4) {
                        uint16_t SrcPort, DstPort;
                        memcpy(&SrcPort, Raw + TransportOffset, 2);
                        memcpy(&DstPort, Raw + TransportOffset + 2, 2);
                        Pkt.SourcePort = qFromBigEndian(SrcPort);
                        Pkt.DestPort = qFromBigEndian(DstPort);
                    }
                } else if (Protocol == 1) {
                    Pkt.Protocol = "ICMP";
                } else {
                    Pkt.Protocol = QString("IP/%1").arg(Protocol);
                }
            } else if (EtherType == 0x0806) {
                Pkt.Protocol = "ARP";
            } else if (EtherType == 0x86DD) {
                Pkt.Protocol = "IPv6";
                if (Data.size() >= 14 + 40) {
                    int Ipv6Offset = 14;
                    uint8_t NextHeader = Raw[Ipv6Offset + 6];
                    if (NextHeader == 6) Pkt.Protocol = "TCP";
                    else if (NextHeader == 17) Pkt.Protocol = "UDP";
                    else if (NextHeader == 58) Pkt.Protocol = "ICMPv6";
                }
            }
        }

        Packets.append(Pkt);
    }

    File.close();
    return Packets;
}

}
