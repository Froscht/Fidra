#pragma once

#include <QByteArray>
#include <QString>
#include <QList>
#include <QMap>
#include <cstdint>

namespace Fidra {

struct DissectedField {
    QString Name;
    QString Value;
    int Offset;
    int Length;
    QList<DissectedField> Children;
};

struct DissectedLayer {
    QString Protocol;
    int Offset;
    int Length;
    QList<DissectedField> Fields;
};

struct DissectedPacket {
    QList<DissectedLayer> Layers;
    QString Summary;
    QString TopProtocol;
    QString SourceAddress;
    uint16_t SourcePort;
    QString DestAddress;
    uint16_t DestPort;
};

#pragma pack(push, 1)

struct EthernetHeader {
    uint8_t DestMac[6];
    uint8_t SrcMac[6];
    uint16_t EtherType;
};

struct Ipv4Header {
    uint8_t VersionIhl;
    uint8_t Dscp;
    uint16_t TotalLength;
    uint16_t Identification;
    uint16_t FlagsFragment;
    uint8_t Ttl;
    uint8_t Protocol;
    uint16_t Checksum;
    uint32_t SrcAddr;
    uint32_t DstAddr;
};

struct Ipv6Header {
    uint32_t VersionClassFlow;
    uint16_t PayloadLength;
    uint8_t NextHeader;
    uint8_t HopLimit;
    uint8_t SrcAddr[16];
    uint8_t DstAddr[16];
};

struct TcpHeader {
    uint16_t SrcPort;
    uint16_t DstPort;
    uint32_t SeqNumber;
    uint32_t AckNumber;
    uint8_t DataOffsetReserved;
    uint8_t Flags;
    uint16_t WindowSize;
    uint16_t Checksum;
    uint16_t UrgentPointer;
};

struct UdpHeader {
    uint16_t SrcPort;
    uint16_t DstPort;
    uint16_t Length;
    uint16_t Checksum;
};

struct IcmpHeader {
    uint8_t Type;
    uint8_t Code;
    uint16_t Checksum;
    uint32_t RestOfHeader;
};

struct DnsHeader {
    uint16_t TransactionId;
    uint16_t Flags;
    uint16_t QuestionCount;
    uint16_t AnswerCount;
    uint16_t AuthorityCount;
    uint16_t AdditionalCount;
};

#pragma pack(pop)

class ProtocolDissector {
public:
    ProtocolDissector();

    DissectedPacket Dissect(const QByteArray& RawData);
    DissectedPacket DissectFromIp(const QByteArray& RawData);

    static QString FormatMac(const uint8_t* Mac);
    static QString FormatIpv4(uint32_t Addr);
    static QString FormatIpv6(const uint8_t* Addr);
    static uint16_t Ntohs(uint16_t Value);
    static uint32_t Ntohl(uint32_t Value);

private:
    DissectedLayer DissectEthernet(const QByteArray& Data, int Offset, int& NextOffset, uint16_t& NextProtocol);
    DissectedLayer DissectIpv4(const QByteArray& Data, int Offset, int& NextOffset, uint8_t& NextProtocol);
    DissectedLayer DissectIpv6(const QByteArray& Data, int Offset, int& NextOffset, uint8_t& NextProtocol);
    DissectedLayer DissectTcp(const QByteArray& Data, int Offset, int& NextOffset);
    DissectedLayer DissectUdp(const QByteArray& Data, int Offset, int& NextOffset);
    DissectedLayer DissectIcmp(const QByteArray& Data, int Offset);
    DissectedLayer DissectDns(const QByteArray& Data, int Offset);
    DissectedLayer DissectHttp(const QByteArray& Data, int Offset);

    QString ParseDnsName(const QByteArray& Data, int Offset, int BaseOffset, int& BytesConsumed);
    QString GetTcpFlagsString(uint8_t Flags);
    QString GetIcmpTypeName(uint8_t Type);
    QString GetDnsTypeName(uint16_t Type);
    bool IsHttpData(const QByteArray& Data, int Offset);
};

}
