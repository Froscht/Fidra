#include "ProtocolDissector.h"
#include <QtEndian>
#include <QStringList>

namespace Fidra {

ProtocolDissector::ProtocolDissector() {
}

uint16_t ProtocolDissector::Ntohs(uint16_t Value) {
    return qFromBigEndian(Value);
}

uint32_t ProtocolDissector::Ntohl(uint32_t Value) {
    return qFromBigEndian(Value);
}

QString ProtocolDissector::FormatMac(const uint8_t* Mac) {
    return QString("%1:%2:%3:%4:%5:%6")
        .arg(Mac[0], 2, 16, QChar('0'))
        .arg(Mac[1], 2, 16, QChar('0'))
        .arg(Mac[2], 2, 16, QChar('0'))
        .arg(Mac[3], 2, 16, QChar('0'))
        .arg(Mac[4], 2, 16, QChar('0'))
        .arg(Mac[5], 2, 16, QChar('0'));
}

QString ProtocolDissector::FormatIpv4(uint32_t Addr) {
    uint32_t HostAddr = Ntohl(Addr);
    return QString("%1.%2.%3.%4")
        .arg((HostAddr >> 24) & 0xFF)
        .arg((HostAddr >> 16) & 0xFF)
        .arg((HostAddr >> 8) & 0xFF)
        .arg(HostAddr & 0xFF);
}

QString ProtocolDissector::FormatIpv6(const uint8_t* Addr) {
    QStringList Parts;
    for (int I = 0; I < 16; I += 2) {
        uint16_t Word = (static_cast<uint16_t>(Addr[I]) << 8) | Addr[I + 1];
        Parts.append(QString::number(Word, 16));
    }
    return Parts.join(":");
}

DissectedPacket ProtocolDissector::Dissect(const QByteArray& RawData) {
    DissectedPacket Result;
    Result.SourcePort = 0;
    Result.DestPort = 0;

    if (RawData.size() < static_cast<int>(sizeof(EthernetHeader))) {
        Result.Summary = "Truncated frame";
        Result.TopProtocol = "ETH";
        return Result;
    }

    int NextOffset = 0;
    uint16_t EtherType = 0;
    DissectedLayer EthLayer = DissectEthernet(RawData, 0, NextOffset, EtherType);
    Result.Layers.append(EthLayer);

    if (EtherType == 0x0800 && RawData.size() >= NextOffset + static_cast<int>(sizeof(Ipv4Header))) {
        int IpNextOffset = 0;
        uint8_t IpProtocol = 0;
        DissectedLayer Ipv4Layer = DissectIpv4(RawData, NextOffset, IpNextOffset, IpProtocol);
        Result.Layers.append(Ipv4Layer);

        auto* IpHdr = reinterpret_cast<const Ipv4Header*>(RawData.constData() + NextOffset);
        Result.SourceAddress = FormatIpv4(IpHdr->SrcAddr);
        Result.DestAddress = FormatIpv4(IpHdr->DstAddr);

        if (IpProtocol == 6 && RawData.size() >= IpNextOffset + static_cast<int>(sizeof(TcpHeader))) {
            int TcpNextOffset = 0;
            DissectedLayer TcpLayer = DissectTcp(RawData, IpNextOffset, TcpNextOffset);
            Result.Layers.append(TcpLayer);

            auto* TcpHdr = reinterpret_cast<const TcpHeader*>(RawData.constData() + IpNextOffset);
            Result.SourcePort = Ntohs(TcpHdr->SrcPort);
            Result.DestPort = Ntohs(TcpHdr->DstPort);
            Result.TopProtocol = "TCP";

            if (TcpNextOffset < RawData.size() && IsHttpData(RawData, TcpNextOffset)) {
                DissectedLayer HttpLayer = DissectHttp(RawData, TcpNextOffset);
                Result.Layers.append(HttpLayer);
                Result.TopProtocol = "HTTP";
                Result.Summary = HttpLayer.Fields.isEmpty() ? "HTTP Data" : HttpLayer.Fields[0].Value;
            } else {
                Result.Summary = QString("%1 -> %2 [%3] Seq=%4 Ack=%5 Win=%6 Len=%7")
                    .arg(Result.SourcePort)
                    .arg(Result.DestPort)
                    .arg(GetTcpFlagsString(TcpHdr->Flags))
                    .arg(Ntohl(TcpHdr->SeqNumber))
                    .arg(Ntohl(TcpHdr->AckNumber))
                    .arg(Ntohs(TcpHdr->WindowSize))
                    .arg(RawData.size() - TcpNextOffset);
            }
        } else if (IpProtocol == 17 && RawData.size() >= IpNextOffset + static_cast<int>(sizeof(UdpHeader))) {
            int UdpNextOffset = 0;
            DissectedLayer UdpLayer = DissectUdp(RawData, IpNextOffset, UdpNextOffset);
            Result.Layers.append(UdpLayer);

            auto* UdpHdr = reinterpret_cast<const UdpHeader*>(RawData.constData() + IpNextOffset);
            Result.SourcePort = Ntohs(UdpHdr->SrcPort);
            Result.DestPort = Ntohs(UdpHdr->DstPort);
            Result.TopProtocol = "UDP";

            if ((Result.SourcePort == 53 || Result.DestPort == 53) &&
                RawData.size() >= UdpNextOffset + static_cast<int>(sizeof(DnsHeader))) {
                DissectedLayer DnsLayer = DissectDns(RawData, UdpNextOffset);
                Result.Layers.append(DnsLayer);
                Result.TopProtocol = "DNS";
                Result.Summary = DnsLayer.Fields.isEmpty() ? "DNS" : DnsLayer.Fields[0].Value;
            } else {
                Result.Summary = QString("%1 -> %2 Len=%3")
                    .arg(Result.SourcePort)
                    .arg(Result.DestPort)
                    .arg(Ntohs(UdpHdr->Length));
            }
        } else if (IpProtocol == 1 && RawData.size() >= IpNextOffset + static_cast<int>(sizeof(IcmpHeader))) {
            DissectedLayer IcmpLayer = DissectIcmp(RawData, IpNextOffset);
            Result.Layers.append(IcmpLayer);
            Result.TopProtocol = "ICMP";

            auto* IcmpHdr = reinterpret_cast<const IcmpHeader*>(RawData.constData() + IpNextOffset);
            Result.Summary = GetIcmpTypeName(IcmpHdr->Type);
        } else {
            Result.TopProtocol = QString("IPv4/Proto %1").arg(IpProtocol);
            Result.Summary = QString("IP Protocol %1").arg(IpProtocol);
        }
    } else if (EtherType == 0x86DD && RawData.size() >= NextOffset + static_cast<int>(sizeof(Ipv6Header))) {
        int Ipv6NextOffset = 0;
        uint8_t NextHeaderProto = 0;
        DissectedLayer Ipv6Layer = DissectIpv6(RawData, NextOffset, Ipv6NextOffset, NextHeaderProto);
        Result.Layers.append(Ipv6Layer);

        auto* Ipv6Hdr = reinterpret_cast<const Ipv6Header*>(RawData.constData() + NextOffset);
        Result.SourceAddress = FormatIpv6(Ipv6Hdr->SrcAddr);
        Result.DestAddress = FormatIpv6(Ipv6Hdr->DstAddr);

        if (NextHeaderProto == 6 && RawData.size() >= Ipv6NextOffset + static_cast<int>(sizeof(TcpHeader))) {
            int TcpNextOffset = 0;
            DissectedLayer TcpLayer = DissectTcp(RawData, Ipv6NextOffset, TcpNextOffset);
            Result.Layers.append(TcpLayer);

            auto* TcpHdr = reinterpret_cast<const TcpHeader*>(RawData.constData() + Ipv6NextOffset);
            Result.SourcePort = Ntohs(TcpHdr->SrcPort);
            Result.DestPort = Ntohs(TcpHdr->DstPort);
            Result.TopProtocol = "TCP";
            Result.Summary = QString("%1 -> %2 [%3] Seq=%4 Len=%5")
                .arg(Result.SourcePort)
                .arg(Result.DestPort)
                .arg(GetTcpFlagsString(TcpHdr->Flags))
                .arg(Ntohl(TcpHdr->SeqNumber))
                .arg(RawData.size() - TcpNextOffset);
        } else if (NextHeaderProto == 17 && RawData.size() >= Ipv6NextOffset + static_cast<int>(sizeof(UdpHeader))) {
            int UdpNextOffset = 0;
            DissectedLayer UdpLayer = DissectUdp(RawData, Ipv6NextOffset, UdpNextOffset);
            Result.Layers.append(UdpLayer);

            auto* UdpHdr = reinterpret_cast<const UdpHeader*>(RawData.constData() + Ipv6NextOffset);
            Result.SourcePort = Ntohs(UdpHdr->SrcPort);
            Result.DestPort = Ntohs(UdpHdr->DstPort);
            Result.TopProtocol = "UDP";
            Result.Summary = QString("%1 -> %2 Len=%3")
                .arg(Result.SourcePort)
                .arg(Result.DestPort)
                .arg(Ntohs(UdpHdr->Length));
        } else if (NextHeaderProto == 58 && RawData.size() >= Ipv6NextOffset + static_cast<int>(sizeof(IcmpHeader))) {
            DissectedLayer IcmpLayer = DissectIcmp(RawData, Ipv6NextOffset);
            Result.Layers.append(IcmpLayer);
            Result.TopProtocol = "ICMPv6";
            auto* IcmpHdr = reinterpret_cast<const IcmpHeader*>(RawData.constData() + Ipv6NextOffset);
            Result.Summary = GetIcmpTypeName(IcmpHdr->Type);
        } else {
            Result.TopProtocol = "IPv6";
            Result.Summary = QString("Next Header: %1").arg(NextHeaderProto);
        }
    } else if (EtherType == 0x0806) {
        Result.TopProtocol = "ARP";
        Result.Summary = "ARP";
    } else {
        Result.TopProtocol = QString("0x%1").arg(EtherType, 4, 16, QChar('0'));
        Result.Summary = QString("EtherType 0x%1").arg(EtherType, 4, 16, QChar('0'));
    }

    return Result;
}

DissectedPacket ProtocolDissector::DissectFromIp(const QByteArray& RawData) {
    DissectedPacket Result;
    Result.SourcePort = 0;
    Result.DestPort = 0;

    if (RawData.size() < 1) {
        Result.Summary = "Empty packet";
        Result.TopProtocol = "???";
        return Result;
    }

    uint8_t Version = (static_cast<uint8_t>(RawData[0]) >> 4) & 0x0F;

    if (Version == 4 && RawData.size() >= static_cast<int>(sizeof(Ipv4Header))) {
        int IpNextOffset = 0;
        uint8_t IpProtocol = 0;
        DissectedLayer Ipv4Layer = DissectIpv4(RawData, 0, IpNextOffset, IpProtocol);
        Result.Layers.append(Ipv4Layer);

        auto* IpHdr = reinterpret_cast<const Ipv4Header*>(RawData.constData());
        Result.SourceAddress = FormatIpv4(IpHdr->SrcAddr);
        Result.DestAddress = FormatIpv4(IpHdr->DstAddr);

        if (IpProtocol == 6 && RawData.size() >= IpNextOffset + static_cast<int>(sizeof(TcpHeader))) {
            int TcpNextOffset = 0;
            DissectedLayer TcpLayer = DissectTcp(RawData, IpNextOffset, TcpNextOffset);
            Result.Layers.append(TcpLayer);

            auto* TcpHdr = reinterpret_cast<const TcpHeader*>(RawData.constData() + IpNextOffset);
            Result.SourcePort = Ntohs(TcpHdr->SrcPort);
            Result.DestPort = Ntohs(TcpHdr->DstPort);
            Result.TopProtocol = "TCP";

            if (TcpNextOffset < RawData.size() && IsHttpData(RawData, TcpNextOffset)) {
                DissectedLayer HttpLayer = DissectHttp(RawData, TcpNextOffset);
                Result.Layers.append(HttpLayer);
                Result.TopProtocol = "HTTP";
                Result.Summary = HttpLayer.Fields.isEmpty() ? "HTTP Data" : HttpLayer.Fields[0].Value;
            } else {
                Result.Summary = QString("%1 -> %2 [%3] Seq=%4 Ack=%5 Win=%6 Len=%7")
                    .arg(Result.SourcePort)
                    .arg(Result.DestPort)
                    .arg(GetTcpFlagsString(TcpHdr->Flags))
                    .arg(Ntohl(TcpHdr->SeqNumber))
                    .arg(Ntohl(TcpHdr->AckNumber))
                    .arg(Ntohs(TcpHdr->WindowSize))
                    .arg(RawData.size() - TcpNextOffset);
            }
        } else if (IpProtocol == 17 && RawData.size() >= IpNextOffset + static_cast<int>(sizeof(UdpHeader))) {
            int UdpNextOffset = 0;
            DissectedLayer UdpLayer = DissectUdp(RawData, IpNextOffset, UdpNextOffset);
            Result.Layers.append(UdpLayer);

            auto* UdpHdr = reinterpret_cast<const UdpHeader*>(RawData.constData() + IpNextOffset);
            Result.SourcePort = Ntohs(UdpHdr->SrcPort);
            Result.DestPort = Ntohs(UdpHdr->DstPort);
            Result.TopProtocol = "UDP";

            if ((Result.SourcePort == 53 || Result.DestPort == 53) &&
                RawData.size() >= UdpNextOffset + static_cast<int>(sizeof(DnsHeader))) {
                DissectedLayer DnsLayer = DissectDns(RawData, UdpNextOffset);
                Result.Layers.append(DnsLayer);
                Result.TopProtocol = "DNS";
                Result.Summary = DnsLayer.Fields.isEmpty() ? "DNS" : DnsLayer.Fields[0].Value;
            } else {
                Result.Summary = QString("%1 -> %2 Len=%3")
                    .arg(Result.SourcePort)
                    .arg(Result.DestPort)
                    .arg(Ntohs(UdpHdr->Length));
            }
        } else if (IpProtocol == 1 && RawData.size() >= IpNextOffset + static_cast<int>(sizeof(IcmpHeader))) {
            DissectedLayer IcmpLayer = DissectIcmp(RawData, IpNextOffset);
            Result.Layers.append(IcmpLayer);
            Result.TopProtocol = "ICMP";
            auto* IcmpHdr = reinterpret_cast<const IcmpHeader*>(RawData.constData() + IpNextOffset);
            Result.Summary = GetIcmpTypeName(IcmpHdr->Type);
        } else {
            Result.TopProtocol = "IP";
            Result.Summary = QString("Protocol %1").arg(IpProtocol);
        }
    } else if (Version == 6 && RawData.size() >= static_cast<int>(sizeof(Ipv6Header))) {
        int Ipv6NextOffset = 0;
        uint8_t NextHeaderProto = 0;
        DissectedLayer Ipv6Layer = DissectIpv6(RawData, 0, Ipv6NextOffset, NextHeaderProto);
        Result.Layers.append(Ipv6Layer);

        auto* Ipv6Hdr = reinterpret_cast<const Ipv6Header*>(RawData.constData());
        Result.SourceAddress = FormatIpv6(Ipv6Hdr->SrcAddr);
        Result.DestAddress = FormatIpv6(Ipv6Hdr->DstAddr);
        Result.TopProtocol = "IPv6";
        Result.Summary = QString("Next Header: %1").arg(NextHeaderProto);
    } else {
        Result.TopProtocol = "???";
        Result.Summary = "Unknown IP version";
    }

    return Result;
}

DissectedLayer ProtocolDissector::DissectEthernet(const QByteArray& Data, int Offset, int& NextOffset, uint16_t& NextProtocol) {
    DissectedLayer Layer;
    Layer.Protocol = "Ethernet II";
    Layer.Offset = Offset;
    Layer.Length = 14;

    auto* Hdr = reinterpret_cast<const EthernetHeader*>(Data.constData() + Offset);
    NextProtocol = Ntohs(Hdr->EtherType);
    NextOffset = Offset + 14;

    DissectedField DstField;
    DstField.Name = "Destination";
    DstField.Value = FormatMac(Hdr->DestMac);
    DstField.Offset = Offset;
    DstField.Length = 6;
    Layer.Fields.append(DstField);

    DissectedField SrcField;
    SrcField.Name = "Source";
    SrcField.Value = FormatMac(Hdr->SrcMac);
    SrcField.Offset = Offset + 6;
    SrcField.Length = 6;
    Layer.Fields.append(SrcField);

    DissectedField TypeField;
    TypeField.Name = "Type";
    TypeField.Value = QString("0x%1").arg(NextProtocol, 4, 16, QChar('0'));
    TypeField.Offset = Offset + 12;
    TypeField.Length = 2;

    if (NextProtocol == 0x0800) TypeField.Value += " (IPv4)";
    else if (NextProtocol == 0x86DD) TypeField.Value += " (IPv6)";
    else if (NextProtocol == 0x0806) TypeField.Value += " (ARP)";

    Layer.Fields.append(TypeField);

    return Layer;
}

DissectedLayer ProtocolDissector::DissectIpv4(const QByteArray& Data, int Offset, int& NextOffset, uint8_t& NextProtocol) {
    DissectedLayer Layer;
    Layer.Protocol = "Internet Protocol Version 4";
    Layer.Offset = Offset;

    auto* Hdr = reinterpret_cast<const Ipv4Header*>(Data.constData() + Offset);
    uint8_t Version = (Hdr->VersionIhl >> 4) & 0x0F;
    uint8_t Ihl = Hdr->VersionIhl & 0x0F;
    int HeaderLen = Ihl * 4;
    Layer.Length = HeaderLen;

    NextProtocol = Hdr->Protocol;
    NextOffset = Offset + HeaderLen;

    DissectedField VersionField;
    VersionField.Name = "Version";
    VersionField.Value = QString::number(Version);
    VersionField.Offset = Offset;
    VersionField.Length = 1;
    Layer.Fields.append(VersionField);

    DissectedField IhlField;
    IhlField.Name = "Header Length";
    IhlField.Value = QString("%1 bytes (%2)").arg(HeaderLen).arg(Ihl);
    IhlField.Offset = Offset;
    IhlField.Length = 1;
    Layer.Fields.append(IhlField);

    DissectedField DscpField;
    DscpField.Name = "Differentiated Services";
    DscpField.Value = QString("0x%1").arg(Hdr->Dscp, 2, 16, QChar('0'));
    DscpField.Offset = Offset + 1;
    DscpField.Length = 1;
    Layer.Fields.append(DscpField);

    DissectedField TotalLenField;
    TotalLenField.Name = "Total Length";
    TotalLenField.Value = QString::number(Ntohs(Hdr->TotalLength));
    TotalLenField.Offset = Offset + 2;
    TotalLenField.Length = 2;
    Layer.Fields.append(TotalLenField);

    DissectedField IdField;
    IdField.Name = "Identification";
    IdField.Value = QString("0x%1 (%2)").arg(Ntohs(Hdr->Identification), 4, 16, QChar('0')).arg(Ntohs(Hdr->Identification));
    IdField.Offset = Offset + 4;
    IdField.Length = 2;
    Layer.Fields.append(IdField);

    uint16_t FlagsFragment = Ntohs(Hdr->FlagsFragment);
    uint8_t IpFlags = (FlagsFragment >> 13) & 0x07;
    uint16_t FragOffset = FlagsFragment & 0x1FFF;

    DissectedField FlagsField;
    FlagsField.Name = "Flags";
    FlagsField.Value = QString("0x%1").arg(IpFlags, 1, 16);
    FlagsField.Offset = Offset + 6;
    FlagsField.Length = 2;

    DissectedField DfChild;
    DfChild.Name = "Don't Fragment";
    DfChild.Value = (IpFlags & 0x02) ? "Set" : "Not set";
    DfChild.Offset = Offset + 6;
    DfChild.Length = 1;
    FlagsField.Children.append(DfChild);

    DissectedField MfChild;
    MfChild.Name = "More Fragments";
    MfChild.Value = (IpFlags & 0x01) ? "Set" : "Not set";
    MfChild.Offset = Offset + 6;
    MfChild.Length = 1;
    FlagsField.Children.append(MfChild);

    Layer.Fields.append(FlagsField);

    DissectedField FragField;
    FragField.Name = "Fragment Offset";
    FragField.Value = QString::number(FragOffset);
    FragField.Offset = Offset + 6;
    FragField.Length = 2;
    Layer.Fields.append(FragField);

    DissectedField TtlField;
    TtlField.Name = "Time to Live";
    TtlField.Value = QString::number(Hdr->Ttl);
    TtlField.Offset = Offset + 8;
    TtlField.Length = 1;
    Layer.Fields.append(TtlField);

    DissectedField ProtoField;
    ProtoField.Name = "Protocol";
    ProtoField.Offset = Offset + 9;
    ProtoField.Length = 1;
    if (NextProtocol == 1) ProtoField.Value = "ICMP (1)";
    else if (NextProtocol == 6) ProtoField.Value = "TCP (6)";
    else if (NextProtocol == 17) ProtoField.Value = "UDP (17)";
    else ProtoField.Value = QString::number(NextProtocol);
    Layer.Fields.append(ProtoField);

    DissectedField ChecksumField;
    ChecksumField.Name = "Header Checksum";
    ChecksumField.Value = QString("0x%1").arg(Ntohs(Hdr->Checksum), 4, 16, QChar('0'));
    ChecksumField.Offset = Offset + 10;
    ChecksumField.Length = 2;
    Layer.Fields.append(ChecksumField);

    DissectedField SrcField;
    SrcField.Name = "Source Address";
    SrcField.Value = FormatIpv4(Hdr->SrcAddr);
    SrcField.Offset = Offset + 12;
    SrcField.Length = 4;
    Layer.Fields.append(SrcField);

    DissectedField DstField;
    DstField.Name = "Destination Address";
    DstField.Value = FormatIpv4(Hdr->DstAddr);
    DstField.Offset = Offset + 16;
    DstField.Length = 4;
    Layer.Fields.append(DstField);

    return Layer;
}

DissectedLayer ProtocolDissector::DissectIpv6(const QByteArray& Data, int Offset, int& NextOffset, uint8_t& NextProtocol) {
    DissectedLayer Layer;
    Layer.Protocol = "Internet Protocol Version 6";
    Layer.Offset = Offset;
    Layer.Length = 40;

    auto* Hdr = reinterpret_cast<const Ipv6Header*>(Data.constData() + Offset);
    uint32_t VcfHost = Ntohl(Hdr->VersionClassFlow);
    uint8_t Version = (VcfHost >> 28) & 0x0F;
    uint8_t TrafficClass = (VcfHost >> 20) & 0xFF;
    uint32_t FlowLabel = VcfHost & 0xFFFFF;

    NextProtocol = Hdr->NextHeader;
    NextOffset = Offset + 40;

    DissectedField VersionField;
    VersionField.Name = "Version";
    VersionField.Value = QString::number(Version);
    VersionField.Offset = Offset;
    VersionField.Length = 1;
    Layer.Fields.append(VersionField);

    DissectedField TrafficField;
    TrafficField.Name = "Traffic Class";
    TrafficField.Value = QString("0x%1").arg(TrafficClass, 2, 16, QChar('0'));
    TrafficField.Offset = Offset;
    TrafficField.Length = 2;
    Layer.Fields.append(TrafficField);

    DissectedField FlowField;
    FlowField.Name = "Flow Label";
    FlowField.Value = QString("0x%1").arg(FlowLabel, 5, 16, QChar('0'));
    FlowField.Offset = Offset;
    FlowField.Length = 4;
    Layer.Fields.append(FlowField);

    DissectedField PayloadField;
    PayloadField.Name = "Payload Length";
    PayloadField.Value = QString::number(Ntohs(Hdr->PayloadLength));
    PayloadField.Offset = Offset + 4;
    PayloadField.Length = 2;
    Layer.Fields.append(PayloadField);

    DissectedField NextHdrField;
    NextHdrField.Name = "Next Header";
    NextHdrField.Offset = Offset + 6;
    NextHdrField.Length = 1;
    if (NextProtocol == 6) NextHdrField.Value = "TCP (6)";
    else if (NextProtocol == 17) NextHdrField.Value = "UDP (17)";
    else if (NextProtocol == 58) NextHdrField.Value = "ICMPv6 (58)";
    else NextHdrField.Value = QString::number(NextProtocol);
    Layer.Fields.append(NextHdrField);

    DissectedField HopField;
    HopField.Name = "Hop Limit";
    HopField.Value = QString::number(Hdr->HopLimit);
    HopField.Offset = Offset + 7;
    HopField.Length = 1;
    Layer.Fields.append(HopField);

    DissectedField SrcField;
    SrcField.Name = "Source Address";
    SrcField.Value = FormatIpv6(Hdr->SrcAddr);
    SrcField.Offset = Offset + 8;
    SrcField.Length = 16;
    Layer.Fields.append(SrcField);

    DissectedField DstField;
    DstField.Name = "Destination Address";
    DstField.Value = FormatIpv6(Hdr->DstAddr);
    DstField.Offset = Offset + 24;
    DstField.Length = 16;
    Layer.Fields.append(DstField);

    return Layer;
}

DissectedLayer ProtocolDissector::DissectTcp(const QByteArray& Data, int Offset, int& NextOffset) {
    DissectedLayer Layer;
    Layer.Protocol = "Transmission Control Protocol";
    Layer.Offset = Offset;

    auto* Hdr = reinterpret_cast<const TcpHeader*>(Data.constData() + Offset);
    uint8_t DataOffset = (Hdr->DataOffsetReserved >> 4) & 0x0F;
    int HeaderLen = DataOffset * 4;
    Layer.Length = HeaderLen;
    NextOffset = Offset + HeaderLen;

    DissectedField SrcPortField;
    SrcPortField.Name = "Source Port";
    SrcPortField.Value = QString::number(Ntohs(Hdr->SrcPort));
    SrcPortField.Offset = Offset;
    SrcPortField.Length = 2;
    Layer.Fields.append(SrcPortField);

    DissectedField DstPortField;
    DstPortField.Name = "Destination Port";
    DstPortField.Value = QString::number(Ntohs(Hdr->DstPort));
    DstPortField.Offset = Offset + 2;
    DstPortField.Length = 2;
    Layer.Fields.append(DstPortField);

    DissectedField SeqField;
    SeqField.Name = "Sequence Number";
    SeqField.Value = QString::number(Ntohl(Hdr->SeqNumber));
    SeqField.Offset = Offset + 4;
    SeqField.Length = 4;
    Layer.Fields.append(SeqField);

    DissectedField AckField;
    AckField.Name = "Acknowledgment Number";
    AckField.Value = QString::number(Ntohl(Hdr->AckNumber));
    AckField.Offset = Offset + 8;
    AckField.Length = 4;
    Layer.Fields.append(AckField);

    DissectedField DataOffField;
    DataOffField.Name = "Data Offset";
    DataOffField.Value = QString("%1 bytes (%2)").arg(HeaderLen).arg(DataOffset);
    DataOffField.Offset = Offset + 12;
    DataOffField.Length = 1;
    Layer.Fields.append(DataOffField);

    DissectedField FlagsField;
    FlagsField.Name = "Flags";
    FlagsField.Value = QString("0x%1 [%2]").arg(Hdr->Flags, 2, 16, QChar('0')).arg(GetTcpFlagsString(Hdr->Flags));
    FlagsField.Offset = Offset + 13;
    FlagsField.Length = 1;

    struct FlagEntry { QString FlagName; uint8_t Mask; };
    FlagEntry AllFlags[] = {
        {"FIN", 0x01}, {"SYN", 0x02}, {"RST", 0x04}, {"PSH", 0x08},
        {"ACK", 0x10}, {"URG", 0x20}, {"ECE", 0x40}, {"CWR", 0x80}
    };
    for (auto& Fe : AllFlags) {
        DissectedField FlagChild;
        FlagChild.Name = Fe.FlagName;
        FlagChild.Value = (Hdr->Flags & Fe.Mask) ? "Set" : "Not set";
        FlagChild.Offset = Offset + 13;
        FlagChild.Length = 1;
        FlagsField.Children.append(FlagChild);
    }
    Layer.Fields.append(FlagsField);

    DissectedField WinField;
    WinField.Name = "Window Size";
    WinField.Value = QString::number(Ntohs(Hdr->WindowSize));
    WinField.Offset = Offset + 14;
    WinField.Length = 2;
    Layer.Fields.append(WinField);

    DissectedField CsumField;
    CsumField.Name = "Checksum";
    CsumField.Value = QString("0x%1").arg(Ntohs(Hdr->Checksum), 4, 16, QChar('0'));
    CsumField.Offset = Offset + 16;
    CsumField.Length = 2;
    Layer.Fields.append(CsumField);

    DissectedField UrgField;
    UrgField.Name = "Urgent Pointer";
    UrgField.Value = QString::number(Ntohs(Hdr->UrgentPointer));
    UrgField.Offset = Offset + 18;
    UrgField.Length = 2;
    Layer.Fields.append(UrgField);

    return Layer;
}

DissectedLayer ProtocolDissector::DissectUdp(const QByteArray& Data, int Offset, int& NextOffset) {
    DissectedLayer Layer;
    Layer.Protocol = "User Datagram Protocol";
    Layer.Offset = Offset;
    Layer.Length = 8;
    NextOffset = Offset + 8;

    auto* Hdr = reinterpret_cast<const UdpHeader*>(Data.constData() + Offset);

    DissectedField SrcPortField;
    SrcPortField.Name = "Source Port";
    SrcPortField.Value = QString::number(Ntohs(Hdr->SrcPort));
    SrcPortField.Offset = Offset;
    SrcPortField.Length = 2;
    Layer.Fields.append(SrcPortField);

    DissectedField DstPortField;
    DstPortField.Name = "Destination Port";
    DstPortField.Value = QString::number(Ntohs(Hdr->DstPort));
    DstPortField.Offset = Offset + 2;
    DstPortField.Length = 2;
    Layer.Fields.append(DstPortField);

    DissectedField LenField;
    LenField.Name = "Length";
    LenField.Value = QString::number(Ntohs(Hdr->Length));
    LenField.Offset = Offset + 4;
    LenField.Length = 2;
    Layer.Fields.append(LenField);

    DissectedField CsumField;
    CsumField.Name = "Checksum";
    CsumField.Value = QString("0x%1").arg(Ntohs(Hdr->Checksum), 4, 16, QChar('0'));
    CsumField.Offset = Offset + 6;
    CsumField.Length = 2;
    Layer.Fields.append(CsumField);

    return Layer;
}

DissectedLayer ProtocolDissector::DissectIcmp(const QByteArray& Data, int Offset) {
    DissectedLayer Layer;
    Layer.Protocol = "Internet Control Message Protocol";
    Layer.Offset = Offset;
    Layer.Length = Data.size() - Offset;

    auto* Hdr = reinterpret_cast<const IcmpHeader*>(Data.constData() + Offset);

    DissectedField TypeField;
    TypeField.Name = "Type";
    TypeField.Value = QString("%1 (%2)").arg(Hdr->Type).arg(GetIcmpTypeName(Hdr->Type));
    TypeField.Offset = Offset;
    TypeField.Length = 1;
    Layer.Fields.append(TypeField);

    DissectedField CodeField;
    CodeField.Name = "Code";
    CodeField.Value = QString::number(Hdr->Code);
    CodeField.Offset = Offset + 1;
    CodeField.Length = 1;
    Layer.Fields.append(CodeField);

    DissectedField CsumField;
    CsumField.Name = "Checksum";
    CsumField.Value = QString("0x%1").arg(Ntohs(Hdr->Checksum), 4, 16, QChar('0'));
    CsumField.Offset = Offset + 2;
    CsumField.Length = 2;
    Layer.Fields.append(CsumField);

    if (Hdr->Type == 0 || Hdr->Type == 8) {
        uint16_t Identifier = Ntohs(static_cast<uint16_t>(Ntohl(Hdr->RestOfHeader) >> 16));
        uint16_t SeqNum = Ntohs(static_cast<uint16_t>(Ntohl(Hdr->RestOfHeader) & 0xFFFF));

        DissectedField IdField;
        IdField.Name = "Identifier";
        IdField.Value = QString("0x%1").arg(Identifier, 4, 16, QChar('0'));
        IdField.Offset = Offset + 4;
        IdField.Length = 2;
        Layer.Fields.append(IdField);

        DissectedField SeqField;
        SeqField.Name = "Sequence Number";
        SeqField.Value = QString::number(SeqNum);
        SeqField.Offset = Offset + 6;
        SeqField.Length = 2;
        Layer.Fields.append(SeqField);
    }

    return Layer;
}

DissectedLayer ProtocolDissector::DissectDns(const QByteArray& Data, int Offset) {
    DissectedLayer Layer;
    Layer.Protocol = "Domain Name System";
    Layer.Offset = Offset;
    Layer.Length = Data.size() - Offset;

    auto* Hdr = reinterpret_cast<const DnsHeader*>(Data.constData() + Offset);
    uint16_t Flags = Ntohs(Hdr->Flags);
    bool IsResponse = (Flags >> 15) & 1;
    uint16_t QuestionCount = Ntohs(Hdr->QuestionCount);
    uint16_t AnswerCount = Ntohs(Hdr->AnswerCount);

    DissectedField TxIdField;
    TxIdField.Name = "Transaction ID";
    TxIdField.Value = QString("0x%1").arg(Ntohs(Hdr->TransactionId), 4, 16, QChar('0'));
    TxIdField.Offset = Offset;
    TxIdField.Length = 2;
    Layer.Fields.append(TxIdField);

    DissectedField FlagsField;
    FlagsField.Name = "Flags";
    FlagsField.Value = QString("0x%1").arg(Flags, 4, 16, QChar('0'));
    FlagsField.Offset = Offset + 2;
    FlagsField.Length = 2;

    DissectedField QrChild;
    QrChild.Name = "QR";
    QrChild.Value = IsResponse ? "Response" : "Query";
    QrChild.Offset = Offset + 2;
    QrChild.Length = 2;
    FlagsField.Children.append(QrChild);

    uint8_t Opcode = (Flags >> 11) & 0x0F;
    DissectedField OpcodeChild;
    OpcodeChild.Name = "Opcode";
    OpcodeChild.Value = QString::number(Opcode);
    OpcodeChild.Offset = Offset + 2;
    OpcodeChild.Length = 2;
    FlagsField.Children.append(OpcodeChild);

    DissectedField RcodeChild;
    RcodeChild.Name = "Reply Code";
    RcodeChild.Value = QString::number(Flags & 0x0F);
    RcodeChild.Offset = Offset + 2;
    RcodeChild.Length = 2;
    FlagsField.Children.append(RcodeChild);

    Layer.Fields.append(FlagsField);

    DissectedField QcField;
    QcField.Name = "Questions";
    QcField.Value = QString::number(QuestionCount);
    QcField.Offset = Offset + 4;
    QcField.Length = 2;
    Layer.Fields.append(QcField);

    DissectedField AcField;
    AcField.Name = "Answer RRs";
    AcField.Value = QString::number(AnswerCount);
    AcField.Offset = Offset + 6;
    AcField.Length = 2;
    Layer.Fields.append(AcField);

    DissectedField AuthField;
    AuthField.Name = "Authority RRs";
    AuthField.Value = QString::number(Ntohs(Hdr->AuthorityCount));
    AuthField.Offset = Offset + 8;
    AuthField.Length = 2;
    Layer.Fields.append(AuthField);

    DissectedField AddField;
    AddField.Name = "Additional RRs";
    AddField.Value = QString::number(Ntohs(Hdr->AdditionalCount));
    AddField.Offset = Offset + 10;
    AddField.Length = 2;
    Layer.Fields.append(AddField);

    int CurrentPos = Offset + 12;
    QString FirstQueryName;

    for (uint16_t I = 0; I < QuestionCount && CurrentPos < Data.size(); ++I) {
        int BytesConsumed = 0;
        QString QName = ParseDnsName(Data, CurrentPos, Offset, BytesConsumed);
        CurrentPos += BytesConsumed;

        if (CurrentPos + 4 > Data.size()) break;

        uint16_t QType = Ntohs(*reinterpret_cast<const uint16_t*>(Data.constData() + CurrentPos));
        uint16_t QClass = Ntohs(*reinterpret_cast<const uint16_t*>(Data.constData() + CurrentPos + 2));
        CurrentPos += 4;

        DissectedField QueryField;
        QueryField.Name = QString("Query %1").arg(I + 1);
        QueryField.Value = QName;
        QueryField.Offset = Offset + 12;
        QueryField.Length = BytesConsumed + 4;

        DissectedField NameChild;
        NameChild.Name = "Name";
        NameChild.Value = QName;
        NameChild.Offset = 0;
        NameChild.Length = BytesConsumed;
        QueryField.Children.append(NameChild);

        DissectedField TypeChild;
        TypeChild.Name = "Type";
        TypeChild.Value = GetDnsTypeName(QType);
        TypeChild.Offset = 0;
        TypeChild.Length = 2;
        QueryField.Children.append(TypeChild);

        DissectedField ClassChild;
        ClassChild.Name = "Class";
        ClassChild.Value = QClass == 1 ? "IN (1)" : QString::number(QClass);
        ClassChild.Offset = 0;
        ClassChild.Length = 2;
        QueryField.Children.append(ClassChild);

        Layer.Fields.append(QueryField);

        if (I == 0) FirstQueryName = QName;
    }

    for (uint16_t I = 0; I < AnswerCount && CurrentPos < Data.size(); ++I) {
        int BytesConsumed = 0;
        QString AName = ParseDnsName(Data, CurrentPos, Offset, BytesConsumed);
        CurrentPos += BytesConsumed;

        if (CurrentPos + 10 > Data.size()) break;

        uint16_t AType = Ntohs(*reinterpret_cast<const uint16_t*>(Data.constData() + CurrentPos));
        CurrentPos += 2;
        CurrentPos += 2;
        CurrentPos += 4;
        uint16_t RdLength = Ntohs(*reinterpret_cast<const uint16_t*>(Data.constData() + CurrentPos));
        CurrentPos += 2;

        QString RdataStr;
        if (AType == 1 && RdLength == 4 && CurrentPos + 4 <= Data.size()) {
            uint32_t Addr = *reinterpret_cast<const uint32_t*>(Data.constData() + CurrentPos);
            RdataStr = FormatIpv4(Addr);
        } else if (AType == 28 && RdLength == 16 && CurrentPos + 16 <= Data.size()) {
            RdataStr = FormatIpv6(reinterpret_cast<const uint8_t*>(Data.constData() + CurrentPos));
        } else if (AType == 5 && CurrentPos < Data.size()) {
            int CnameConsumed = 0;
            RdataStr = ParseDnsName(Data, CurrentPos, Offset, CnameConsumed);
        } else {
            RdataStr = QString("%1 bytes").arg(RdLength);
        }

        DissectedField AnswerField;
        AnswerField.Name = QString("Answer %1").arg(I + 1);
        AnswerField.Value = QString("%1 -> %2").arg(AName, RdataStr);
        AnswerField.Offset = 0;
        AnswerField.Length = 0;

        DissectedField NameChild;
        NameChild.Name = "Name";
        NameChild.Value = AName;
        NameChild.Offset = 0;
        NameChild.Length = 0;
        AnswerField.Children.append(NameChild);

        DissectedField TypeChild;
        TypeChild.Name = "Type";
        TypeChild.Value = GetDnsTypeName(AType);
        TypeChild.Offset = 0;
        TypeChild.Length = 2;
        AnswerField.Children.append(TypeChild);

        DissectedField DataChild;
        DataChild.Name = "Data";
        DataChild.Value = RdataStr;
        DataChild.Offset = 0;
        DataChild.Length = RdLength;
        AnswerField.Children.append(DataChild);

        Layer.Fields.append(AnswerField);

        CurrentPos += RdLength;
    }

    if (!FirstQueryName.isEmpty()) {
        DissectedField SummaryField;
        SummaryField.Name = "Info";
        SummaryField.Value = QString("%1 %2 %3").arg(IsResponse ? "Response" : "Query").arg(FirstQueryName).arg(AnswerCount > 0 ? QString("(%1 answers)").arg(AnswerCount) : "");
        SummaryField.Offset = 0;
        SummaryField.Length = 0;
        Layer.Fields.insert(0, SummaryField);
    }

    return Layer;
}

DissectedLayer ProtocolDissector::DissectHttp(const QByteArray& Data, int Offset) {
    DissectedLayer Layer;
    Layer.Protocol = "Hypertext Transfer Protocol";
    Layer.Offset = Offset;
    Layer.Length = Data.size() - Offset;

    QByteArray HttpData = Data.mid(Offset);
    int HeaderEnd = HttpData.indexOf("\r\n\r\n");
    if (HeaderEnd == -1) HeaderEnd = HttpData.indexOf("\n\n");

    QByteArray HeaderSection = (HeaderEnd != -1) ? HttpData.left(HeaderEnd) : HttpData;
    QList<QByteArray> Lines = HeaderSection.split('\n');

    if (Lines.isEmpty()) return Layer;

    QString FirstLine = QString::fromUtf8(Lines[0]).trimmed();

    DissectedField RequestField;
    RequestField.Name = "Request/Status Line";
    RequestField.Value = FirstLine;
    RequestField.Offset = Offset;
    RequestField.Length = Lines[0].size();
    Layer.Fields.append(RequestField);

    if (FirstLine.startsWith("HTTP/")) {
        QStringList Parts = FirstLine.split(' ');
        if (Parts.size() >= 2) {
            DissectedField VersionChild;
            VersionChild.Name = "Version";
            VersionChild.Value = Parts[0];
            VersionChild.Offset = Offset;
            VersionChild.Length = Parts[0].size();
            Layer.Fields.append(VersionChild);

            DissectedField StatusChild;
            StatusChild.Name = "Status Code";
            StatusChild.Value = Parts[1];
            StatusChild.Offset = Offset;
            StatusChild.Length = Parts[1].size();
            Layer.Fields.append(StatusChild);

            if (Parts.size() >= 3) {
                DissectedField ReasonChild;
                ReasonChild.Name = "Reason Phrase";
                ReasonChild.Value = Parts.mid(2).join(' ');
                ReasonChild.Offset = Offset;
                ReasonChild.Length = 0;
                Layer.Fields.append(ReasonChild);
            }
        }
    } else {
        QStringList Parts = FirstLine.split(' ');
        if (Parts.size() >= 2) {
            DissectedField MethodChild;
            MethodChild.Name = "Method";
            MethodChild.Value = Parts[0];
            MethodChild.Offset = Offset;
            MethodChild.Length = Parts[0].size();
            Layer.Fields.append(MethodChild);

            DissectedField UriChild;
            UriChild.Name = "URI";
            UriChild.Value = Parts[1];
            UriChild.Offset = Offset;
            UriChild.Length = Parts[1].size();
            Layer.Fields.append(UriChild);

            if (Parts.size() >= 3) {
                DissectedField VersionChild;
                VersionChild.Name = "Version";
                VersionChild.Value = Parts[2];
                VersionChild.Offset = Offset;
                VersionChild.Length = Parts[2].size();
                Layer.Fields.append(VersionChild);
            }
        }
    }

    DissectedField HeadersField;
    HeadersField.Name = "Headers";
    HeadersField.Value = QString("%1 headers").arg(Lines.size() - 1);
    HeadersField.Offset = Offset;
    HeadersField.Length = 0;

    for (int I = 1; I < Lines.size(); ++I) {
        QString HeaderLine = QString::fromUtf8(Lines[I]).trimmed();
        if (HeaderLine.isEmpty()) continue;

        int ColonPos = HeaderLine.indexOf(':');
        if (ColonPos > 0) {
            DissectedField HdrChild;
            HdrChild.Name = HeaderLine.left(ColonPos).trimmed();
            HdrChild.Value = HeaderLine.mid(ColonPos + 1).trimmed();
            HdrChild.Offset = 0;
            HdrChild.Length = 0;
            HeadersField.Children.append(HdrChild);
        }
    }

    Layer.Fields.append(HeadersField);

    if (HeaderEnd != -1) {
        int BodyStart = HeaderEnd + ((HttpData.indexOf("\r\n\r\n") != -1) ? 4 : 2);
        int BodyLen = HttpData.size() - BodyStart;
        if (BodyLen > 0) {
            DissectedField BodyField;
            BodyField.Name = "Body";
            BodyField.Value = QString("%1 bytes").arg(BodyLen);
            BodyField.Offset = Offset + BodyStart;
            BodyField.Length = BodyLen;
            Layer.Fields.append(BodyField);
        }
    }

    return Layer;
}

QString ProtocolDissector::ParseDnsName(const QByteArray& Data, int Offset, int BaseOffset, int& BytesConsumed) {
    QStringList Labels;
    int Pos = Offset;
    BytesConsumed = 0;
    bool FollowedPointer = false;
    int MaxIterations = 128;

    while (Pos < Data.size() && MaxIterations-- > 0) {
        uint8_t Len = static_cast<uint8_t>(Data[Pos]);

        if (Len == 0) {
            if (!FollowedPointer) BytesConsumed = Pos - Offset + 1;
            break;
        }

        if ((Len & 0xC0) == 0xC0) {
            if (Pos + 1 >= Data.size()) break;
            uint16_t Pointer = ((static_cast<uint16_t>(Len) & 0x3F) << 8) | static_cast<uint8_t>(Data[Pos + 1]);
            if (!FollowedPointer) BytesConsumed = Pos - Offset + 2;
            FollowedPointer = true;
            Pos = BaseOffset + Pointer;
            continue;
        }

        ++Pos;
        if (Pos + Len > Data.size()) break;
        Labels.append(QString::fromUtf8(Data.constData() + Pos, Len));
        Pos += Len;
    }

    if (BytesConsumed == 0 && !FollowedPointer) BytesConsumed = Pos - Offset;

    return Labels.join(".");
}

QString ProtocolDissector::GetTcpFlagsString(uint8_t Flags) {
    QStringList FlagNames;
    if (Flags & 0x01) FlagNames.append("FIN");
    if (Flags & 0x02) FlagNames.append("SYN");
    if (Flags & 0x04) FlagNames.append("RST");
    if (Flags & 0x08) FlagNames.append("PSH");
    if (Flags & 0x10) FlagNames.append("ACK");
    if (Flags & 0x20) FlagNames.append("URG");
    if (Flags & 0x40) FlagNames.append("ECE");
    if (Flags & 0x80) FlagNames.append("CWR");
    return FlagNames.join(", ");
}

QString ProtocolDissector::GetIcmpTypeName(uint8_t Type) {
    switch (Type) {
    case 0: return "Echo Reply";
    case 3: return "Destination Unreachable";
    case 4: return "Source Quench";
    case 5: return "Redirect";
    case 8: return "Echo Request";
    case 9: return "Router Advertisement";
    case 10: return "Router Solicitation";
    case 11: return "Time Exceeded";
    case 12: return "Parameter Problem";
    case 13: return "Timestamp";
    case 14: return "Timestamp Reply";
    default: return QString("Type %1").arg(Type);
    }
}

QString ProtocolDissector::GetDnsTypeName(uint16_t Type) {
    switch (Type) {
    case 1: return "A (1)";
    case 2: return "NS (2)";
    case 5: return "CNAME (5)";
    case 6: return "SOA (6)";
    case 12: return "PTR (12)";
    case 15: return "MX (15)";
    case 16: return "TXT (16)";
    case 28: return "AAAA (28)";
    case 33: return "SRV (33)";
    case 41: return "OPT (41)";
    case 65: return "HTTPS (65)";
    case 255: return "ANY (255)";
    default: return QString("Type %1").arg(Type);
    }
}

bool ProtocolDissector::IsHttpData(const QByteArray& Data, int Offset) {
    if (Offset >= Data.size()) return false;

    QByteArray Chunk = Data.mid(Offset, 16);
    if (Chunk.startsWith("GET ") || Chunk.startsWith("POST ") ||
        Chunk.startsWith("PUT ") || Chunk.startsWith("DELETE ") ||
        Chunk.startsWith("HEAD ") || Chunk.startsWith("OPTIONS ") ||
        Chunk.startsWith("PATCH ") || Chunk.startsWith("CONNECT ") ||
        Chunk.startsWith("TRACE ") || Chunk.startsWith("HTTP/")) {
        return true;
    }
    return false;
}

}
