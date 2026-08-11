#include "PacketModel.h"
#include <algorithm>
#include <QFont>

namespace Fidra {

PacketModel::PacketModel(QObject* Parent)
    : QAbstractTableModel(Parent) {
    Timer.start();
    AllPackets.reserve(100000);
    DisplayIndex.reserve(100000);
    InitProtocolColors();
}

PacketModel::~PacketModel() {
}

void PacketModel::InitProtocolColors() {
    ProtocolColors["TCP"] = QColor(228, 228, 255);
    ProtocolColors["UDP"] = QColor(218, 238, 255);
    ProtocolColors["DNS"] = QColor(218, 238, 218);
    ProtocolColors["HTTP"] = QColor(228, 255, 199);
    ProtocolColors["ICMP"] = QColor(252, 224, 255);
    ProtocolColors["ICMPv6"] = QColor(252, 224, 255);
    ProtocolColors["ARP"] = QColor(250, 240, 215);
    ProtocolColors["IPv6"] = QColor(218, 238, 255);
    ProtocolColors["TLS"] = QColor(218, 236, 218);
    ProtocolColors["SSH"] = QColor(218, 236, 218);
}

int PacketModel::rowCount(const QModelIndex& Parent) const {
    if (Parent.isValid()) return 0;
    QMutexLocker Lock(&DataMutex);
    return DisplayIndex.size();
}

int PacketModel::columnCount(const QModelIndex& Parent) const {
    if (Parent.isValid()) return 0;
    return ColCount;
}

QVariant PacketModel::data(const QModelIndex& Index, int Role) const {
    if (!Index.isValid()) return {};

    QMutexLocker Lock(&DataMutex);

    if (Index.row() < 0 || Index.row() >= DisplayIndex.size()) return {};
    int RealIndex = DisplayIndex[Index.row()];
    if (RealIndex < 0 || RealIndex >= AllPackets.size()) return {};

    const StoredPacket& Stored = AllPackets[RealIndex];

    if (Role == Qt::DisplayRole) {
        switch (Index.column()) {
        case ColNumber:
            return Stored.OriginalIndex + 1;
        case ColTime:
            return QString::number(Stored.RelativeTime, 'f', 6);
        case ColSource: {
            QString Src = Stored.Dissection.SourceAddress;
            if (Stored.Dissection.SourcePort > 0)
                Src += ":" + QString::number(Stored.Dissection.SourcePort);
            return Src;
        }
        case ColDestination: {
            QString Dst = Stored.Dissection.DestAddress;
            if (Stored.Dissection.DestPort > 0)
                Dst += ":" + QString::number(Stored.Dissection.DestPort);
            return Dst;
        }
        case ColProtocol:
            return Stored.Dissection.TopProtocol;
        case ColLength:
            return Stored.Pkt.Data.size();
        case ColInfo:
            return Stored.Dissection.Summary;
        }
    } else if (Role == Qt::BackgroundRole) {
        QString Protocol = Stored.Dissection.TopProtocol;
        if (ProtocolColors.contains(Protocol)) {
            QColor Color = ProtocolColors[Protocol];
            Color.setAlpha(40);
            return Color;
        }
    } else if (Role == Qt::ForegroundRole) {
        QString Protocol = Stored.Dissection.TopProtocol;
        if (Protocol == "TCP") return QColor(180, 180, 255);
        if (Protocol == "UDP") return QColor(150, 200, 255);
        if (Protocol == "DNS") return QColor(150, 220, 150);
        if (Protocol == "HTTP") return QColor(180, 255, 140);
        if (Protocol == "ICMP" || Protocol == "ICMPv6") return QColor(230, 180, 255);
        if (Protocol == "ARP") return QColor(240, 220, 160);
        return QColor(212, 212, 212);
    } else if (Role == Qt::FontRole) {
        QFont MonoFont("Consolas", 9);
        MonoFont.setStyleHint(QFont::Monospace);
        return MonoFont;
    } else if (Role == Qt::TextAlignmentRole) {
        if (Index.column() == ColNumber || Index.column() == ColLength)
            return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
        return static_cast<int>(Qt::AlignLeft | Qt::AlignVCenter);
    }

    return {};
}

QVariant PacketModel::headerData(int Section, Qt::Orientation Orientation, int Role) const {
    if (Orientation != Qt::Horizontal || Role != Qt::DisplayRole) return {};

    switch (Section) {
    case ColNumber: return "No.";
    case ColTime: return "Time";
    case ColSource: return "Source";
    case ColDestination: return "Destination";
    case ColProtocol: return "Protocol";
    case ColLength: return "Length";
    case ColInfo: return "Info";
    }
    return {};
}

void PacketModel::sort(int Column, Qt::SortOrder Order) {
    QMutexLocker Lock(&DataMutex);

    emit layoutAboutToBeChanged();

    std::sort(DisplayIndex.begin(), DisplayIndex.end(), [this, Column, Order](int A, int B) {
        const StoredPacket& Pa = AllPackets[A];
        const StoredPacket& Pb = AllPackets[B];

        int Result = 0;
        switch (Column) {
        case ColNumber:
            Result = Pa.OriginalIndex - Pb.OriginalIndex;
            break;
        case ColTime:
            Result = (Pa.RelativeTime < Pb.RelativeTime) ? -1 : (Pa.RelativeTime > Pb.RelativeTime) ? 1 : 0;
            break;
        case ColSource:
            Result = Pa.Dissection.SourceAddress.compare(Pb.Dissection.SourceAddress);
            break;
        case ColDestination:
            Result = Pa.Dissection.DestAddress.compare(Pb.Dissection.DestAddress);
            break;
        case ColProtocol:
            Result = Pa.Dissection.TopProtocol.compare(Pb.Dissection.TopProtocol);
            break;
        case ColLength:
            Result = Pa.Pkt.Data.size() - Pb.Pkt.Data.size();
            break;
        case ColInfo:
            Result = Pa.Dissection.Summary.compare(Pb.Dissection.Summary);
            break;
        }

        return (Order == Qt::AscendingOrder) ? Result < 0 : Result > 0;
    });

    emit layoutChanged();
}

void PacketModel::AddPacket(const NetworkPacket& Packet) {
    QMutexLocker Lock(&DataMutex);

    StoredPacket Stored;
    Stored.Pkt = Packet;
    Stored.RelativeTime = Timer.elapsed() / 1000.0;
    Stored.OriginalIndex = AllPackets.size();

    if (Packet.Data.size() >= 14) {
        Stored.Dissection = Dissector.Dissect(Packet.Data);
    } else {
        Stored.Dissection = Dissector.DissectFromIp(Packet.Data);
    }

    if (Stored.Dissection.SourceAddress.isEmpty()) {
        Stored.Dissection.SourceAddress = Packet.SourceAddress;
    }
    if (Stored.Dissection.DestAddress.isEmpty()) {
        Stored.Dissection.DestAddress = Packet.DestAddress;
    }
    if (Stored.Dissection.SourcePort == 0) {
        Stored.Dissection.SourcePort = Packet.SourcePort;
    }
    if (Stored.Dissection.DestPort == 0) {
        Stored.Dissection.DestPort = Packet.DestPort;
    }
    if (Stored.Dissection.TopProtocol.isEmpty()) {
        Stored.Dissection.TopProtocol = Packet.Protocol;
    }

    int NewIndex = AllPackets.size();
    AllPackets.append(Stored);

    if (CurrentFilter.isEmpty() || MatchesFilter(Stored)) {
        int NewRow = DisplayIndex.size();
        beginInsertRows(QModelIndex(), NewRow, NewRow);
        DisplayIndex.append(NewIndex);
        endInsertRows();
    }
}

void PacketModel::AddPackets(const QList<NetworkPacket>& Packets) {
    if (Packets.isEmpty()) return;

    QMutexLocker Lock(&DataMutex);

    QVector<int> NewDisplayIndices;

    for (const auto& Packet : Packets) {
        StoredPacket Stored;
        Stored.Pkt = Packet;
        Stored.RelativeTime = Timer.elapsed() / 1000.0;
        Stored.OriginalIndex = AllPackets.size();

        if (Packet.Data.size() >= 14) {
            Stored.Dissection = Dissector.Dissect(Packet.Data);
        } else {
            Stored.Dissection = Dissector.DissectFromIp(Packet.Data);
        }

        if (Stored.Dissection.SourceAddress.isEmpty())
            Stored.Dissection.SourceAddress = Packet.SourceAddress;
        if (Stored.Dissection.DestAddress.isEmpty())
            Stored.Dissection.DestAddress = Packet.DestAddress;
        if (Stored.Dissection.SourcePort == 0)
            Stored.Dissection.SourcePort = Packet.SourcePort;
        if (Stored.Dissection.DestPort == 0)
            Stored.Dissection.DestPort = Packet.DestPort;
        if (Stored.Dissection.TopProtocol.isEmpty())
            Stored.Dissection.TopProtocol = Packet.Protocol;

        int NewIndex = AllPackets.size();
        AllPackets.append(Stored);

        if (CurrentFilter.isEmpty() || MatchesFilter(Stored)) {
            NewDisplayIndices.append(NewIndex);
        }
    }

    if (!NewDisplayIndices.isEmpty()) {
        int FirstRow = DisplayIndex.size();
        int LastRow = FirstRow + NewDisplayIndices.size() - 1;
        beginInsertRows(QModelIndex(), FirstRow, LastRow);
        DisplayIndex.append(NewDisplayIndices);
        endInsertRows();
    }
}

void PacketModel::Clear() {
    QMutexLocker Lock(&DataMutex);
    beginResetModel();
    AllPackets.clear();
    AllPackets.reserve(100000);
    DisplayIndex.clear();
    DisplayIndex.reserve(100000);
    Timer.restart();
    endResetModel();
}

int PacketModel::TotalPacketCount() const {
    QMutexLocker Lock(&DataMutex);
    return AllPackets.size();
}

int PacketModel::DisplayedPacketCount() const {
    QMutexLocker Lock(&DataMutex);
    return DisplayIndex.size();
}

NetworkPacket PacketModel::GetPacket(int DisplayRow) const {
    QMutexLocker Lock(&DataMutex);
    if (DisplayRow < 0 || DisplayRow >= DisplayIndex.size()) return {};
    int RealIndex = DisplayIndex[DisplayRow];
    if (RealIndex < 0 || RealIndex >= AllPackets.size()) return {};
    return AllPackets[RealIndex].Pkt;
}

DissectedPacket PacketModel::GetDissection(int DisplayRow) const {
    QMutexLocker Lock(&DataMutex);
    if (DisplayRow < 0 || DisplayRow >= DisplayIndex.size()) return {};
    int RealIndex = DisplayIndex[DisplayRow];
    if (RealIndex < 0 || RealIndex >= AllPackets.size()) return {};
    return AllPackets[RealIndex].Dissection;
}

QByteArray PacketModel::GetPacketData(int DisplayRow) const {
    QMutexLocker Lock(&DataMutex);
    if (DisplayRow < 0 || DisplayRow >= DisplayIndex.size()) return {};
    int RealIndex = DisplayIndex[DisplayRow];
    if (RealIndex < 0 || RealIndex >= AllPackets.size()) return {};
    return AllPackets[RealIndex].Pkt.Data;
}

void PacketModel::SetDisplayFilter(const QString& Filter) {
    QMutexLocker Lock(&DataMutex);
    CurrentFilter = Filter.trimmed().toLower();
    RebuildDisplayIndex();
}

QString PacketModel::GetDisplayFilter() const {
    QMutexLocker Lock(&DataMutex);
    return CurrentFilter;
}

void PacketModel::RebuildDisplayIndex() {
    beginResetModel();
    DisplayIndex.clear();
    DisplayIndex.reserve(AllPackets.size());

    for (int I = 0; I < AllPackets.size(); ++I) {
        if (CurrentFilter.isEmpty() || MatchesFilter(AllPackets[I])) {
            DisplayIndex.append(I);
        }
    }
    endResetModel();
}

bool PacketModel::MatchesFilter(const StoredPacket& Stored) const {
    if (CurrentFilter.isEmpty()) return true;

    QStringList Tokens = CurrentFilter.split("&&", Qt::SkipEmptyParts);
    for (const QString& Token : Tokens) {
        QString Trimmed = Token.trimmed();
        if (!Trimmed.isEmpty() && !EvaluateFilterExpression(Stored, Trimmed)) {
            return false;
        }
    }
    return true;
}

bool PacketModel::EvaluateFilterExpression(const StoredPacket& Stored, const QString& Expr) const {
    QString E = Expr.trimmed();

    if (E.startsWith("!") || E.startsWith("not ")) {
        QString Inner = E.startsWith("!") ? E.mid(1).trimmed() : E.mid(4).trimmed();
        return !EvaluateFilterExpression(Stored, Inner);
    }

    if (E.contains("||")) {
        QStringList OrParts = E.split("||", Qt::SkipEmptyParts);
        for (const QString& Part : OrParts) {
            if (EvaluateFilterExpression(Stored, Part.trimmed())) return true;
        }
        return false;
    }

    if (E.contains("==")) {
        QStringList Parts = E.split("==", Qt::SkipEmptyParts);
        if (Parts.size() == 2) {
            QString Field = Parts[0].trimmed();
            QString Value = Parts[1].trimmed();

            if (Field == "ip.src") {
                return Stored.Dissection.SourceAddress.toLower() == Value;
            } else if (Field == "ip.dst") {
                return Stored.Dissection.DestAddress.toLower() == Value;
            } else if (Field == "ip.addr") {
                return Stored.Dissection.SourceAddress.toLower() == Value ||
                       Stored.Dissection.DestAddress.toLower() == Value;
            } else if (Field == "tcp.port") {
                uint16_t Port = Value.toUShort();
                return (Stored.Dissection.TopProtocol == "TCP" || Stored.Dissection.TopProtocol == "HTTP") &&
                       (Stored.Dissection.SourcePort == Port || Stored.Dissection.DestPort == Port);
            } else if (Field == "udp.port") {
                uint16_t Port = Value.toUShort();
                return (Stored.Dissection.TopProtocol == "UDP" || Stored.Dissection.TopProtocol == "DNS") &&
                       (Stored.Dissection.SourcePort == Port || Stored.Dissection.DestPort == Port);
            } else if (Field == "tcp.srcport") {
                uint16_t Port = Value.toUShort();
                return (Stored.Dissection.TopProtocol == "TCP" || Stored.Dissection.TopProtocol == "HTTP") &&
                       Stored.Dissection.SourcePort == Port;
            } else if (Field == "tcp.dstport") {
                uint16_t Port = Value.toUShort();
                return (Stored.Dissection.TopProtocol == "TCP" || Stored.Dissection.TopProtocol == "HTTP") &&
                       Stored.Dissection.DestPort == Port;
            } else if (Field == "udp.srcport") {
                uint16_t Port = Value.toUShort();
                return (Stored.Dissection.TopProtocol == "UDP" || Stored.Dissection.TopProtocol == "DNS") &&
                       Stored.Dissection.SourcePort == Port;
            } else if (Field == "udp.dstport") {
                uint16_t Port = Value.toUShort();
                return (Stored.Dissection.TopProtocol == "UDP" || Stored.Dissection.TopProtocol == "DNS") &&
                       Stored.Dissection.DestPort == Port;
            } else if (Field == "frame.len") {
                int Len = Value.toInt();
                return Stored.Pkt.Data.size() == Len;
            }
        }
    }

    if (E.contains("!=")) {
        QStringList Parts = E.split("!=", Qt::SkipEmptyParts);
        if (Parts.size() == 2) {
            QString EqExpr = Parts[0].trimmed() + "==" + Parts[1].trimmed();
            return !EvaluateFilterExpression(Stored, EqExpr);
        }
    }

    if (E.contains(">") && !E.contains(">=") && !E.contains("!=")) {
        QStringList Parts = E.split(">", Qt::SkipEmptyParts);
        if (Parts.size() == 2) {
            QString Field = Parts[0].trimmed();
            int Value = Parts[1].trimmed().toInt();
            if (Field == "frame.len") return Stored.Pkt.Data.size() > Value;
        }
    }

    if (E.contains("<") && !E.contains("<=")) {
        QStringList Parts = E.split("<", Qt::SkipEmptyParts);
        if (Parts.size() == 2) {
            QString Field = Parts[0].trimmed();
            int Value = Parts[1].trimmed().toInt();
            if (Field == "frame.len") return Stored.Pkt.Data.size() < Value;
        }
    }

    if (E == "tcp") {
        return Stored.Dissection.TopProtocol == "TCP" || Stored.Dissection.TopProtocol == "HTTP";
    } else if (E == "udp") {
        return Stored.Dissection.TopProtocol == "UDP" || Stored.Dissection.TopProtocol == "DNS";
    } else if (E == "icmp") {
        return Stored.Dissection.TopProtocol == "ICMP";
    } else if (E == "icmpv6") {
        return Stored.Dissection.TopProtocol == "ICMPv6";
    } else if (E == "dns") {
        return Stored.Dissection.TopProtocol == "DNS";
    } else if (E == "http") {
        return Stored.Dissection.TopProtocol == "HTTP";
    } else if (E == "arp") {
        return Stored.Dissection.TopProtocol == "ARP";
    } else if (E == "ip") {
        return !Stored.Dissection.SourceAddress.isEmpty();
    } else if (E == "ipv6") {
        return Stored.Dissection.SourceAddress.contains(":");
    }

    QString LowerProto = Stored.Dissection.TopProtocol.toLower();
    QString LowerSrc = Stored.Dissection.SourceAddress.toLower();
    QString LowerDst = Stored.Dissection.DestAddress.toLower();
    QString LowerSummary = Stored.Dissection.Summary.toLower();

    return LowerProto.contains(E) || LowerSrc.contains(E) ||
           LowerDst.contains(E) || LowerSummary.contains(E);
}

QColor PacketModel::GetProtocolColor(const QString& Protocol) const {
    return ProtocolColors.value(Protocol, QColor(212, 212, 212));
}

}
