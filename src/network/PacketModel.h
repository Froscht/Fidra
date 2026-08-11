#pragma once

#include <fidra/Types.h>
#include "ProtocolDissector.h"
#include <QAbstractTableModel>
#include <QColor>
#include <QElapsedTimer>
#include <QVector>
#include <QMutex>
#include <QRegularExpression>

namespace Fidra {

class PacketModel : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        ColNumber = 0,
        ColTime,
        ColSource,
        ColDestination,
        ColProtocol,
        ColLength,
        ColInfo,
        ColCount
    };

    explicit PacketModel(QObject* Parent = nullptr);
    ~PacketModel() override;

    int rowCount(const QModelIndex& Parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& Parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& Index, int Role = Qt::DisplayRole) const override;
    QVariant headerData(int Section, Qt::Orientation Orientation, int Role = Qt::DisplayRole) const override;
    void sort(int Column, Qt::SortOrder Order = Qt::AscendingOrder) override;

    void AddPacket(const NetworkPacket& Packet);
    void AddPackets(const QList<NetworkPacket>& Packets);
    void Clear();
    int TotalPacketCount() const;
    int DisplayedPacketCount() const;

    NetworkPacket GetPacket(int DisplayRow) const;
    DissectedPacket GetDissection(int DisplayRow) const;
    QByteArray GetPacketData(int DisplayRow) const;

    void SetDisplayFilter(const QString& Filter);
    QString GetDisplayFilter() const;

    QColor GetProtocolColor(const QString& Protocol) const;

private:
    struct StoredPacket {
        NetworkPacket Pkt;
        DissectedPacket Dissection;
        double RelativeTime;
        int OriginalIndex;
    };

    void RebuildDisplayIndex();
    bool MatchesFilter(const StoredPacket& Stored) const;
    bool EvaluateFilterExpression(const StoredPacket& Stored, const QString& Expr) const;

    QVector<StoredPacket> AllPackets;
    QVector<int> DisplayIndex;
    QString CurrentFilter;
    QElapsedTimer Timer;
    ProtocolDissector Dissector;
    mutable QRecursiveMutex DataMutex;

    QMap<QString, QColor> ProtocolColors;
    void InitProtocolColors();
};

}
