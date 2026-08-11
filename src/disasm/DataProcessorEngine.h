#pragma once

#include <fidra/Types.h>
#include <QObject>
#include <QByteArray>
#include <QVector>
#include <QMap>
#include <QPointF>
#include <QString>
#include <QVariant>

namespace Fidra {

class AnalysisDatabase;

enum class NodeType {
    ReadBytes, ReadU8, ReadU16, ReadU32, ReadU64, ReadString, Constant, HexInput,
    XorKey, XorRepeating, Add, Sub, And, Or, Not, Shl, Shr, Rol, Ror,
    Base64Encode, Base64Decode, Rc4,
    ZlibDecompress, ZlibCompress,
    Md5, Sha1, Sha256, Crc32,
    ToHex, FromHex, ToAscii, ToUtf8, Reverse, Uppercase, Lowercase,
    Entropy, ByteCount, Length,
    OutputBytes, OutputString, OutputFile, Visualize
};

struct NodePort {
    QString Name;
    bool IsInput;
    int PortIndex;
    QByteArray Data;
    bool HasData = false;
};

struct ProcessorNode {
    int Id;
    NodeType Type;
    QString Label;
    QPointF Position;
    QVector<NodePort> InputPorts;
    QVector<NodePort> OutputPorts;
    QMap<QString, QVariant> Properties;
};

struct NodeConnection {
    int SourceNodeId;
    int SourcePortIndex;
    int DestNodeId;
    int DestPortIndex;
};

class DataProcessorEngine : public QObject {
    Q_OBJECT

public:
    explicit DataProcessorEngine(QObject* Parent = nullptr);

    int AddNode(NodeType Type, QPointF Position = {});
    void RemoveNode(int NodeId);
    bool Connect(int SourceNode, int SourcePort, int DestNode, int DestPort);
    void Disconnect(int SourceNode, int SourcePort, int DestNode, int DestPort);

    void SetNodeProperty(int NodeId, const QString& Key, const QVariant& Value);

    bool Execute(AnalysisDatabase* Db);

    QVector<ProcessorNode> GetNodes() const;
    QVector<NodeConnection> GetConnections() const;

    ProcessorNode* FindNode(int NodeId);
    const ProcessorNode* FindNode(int NodeId) const;

    QByteArray GetNodeOutput(int NodeId, int PortIndex) const;

    bool SavePipeline(const QString& Path) const;
    bool LoadPipeline(const QString& Path);

    static QString NodeTypeName(NodeType Type);
    static QString NodeCategory(NodeType Type);

signals:
    void ExecutionComplete();
    void ExecutionError(const QString& NodeLabel, const QString& Error);
    void NodeOutputReady(int NodeId, int PortIndex, const QByteArray& Data);

private:
    QVector<int> TopologicalSort() const;
    QByteArray ExecuteNode(ProcessorNode& Node, AnalysisDatabase* Db);
    ProcessorNode CreateNode(NodeType Type) const;

    QVector<ProcessorNode> Nodes;
    QVector<NodeConnection> Connections;
    int NextNodeId;
};

}
