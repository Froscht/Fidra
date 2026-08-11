#include "DataProcessorEngine.h"
#include "../analysis/AnalysisDatabase.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QCryptographicHash>
#include <algorithm>
#include <cmath>
#include <cstring>

namespace Fidra {

DataProcessorEngine::DataProcessorEngine(QObject* Parent)
    : QObject(Parent)
    , NextNodeId(1)
{
}

ProcessorNode DataProcessorEngine::CreateNode(NodeType Type) const {
    ProcessorNode Node;
    Node.Id = 0;
    Node.Type = Type;
    Node.Label = NodeTypeName(Type);

    auto MakeInput = [](const QString& Name, int Index) -> NodePort {
        NodePort Port;
        Port.Name = Name;
        Port.IsInput = true;
        Port.PortIndex = Index;
        Port.HasData = false;
        return Port;
    };

    auto MakeOutput = [](const QString& Name, int Index) -> NodePort {
        NodePort Port;
        Port.Name = Name;
        Port.IsInput = false;
        Port.PortIndex = Index;
        Port.HasData = false;
        return Port;
    };

    switch (Type) {
    case NodeType::ReadBytes:
        Node.OutputPorts.append(MakeOutput("Data", 0));
        Node.Properties["Address"] = QVariant(static_cast<qulonglong>(0));
        Node.Properties["Size"] = QVariant(16);
        break;
    case NodeType::ReadU8:
        Node.OutputPorts.append(MakeOutput("Data", 0));
        Node.Properties["Address"] = QVariant(static_cast<qulonglong>(0));
        break;
    case NodeType::ReadU16:
        Node.OutputPorts.append(MakeOutput("Data", 0));
        Node.Properties["Address"] = QVariant(static_cast<qulonglong>(0));
        break;
    case NodeType::ReadU32:
        Node.OutputPorts.append(MakeOutput("Data", 0));
        Node.Properties["Address"] = QVariant(static_cast<qulonglong>(0));
        break;
    case NodeType::ReadU64:
        Node.OutputPorts.append(MakeOutput("Data", 0));
        Node.Properties["Address"] = QVariant(static_cast<qulonglong>(0));
        break;
    case NodeType::ReadString:
        Node.OutputPorts.append(MakeOutput("Data", 0));
        Node.Properties["Address"] = QVariant(static_cast<qulonglong>(0));
        Node.Properties["MaxLength"] = QVariant(256);
        break;
    case NodeType::Constant:
        Node.OutputPorts.append(MakeOutput("Data", 0));
        Node.Properties["Value"] = QVariant(QByteArray());
        break;
    case NodeType::HexInput:
        Node.OutputPorts.append(MakeOutput("Data", 0));
        Node.Properties["Value"] = QVariant(QString());
        break;

    case NodeType::XorKey:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        Node.Properties["Key"] = QVariant(0);
        break;
    case NodeType::XorRepeating:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        Node.Properties["Key"] = QVariant(QString());
        break;
    case NodeType::Add:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        Node.Properties["Value"] = QVariant(0);
        break;
    case NodeType::Sub:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        Node.Properties["Value"] = QVariant(0);
        break;
    case NodeType::And:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        Node.Properties["Value"] = QVariant(0xFF);
        break;
    case NodeType::Or:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        Node.Properties["Value"] = QVariant(0);
        break;
    case NodeType::Not:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;
    case NodeType::Shl:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        Node.Properties["Amount"] = QVariant(1);
        break;
    case NodeType::Shr:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        Node.Properties["Amount"] = QVariant(1);
        break;
    case NodeType::Rol:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        Node.Properties["Amount"] = QVariant(1);
        break;
    case NodeType::Ror:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        Node.Properties["Amount"] = QVariant(1);
        break;

    case NodeType::Base64Encode:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;
    case NodeType::Base64Decode:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;
    case NodeType::Rc4:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        Node.Properties["Key"] = QVariant(QString());
        break;

    case NodeType::ZlibDecompress:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;
    case NodeType::ZlibCompress:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;

    case NodeType::Md5:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Hash", 0));
        break;
    case NodeType::Sha1:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Hash", 0));
        break;
    case NodeType::Sha256:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Hash", 0));
        break;
    case NodeType::Crc32:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Hash", 0));
        break;

    case NodeType::ToHex:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;
    case NodeType::FromHex:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;
    case NodeType::ToAscii:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;
    case NodeType::ToUtf8:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;
    case NodeType::Reverse:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;
    case NodeType::Uppercase:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;
    case NodeType::Lowercase:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;

    case NodeType::Entropy:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;
    case NodeType::ByteCount:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;
    case NodeType::Length:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;

    case NodeType::OutputBytes:
        Node.InputPorts.append(MakeInput("Data", 0));
        break;
    case NodeType::OutputString:
        Node.InputPorts.append(MakeInput("Data", 0));
        break;
    case NodeType::OutputFile:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.Properties["Path"] = QVariant(QString());
        break;
    case NodeType::Visualize:
        Node.InputPorts.append(MakeInput("Data", 0));
        Node.OutputPorts.append(MakeOutput("Result", 0));
        break;
    }

    return Node;
}

int DataProcessorEngine::AddNode(NodeType Type, QPointF Position) {
    ProcessorNode Node = CreateNode(Type);
    Node.Id = NextNodeId++;
    Node.Position = Position;
    Nodes.append(Node);
    return Node.Id;
}

void DataProcessorEngine::RemoveNode(int NodeId) {
    Connections.erase(
        std::remove_if(Connections.begin(), Connections.end(),
            [NodeId](const NodeConnection& Conn) {
                return Conn.SourceNodeId == NodeId || Conn.DestNodeId == NodeId;
            }),
        Connections.end());

    Nodes.erase(
        std::remove_if(Nodes.begin(), Nodes.end(),
            [NodeId](const ProcessorNode& Node) {
                return Node.Id == NodeId;
            }),
        Nodes.end());
}

bool DataProcessorEngine::Connect(int SourceNode, int SourcePort, int DestNode, int DestPort) {
    ProcessorNode* Src = FindNode(SourceNode);
    ProcessorNode* Dst = FindNode(DestNode);
    if (!Src || !Dst) return false;
    if (SourcePort < 0 || SourcePort >= Src->OutputPorts.size()) return false;
    if (DestPort < 0 || DestPort >= Dst->InputPorts.size()) return false;

    for (const auto& Conn : Connections) {
        if (Conn.DestNodeId == DestNode && Conn.DestPortIndex == DestPort) {
            return false;
        }
    }

    if (SourceNode == DestNode) return false;

    NodeConnection Conn;
    Conn.SourceNodeId = SourceNode;
    Conn.SourcePortIndex = SourcePort;
    Conn.DestNodeId = DestNode;
    Conn.DestPortIndex = DestPort;
    Connections.append(Conn);
    return true;
}

void DataProcessorEngine::Disconnect(int SourceNode, int SourcePort, int DestNode, int DestPort) {
    Connections.erase(
        std::remove_if(Connections.begin(), Connections.end(),
            [=](const NodeConnection& Conn) {
                return Conn.SourceNodeId == SourceNode &&
                       Conn.SourcePortIndex == SourcePort &&
                       Conn.DestNodeId == DestNode &&
                       Conn.DestPortIndex == DestPort;
            }),
        Connections.end());
}

void DataProcessorEngine::SetNodeProperty(int NodeId, const QString& Key, const QVariant& Value) {
    ProcessorNode* Node = FindNode(NodeId);
    if (Node) {
        Node->Properties[Key] = Value;
    }
}

ProcessorNode* DataProcessorEngine::FindNode(int NodeId) {
    for (auto& Node : Nodes) {
        if (Node.Id == NodeId) return &Node;
    }
    return nullptr;
}

const ProcessorNode* DataProcessorEngine::FindNode(int NodeId) const {
    for (const auto& Node : Nodes) {
        if (Node.Id == NodeId) return &Node;
    }
    return nullptr;
}

QVector<ProcessorNode> DataProcessorEngine::GetNodes() const {
    return Nodes;
}

QVector<NodeConnection> DataProcessorEngine::GetConnections() const {
    return Connections;
}

QByteArray DataProcessorEngine::GetNodeOutput(int NodeId, int PortIndex) const {
    const ProcessorNode* Node = FindNode(NodeId);
    if (!Node) return {};
    for (const auto& Port : Node->OutputPorts) {
        if (Port.PortIndex == PortIndex && Port.HasData) {
            return Port.Data;
        }
    }
    if (Node->OutputPorts.isEmpty() && !Node->InputPorts.isEmpty()) {
        for (const auto& Port : Node->InputPorts) {
            if (Port.PortIndex == PortIndex && Port.HasData) {
                return Port.Data;
            }
        }
    }
    return {};
}

QVector<int> DataProcessorEngine::TopologicalSort() const {
    QMap<int, int> InDegree;
    QMap<int, QVector<int>> Adjacency;

    for (const auto& Node : Nodes) {
        InDegree[Node.Id] = 0;
        Adjacency[Node.Id] = {};
    }

    for (const auto& Conn : Connections) {
        Adjacency[Conn.SourceNodeId].append(Conn.DestNodeId);
        InDegree[Conn.DestNodeId]++;
    }

    QVector<int> Queue;
    for (auto It = InDegree.constBegin(); It != InDegree.constEnd(); ++It) {
        if (It.value() == 0) {
            Queue.append(It.key());
        }
    }

    QVector<int> Sorted;
    int Front = 0;

    while (Front < Queue.size()) {
        int Current = Queue[Front++];
        Sorted.append(Current);

        for (int Neighbor : Adjacency[Current]) {
            InDegree[Neighbor]--;
            if (InDegree[Neighbor] == 0) {
                Queue.append(Neighbor);
            }
        }
    }

    return Sorted;
}

bool DataProcessorEngine::Execute(AnalysisDatabase* Db) {
    for (auto& Node : Nodes) {
        for (auto& Port : Node.InputPorts) {
            Port.Data.clear();
            Port.HasData = false;
        }
        for (auto& Port : Node.OutputPorts) {
            Port.Data.clear();
            Port.HasData = false;
        }
    }

    QVector<int> Order = TopologicalSort();

    if (Order.size() != Nodes.size()) {
        emit ExecutionError("Pipeline", "Cycle detected in node graph");
        return false;
    }

    for (int NodeId : Order) {
        ProcessorNode* Node = FindNode(NodeId);
        if (!Node) continue;

        for (const auto& Conn : Connections) {
            if (Conn.DestNodeId == NodeId) {
                const ProcessorNode* SrcNode = FindNode(Conn.SourceNodeId);
                if (!SrcNode) continue;

                for (const auto& SrcPort : SrcNode->OutputPorts) {
                    if (SrcPort.PortIndex == Conn.SourcePortIndex && SrcPort.HasData) {
                        for (auto& DstPort : Node->InputPorts) {
                            if (DstPort.PortIndex == Conn.DestPortIndex) {
                                DstPort.Data = SrcPort.Data;
                                DstPort.HasData = true;
                                break;
                            }
                        }
                        break;
                    }
                }
            }
        }

        QByteArray Result = ExecuteNode(*Node, Db);

        if (!Node->OutputPorts.isEmpty()) {
            Node->OutputPorts[0].Data = Result;
            Node->OutputPorts[0].HasData = true;
            emit NodeOutputReady(Node->Id, 0, Result);
        }
    }

    emit ExecutionComplete();
    return true;
}

QByteArray DataProcessorEngine::ExecuteNode(ProcessorNode& Node, AnalysisDatabase* Db) {
    QByteArray InputData;
    if (!Node.InputPorts.isEmpty() && Node.InputPorts[0].HasData) {
        InputData = Node.InputPorts[0].Data;
    }

    switch (Node.Type) {
    case NodeType::ReadBytes: {
        if (!Db) return {};
        Address Addr = Node.Properties["Address"].toULongLong();
        int Size = Node.Properties["Size"].toInt();
        if (Size <= 0) Size = 16;
        return Db->ReadBytes(Addr, static_cast<size_t>(Size));
    }
    case NodeType::ReadU8: {
        if (!Db) return {};
        Address Addr = Node.Properties["Address"].toULongLong();
        return Db->ReadBytes(Addr, 1);
    }
    case NodeType::ReadU16: {
        if (!Db) return {};
        Address Addr = Node.Properties["Address"].toULongLong();
        return Db->ReadBytes(Addr, 2);
    }
    case NodeType::ReadU32: {
        if (!Db) return {};
        Address Addr = Node.Properties["Address"].toULongLong();
        return Db->ReadBytes(Addr, 4);
    }
    case NodeType::ReadU64: {
        if (!Db) return {};
        Address Addr = Node.Properties["Address"].toULongLong();
        return Db->ReadBytes(Addr, 8);
    }
    case NodeType::ReadString: {
        if (!Db) return {};
        Address Addr = Node.Properties["Address"].toULongLong();
        int MaxLen = Node.Properties["MaxLength"].toInt();
        if (MaxLen <= 0) MaxLen = 256;
        QByteArray Raw = Db->ReadBytes(Addr, static_cast<size_t>(MaxLen));
        int NullPos = Raw.indexOf('\0');
        if (NullPos >= 0) {
            Raw.truncate(NullPos);
        }
        return Raw;
    }
    case NodeType::Constant: {
        return Node.Properties["Value"].toByteArray();
    }
    case NodeType::HexInput: {
        QString HexStr = Node.Properties["Value"].toString();
        HexStr.remove(' ').remove('\n').remove('\r').remove('\t');
        return QByteArray::fromHex(HexStr.toLatin1());
    }

    case NodeType::XorKey: {
        uint8_t Key = static_cast<uint8_t>(Node.Properties["Key"].toInt() & 0xFF);
        QByteArray Result = InputData;
        for (int I = 0; I < Result.size(); ++I) {
            Result[I] = static_cast<char>(static_cast<uint8_t>(Result[I]) ^ Key);
        }
        return Result;
    }
    case NodeType::XorRepeating: {
        QString KeyHex = Node.Properties["Key"].toString();
        KeyHex.remove(' ');
        QByteArray Key = QByteArray::fromHex(KeyHex.toLatin1());
        if (Key.isEmpty()) return InputData;
        QByteArray Result = InputData;
        for (int I = 0; I < Result.size(); ++I) {
            Result[I] = static_cast<char>(
                static_cast<uint8_t>(Result[I]) ^
                static_cast<uint8_t>(Key[I % Key.size()]));
        }
        return Result;
    }
    case NodeType::Add: {
        uint8_t Val = static_cast<uint8_t>(Node.Properties["Value"].toInt() & 0xFF);
        QByteArray Result = InputData;
        for (int I = 0; I < Result.size(); ++I) {
            Result[I] = static_cast<char>(static_cast<uint8_t>(Result[I]) + Val);
        }
        return Result;
    }
    case NodeType::Sub: {
        uint8_t Val = static_cast<uint8_t>(Node.Properties["Value"].toInt() & 0xFF);
        QByteArray Result = InputData;
        for (int I = 0; I < Result.size(); ++I) {
            Result[I] = static_cast<char>(static_cast<uint8_t>(Result[I]) - Val);
        }
        return Result;
    }
    case NodeType::And: {
        uint8_t Val = static_cast<uint8_t>(Node.Properties["Value"].toInt() & 0xFF);
        QByteArray Result = InputData;
        for (int I = 0; I < Result.size(); ++I) {
            Result[I] = static_cast<char>(static_cast<uint8_t>(Result[I]) & Val);
        }
        return Result;
    }
    case NodeType::Or: {
        uint8_t Val = static_cast<uint8_t>(Node.Properties["Value"].toInt() & 0xFF);
        QByteArray Result = InputData;
        for (int I = 0; I < Result.size(); ++I) {
            Result[I] = static_cast<char>(static_cast<uint8_t>(Result[I]) | Val);
        }
        return Result;
    }
    case NodeType::Not: {
        QByteArray Result = InputData;
        for (int I = 0; I < Result.size(); ++I) {
            Result[I] = static_cast<char>(~static_cast<uint8_t>(Result[I]));
        }
        return Result;
    }
    case NodeType::Shl: {
        int Amount = Node.Properties["Amount"].toInt() & 7;
        QByteArray Result = InputData;
        for (int I = 0; I < Result.size(); ++I) {
            Result[I] = static_cast<char>(static_cast<uint8_t>(Result[I]) << Amount);
        }
        return Result;
    }
    case NodeType::Shr: {
        int Amount = Node.Properties["Amount"].toInt() & 7;
        QByteArray Result = InputData;
        for (int I = 0; I < Result.size(); ++I) {
            Result[I] = static_cast<char>(static_cast<uint8_t>(Result[I]) >> Amount);
        }
        return Result;
    }
    case NodeType::Rol: {
        int Amount = Node.Properties["Amount"].toInt() & 7;
        QByteArray Result = InputData;
        for (int I = 0; I < Result.size(); ++I) {
            uint8_t B = static_cast<uint8_t>(Result[I]);
            Result[I] = static_cast<char>((B << Amount) | (B >> (8 - Amount)));
        }
        return Result;
    }
    case NodeType::Ror: {
        int Amount = Node.Properties["Amount"].toInt() & 7;
        QByteArray Result = InputData;
        for (int I = 0; I < Result.size(); ++I) {
            uint8_t B = static_cast<uint8_t>(Result[I]);
            Result[I] = static_cast<char>((B >> Amount) | (B << (8 - Amount)));
        }
        return Result;
    }

    case NodeType::Base64Encode: {
        return InputData.toBase64();
    }
    case NodeType::Base64Decode: {
        return QByteArray::fromBase64(InputData);
    }
    case NodeType::Rc4: {
        QString KeyHex = Node.Properties["Key"].toString();
        KeyHex.remove(' ');
        QByteArray Key = QByteArray::fromHex(KeyHex.toLatin1());
        if (Key.isEmpty()) return InputData;

        uint8_t S[256];
        for (int I = 0; I < 256; ++I) S[I] = static_cast<uint8_t>(I);

        int J = 0;
        for (int I = 0; I < 256; ++I) {
            J = (J + S[I] + static_cast<uint8_t>(Key[I % Key.size()])) & 0xFF;
            std::swap(S[I], S[J]);
        }

        QByteArray Result = InputData;
        int I = 0;
        J = 0;
        for (int K = 0; K < Result.size(); ++K) {
            I = (I + 1) & 0xFF;
            J = (J + S[I]) & 0xFF;
            std::swap(S[I], S[J]);
            uint8_t KeyByte = S[(S[I] + S[J]) & 0xFF];
            Result[K] = static_cast<char>(static_cast<uint8_t>(Result[K]) ^ KeyByte);
        }
        return Result;
    }

    case NodeType::ZlibDecompress: {
        if (InputData.size() < 4) return {};
        return qUncompress(InputData);
    }
    case NodeType::ZlibCompress: {
        return qCompress(InputData);
    }

    case NodeType::Md5: {
        return QCryptographicHash::hash(InputData, QCryptographicHash::Md5).toHex();
    }
    case NodeType::Sha1: {
        return QCryptographicHash::hash(InputData, QCryptographicHash::Sha1).toHex();
    }
    case NodeType::Sha256: {
        return QCryptographicHash::hash(InputData, QCryptographicHash::Sha256).toHex();
    }
    case NodeType::Crc32: {
        uint32_t Crc = 0xFFFFFFFF;
        const uint8_t* Ptr = reinterpret_cast<const uint8_t*>(InputData.constData());
        for (int I = 0; I < InputData.size(); ++I) {
            Crc ^= Ptr[I];
            for (int J = 0; J < 8; ++J) {
                if (Crc & 1)
                    Crc = (Crc >> 1) ^ 0xEDB88320;
                else
                    Crc >>= 1;
            }
        }
        Crc ^= 0xFFFFFFFF;
        QByteArray Result;
        Result.append(QString("%1").arg(Crc, 8, 16, QChar('0')).toLatin1());
        return Result;
    }

    case NodeType::ToHex: {
        return InputData.toHex(' ');
    }
    case NodeType::FromHex: {
        return QByteArray::fromHex(InputData);
    }
    case NodeType::ToAscii: {
        QByteArray Result;
        Result.reserve(InputData.size());
        for (int I = 0; I < InputData.size(); ++I) {
            uint8_t B = static_cast<uint8_t>(InputData[I]);
            if (B >= 0x20 && B <= 0x7E)
                Result.append(static_cast<char>(B));
            else
                Result.append('.');
        }
        return Result;
    }
    case NodeType::ToUtf8: {
        return QString::fromUtf8(InputData).toUtf8();
    }
    case NodeType::Reverse: {
        QByteArray Result = InputData;
        std::reverse(Result.begin(), Result.end());
        return Result;
    }
    case NodeType::Uppercase: {
        return InputData.toUpper();
    }
    case NodeType::Lowercase: {
        return InputData.toLower();
    }

    case NodeType::Entropy: {
        if (InputData.isEmpty()) return QByteArray("0.000000");
        int Freq[256] = {};
        const uint8_t* Ptr = reinterpret_cast<const uint8_t*>(InputData.constData());
        for (int I = 0; I < InputData.size(); ++I) {
            Freq[Ptr[I]]++;
        }
        double Ent = 0.0;
        double Size = static_cast<double>(InputData.size());
        for (int I = 0; I < 256; ++I) {
            if (Freq[I] > 0) {
                double P = static_cast<double>(Freq[I]) / Size;
                Ent -= P * std::log2(P);
            }
        }
        return QString::number(Ent, 'f', 6).toLatin1();
    }
    case NodeType::ByteCount: {
        int Freq[256] = {};
        const uint8_t* Ptr = reinterpret_cast<const uint8_t*>(InputData.constData());
        for (int I = 0; I < InputData.size(); ++I) {
            Freq[Ptr[I]]++;
        }
        QString Result;
        for (int I = 0; I < 256; ++I) {
            if (Freq[I] > 0) {
                Result += QString("0x%1: %2\n")
                    .arg(I, 2, 16, QChar('0'))
                    .arg(Freq[I]);
            }
        }
        return Result.toLatin1();
    }
    case NodeType::Length: {
        return QString::number(InputData.size()).toLatin1();
    }

    case NodeType::OutputBytes: {
        emit NodeOutputReady(Node.Id, 0, InputData);
        return InputData;
    }
    case NodeType::OutputString: {
        emit NodeOutputReady(Node.Id, 0, InputData);
        return InputData;
    }
    case NodeType::OutputFile: {
        QString Path = Node.Properties["Path"].toString();
        if (!Path.isEmpty()) {
            QFile File(Path);
            if (File.open(QIODevice::WriteOnly)) {
                File.write(InputData);
                File.close();
            }
        }
        return InputData;
    }
    case NodeType::Visualize: {
        QString Dump;
        int TotalBytes = InputData.size();
        const uint8_t* Ptr = reinterpret_cast<const uint8_t*>(InputData.constData());

        for (int Offset = 0; Offset < TotalBytes; Offset += 16) {
            QString Line = QString("%1  ").arg(Offset, 8, 16, QChar('0'));

            int LineBytes = qMin(16, TotalBytes - Offset);

            for (int I = 0; I < 16; ++I) {
                if (I < LineBytes) {
                    Line += QString("%1 ").arg(Ptr[Offset + I], 2, 16, QChar('0'));
                } else {
                    Line += "   ";
                }
                if (I == 7) Line += " ";
            }

            Line += " |";
            for (int I = 0; I < LineBytes; ++I) {
                uint8_t B = Ptr[Offset + I];
                if (B >= 0x20 && B <= 0x7E)
                    Line += QChar(B);
                else
                    Line += '.';
            }
            Line += "|\n";

            Dump += Line;
        }

        return Dump.toLatin1();
    }
    }

    return {};
}

QString DataProcessorEngine::NodeTypeName(NodeType Type) {
    switch (Type) {
    case NodeType::ReadBytes: return "Read Bytes";
    case NodeType::ReadU8: return "Read U8";
    case NodeType::ReadU16: return "Read U16";
    case NodeType::ReadU32: return "Read U32";
    case NodeType::ReadU64: return "Read U64";
    case NodeType::ReadString: return "Read String";
    case NodeType::Constant: return "Constant";
    case NodeType::HexInput: return "Hex Input";
    case NodeType::XorKey: return "XOR Key";
    case NodeType::XorRepeating: return "XOR Repeating";
    case NodeType::Add: return "Add";
    case NodeType::Sub: return "Subtract";
    case NodeType::And: return "AND";
    case NodeType::Or: return "OR";
    case NodeType::Not: return "NOT";
    case NodeType::Shl: return "Shift Left";
    case NodeType::Shr: return "Shift Right";
    case NodeType::Rol: return "Rotate Left";
    case NodeType::Ror: return "Rotate Right";
    case NodeType::Base64Encode: return "Base64 Encode";
    case NodeType::Base64Decode: return "Base64 Decode";
    case NodeType::Rc4: return "RC4";
    case NodeType::ZlibDecompress: return "Zlib Decompress";
    case NodeType::ZlibCompress: return "Zlib Compress";
    case NodeType::Md5: return "MD5";
    case NodeType::Sha1: return "SHA-1";
    case NodeType::Sha256: return "SHA-256";
    case NodeType::Crc32: return "CRC32";
    case NodeType::ToHex: return "To Hex";
    case NodeType::FromHex: return "From Hex";
    case NodeType::ToAscii: return "To ASCII";
    case NodeType::ToUtf8: return "To UTF-8";
    case NodeType::Reverse: return "Reverse";
    case NodeType::Uppercase: return "Uppercase";
    case NodeType::Lowercase: return "Lowercase";
    case NodeType::Entropy: return "Entropy";
    case NodeType::ByteCount: return "Byte Count";
    case NodeType::Length: return "Length";
    case NodeType::OutputBytes: return "Output Bytes";
    case NodeType::OutputString: return "Output String";
    case NodeType::OutputFile: return "Output File";
    case NodeType::Visualize: return "Visualize";
    }
    return "Unknown";
}

QString DataProcessorEngine::NodeCategory(NodeType Type) {
    switch (Type) {
    case NodeType::ReadBytes:
    case NodeType::ReadU8:
    case NodeType::ReadU16:
    case NodeType::ReadU32:
    case NodeType::ReadU64:
    case NodeType::ReadString:
    case NodeType::Constant:
    case NodeType::HexInput:
        return "Input";

    case NodeType::XorKey:
    case NodeType::XorRepeating:
    case NodeType::Add:
    case NodeType::Sub:
    case NodeType::And:
    case NodeType::Or:
    case NodeType::Not:
    case NodeType::Shl:
    case NodeType::Shr:
    case NodeType::Rol:
    case NodeType::Ror:
        return "Transform";

    case NodeType::Base64Encode:
    case NodeType::Base64Decode:
    case NodeType::Rc4:
        return "Crypto";

    case NodeType::ZlibDecompress:
    case NodeType::ZlibCompress:
        return "Compress";

    case NodeType::Md5:
    case NodeType::Sha1:
    case NodeType::Sha256:
    case NodeType::Crc32:
        return "Hash";

    case NodeType::ToHex:
    case NodeType::FromHex:
    case NodeType::ToAscii:
    case NodeType::ToUtf8:
    case NodeType::Reverse:
    case NodeType::Uppercase:
    case NodeType::Lowercase:
        return "String";

    case NodeType::Entropy:
    case NodeType::ByteCount:
    case NodeType::Length:
        return "Math";

    case NodeType::OutputBytes:
    case NodeType::OutputString:
    case NodeType::OutputFile:
    case NodeType::Visualize:
        return "Output";
    }
    return "Unknown";
}

bool DataProcessorEngine::SavePipeline(const QString& Path) const {
    QJsonObject Root;

    QJsonArray NodesArray;
    for (const auto& Node : Nodes) {
        QJsonObject NodeObj;
        NodeObj["id"] = Node.Id;
        NodeObj["type"] = static_cast<int>(Node.Type);
        NodeObj["label"] = Node.Label;
        NodeObj["x"] = Node.Position.x();
        NodeObj["y"] = Node.Position.y();

        QJsonObject Props;
        for (auto It = Node.Properties.constBegin(); It != Node.Properties.constEnd(); ++It) {
            QVariant Val = It.value();
            if (Val.typeId() == QMetaType::QByteArray) {
                Props[It.key()] = QString::fromLatin1(Val.toByteArray().toHex());
            } else if (Val.typeId() == QMetaType::ULongLong || Val.typeId() == QMetaType::LongLong) {
                Props[It.key()] = QString::number(Val.toULongLong());
            } else {
                Props[It.key()] = QJsonValue::fromVariant(Val);
            }
        }
        NodeObj["properties"] = Props;

        NodesArray.append(NodeObj);
    }
    Root["nodes"] = NodesArray;

    QJsonArray ConnsArray;
    for (const auto& Conn : Connections) {
        QJsonObject ConnObj;
        ConnObj["sourceNode"] = Conn.SourceNodeId;
        ConnObj["sourcePort"] = Conn.SourcePortIndex;
        ConnObj["destNode"] = Conn.DestNodeId;
        ConnObj["destPort"] = Conn.DestPortIndex;
        ConnsArray.append(ConnObj);
    }
    Root["connections"] = ConnsArray;

    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly)) return false;
    File.write(QJsonDocument(Root).toJson());
    File.close();
    return true;
}

bool DataProcessorEngine::LoadPipeline(const QString& Path) {
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly)) return false;

    QJsonDocument Doc = QJsonDocument::fromJson(File.readAll());
    File.close();

    if (!Doc.isObject()) return false;
    QJsonObject Root = Doc.object();

    Nodes.clear();
    Connections.clear();
    NextNodeId = 1;

    QJsonArray NodesArray = Root["nodes"].toArray();
    for (const auto& NodeVal : NodesArray) {
        QJsonObject NodeObj = NodeVal.toObject();
        NodeType Type = static_cast<NodeType>(NodeObj["type"].toInt());
        ProcessorNode Node = CreateNode(Type);
        Node.Id = NodeObj["id"].toInt();
        Node.Label = NodeObj["label"].toString();
        Node.Position = QPointF(NodeObj["x"].toDouble(), NodeObj["y"].toDouble());

        if (Node.Id >= NextNodeId) NextNodeId = Node.Id + 1;

        QJsonObject Props = NodeObj["properties"].toObject();
        for (auto It = Props.constBegin(); It != Props.constEnd(); ++It) {
            if (Node.Properties.contains(It.key())) {
                QVariant Existing = Node.Properties[It.key()];
                if (Existing.typeId() == QMetaType::QByteArray) {
                    Node.Properties[It.key()] = QByteArray::fromHex(It.value().toString().toLatin1());
                } else if (Existing.typeId() == QMetaType::ULongLong) {
                    Node.Properties[It.key()] = QVariant(It.value().toString().toULongLong());
                } else if (Existing.typeId() == QMetaType::Int) {
                    Node.Properties[It.key()] = QVariant(It.value().toInt());
                } else {
                    Node.Properties[It.key()] = It.value().toVariant();
                }
            } else {
                Node.Properties[It.key()] = It.value().toVariant();
            }
        }

        Nodes.append(Node);
    }

    QJsonArray ConnsArray = Root["connections"].toArray();
    for (const auto& ConnVal : ConnsArray) {
        QJsonObject ConnObj = ConnVal.toObject();
        NodeConnection Conn;
        Conn.SourceNodeId = ConnObj["sourceNode"].toInt();
        Conn.SourcePortIndex = ConnObj["sourcePort"].toInt();
        Conn.DestNodeId = ConnObj["destNode"].toInt();
        Conn.DestPortIndex = ConnObj["destPort"].toInt();
        Connections.append(Conn);
    }

    return true;
}

}
