#pragma once

#include <fidra/ICore.h>
#include <QObject>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <QString>
#include <QMap>
#include <functional>

namespace Fidra {

struct McpToolDefinition {
    QString Name;
    QString Description;
    QJsonObject InputSchema;
    bool Enabled;
    std::function<QJsonValue(const QJsonObject&)> Handler;
};

class McpToolRegistry : public QObject {
    Q_OBJECT

public:
    explicit McpToolRegistry(QObject* Parent = nullptr);
    ~McpToolRegistry() override;

    void Initialize(ICore* Core);

    void RegisterTool(const QString& Name, const QString& Description,
                      const QJsonObject& InputSchema,
                      std::function<QJsonValue(const QJsonObject&)> Handler);

    void UnregisterTool(const QString& Name);

    bool HasTool(const QString& Name) const;
    void SetToolEnabled(const QString& Name, bool Enabled);
    bool IsToolEnabled(const QString& Name) const;

    QJsonArray GetToolList() const;
    QJsonValue CallTool(const QString& Name, const QJsonObject& Arguments);

    QList<McpToolDefinition> GetAllTools() const;

    ICore* GetCore() const { return CoreRef; }

signals:
    void ToolRegistered(const QString& Name);
    void ToolUnregistered(const QString& Name);
    void ToolCalled(const QString& Name, const QJsonObject& Args, const QJsonValue& Result);
    void ToolEnabledChanged(const QString& Name, bool Enabled);

private:
    void RegisterBuiltinTools();

    void RegisterCoreTools();
    void RegisterAnalysisTools();
    void RegisterMemoryTools();
    void RegisterNetworkTools();
    void RegisterCodegenTools();
    void RegisterScriptingTools();
    void RegisterAiTools();
    void RegisterFileTools();
    void RegisterEncodingTools();
    void RegisterDebuggerTools();
    void RegisterUtilityTools();

    QJsonValue HandleReadMemory(const QJsonObject& Args);
    QJsonValue HandleWriteMemory(const QJsonObject& Args);
    QJsonValue HandleGetMemoryRegions(const QJsonObject& Args);
    QJsonValue HandleGetProcessList(const QJsonObject& Args);
    QJsonValue HandleAttachProcess(const QJsonObject& Args);
    QJsonValue HandleDetachProcess(const QJsonObject& Args);
    QJsonValue HandleDisassemble(const QJsonObject& Args);
    QJsonValue HandleScanValue(const QJsonObject& Args);
    QJsonValue HandleGetModules(const QJsonObject& Args);
    QJsonValue HandleGetRegisters(const QJsonObject& Args);
    QJsonValue HandleSetBreakpoint(const QJsonObject& Args);
    QJsonValue HandleRemoveBreakpoint(const QJsonObject& Args);
    QJsonValue HandlePatternScan(const QJsonObject& Args);
    QJsonValue HandleReadString(const QJsonObject& Args);
    QJsonValue HandleGetImports(const QJsonObject& Args);
    QJsonValue HandleGetExports(const QJsonObject& Args);
    QJsonValue HandleEvaluateExpression(const QJsonObject& Args);

    QMap<QString, McpToolDefinition> Tools;
    ICore* CoreRef;

    QMap<QString, QByteArray> MemorySnapshots;
    QMap<QString, QPair<Address, QByteArray>> PatchBackups;
    QMap<Address, QByteArray> FrozenValues;
    QMap<QString, QJsonArray> Bookmarks;
    QMap<QString, QJsonArray> Labels;
    QMap<QString, QJsonArray> Macros;
};

}
