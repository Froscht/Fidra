#pragma once

#include <fidra/IModule.h>

namespace Fidra {

class McpServer;
class McpToolRegistry;
class McpWidget;

class McpModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit McpModule(QObject* Parent = nullptr);
    ~McpModule() override;

    QString Name() const override;
    QString Description() const override;
    QIcon Icon() const override;
    int Priority() const override;

    QWidget* CreateMainWidget(QWidget* Parent) override;

    void Initialize(ICore* Core) override;
    void Shutdown() override;

    void OnProcessAttached(const ProcessInfo& Info) override;
    void OnProcessDetached() override;

    McpServer* GetServer() const;
    McpToolRegistry* GetToolRegistry() const;

private:
    ICore* CoreRef;
    McpServer* Server;
    McpToolRegistry* ToolRegistry;
    McpWidget* Widget;
};

}
