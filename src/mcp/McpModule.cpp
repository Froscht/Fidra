#include "McpModule.h"
#include "McpServer.h"
#include "McpToolRegistry.h"
#include "McpWidget.h"

namespace Fidra {

McpModule::McpModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , Server(nullptr)
    , ToolRegistry(nullptr)
    , Widget(nullptr) {
}

McpModule::~McpModule() {
}

QString McpModule::Name() const {
    return QStringLiteral("MCP");
}

QString McpModule::Description() const {
    return QStringLiteral("Model Context Protocol server for AI agent integration");
}

QIcon McpModule::Icon() const {
    return QIcon::fromTheme(QStringLiteral("network-server"));
}

int McpModule::Priority() const {
    return 900;
}

QWidget* McpModule::CreateMainWidget(QWidget* Parent) {
    Widget = new McpWidget(Parent);
    return Widget;
}

void McpModule::Initialize(ICore* Core) {
    CoreRef = Core;

    ToolRegistry = new McpToolRegistry(this);
    ToolRegistry->Initialize(Core);

    Server = new McpServer(this);
    Server->SetToolRegistry(ToolRegistry);

    if (Widget) {
        Widget->SetServer(Server);
        Widget->SetToolRegistry(ToolRegistry);
    }

    connect(Server, &McpServer::LogMessage, this, [Core](const QString& Message) {
        Core->Log(Message, LogLevel::Info);
    });
}

void McpModule::Shutdown() {
    if (Server) {
        Server->StopTcp();
        Server->StopStdio();
    }
    CoreRef = nullptr;
}

void McpModule::OnProcessAttached(const ProcessInfo& Info) {
    Q_UNUSED(Info);
}

void McpModule::OnProcessDetached() {
}

McpServer* McpModule::GetServer() const {
    return Server;
}

McpToolRegistry* McpModule::GetToolRegistry() const {
    return ToolRegistry;
}

}
