#pragma once

#include <fidra/IModule.h>
#include <fidra/ICore.h>
#include <QObject>
#include <QLibrary>
#include <QString>
#include <QStringList>
#include <QList>
#include <QVector>

namespace Fidra {

struct PluginInfo {
    QString Name;
    QString Path;
    QString FilePath;
    QString Version;
    QString Author;
    QString Description;
    bool Loaded;
};

class PluginManager : public QObject {
    Q_OBJECT

public:
    explicit PluginManager(ICore* Core, QObject* Parent = nullptr);
    ~PluginManager() override;

    QVector<PluginInfo> GetPlugins() const;
    bool LoadPlugin(const QString& Path);
    void UnloadPlugin(const QString& Name);
    void UnloadAll();
    void ScanDirectory(const QString& Dir);
    void ScanDefaultDirectories();
    void ExecutePlugin(const QString& Name);
    QList<IModule*> GetLoadedModules() const;

signals:
    void PluginLoaded(const QString& Name);
    void PluginUnloaded(const QString& Name);
    void LogMessage(const QString& Message);

private:
    struct LoadedPlugin {
        QLibrary* Library;
        IModule* Module;
        PluginInfo Info;
    };

    using CreateModuleFunc = IModule* (*)();
    using PluginInfoFunc = const char* (*)();

    PluginInfo ParsePluginInfo(const QString& FilePath, PluginInfoFunc InfoFunc) const;

    ICore* CoreRef;
    QList<LoadedPlugin> LoadedPlugins;
    QStringList PluginDirectories;
};

}
