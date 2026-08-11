#pragma once

#include <fidra/IModule.h>
#include <fidra/ICore.h>
#include <QObject>
#include <QLibrary>
#include <QString>
#include <QStringList>
#include <QList>

namespace Fidra {

class PluginLoader : public QObject {
    Q_OBJECT

public:
    struct PluginInfo {
        QString Name;
        QString Path;
        QString Version;
        QString Author;
        QString Description;
        bool Loaded;
    };

    explicit PluginLoader(QObject* Parent = nullptr);
    ~PluginLoader() override;

    void SetPluginDirectory(const QString& Path);
    QStringList DiscoverPlugins() const;
    bool LoadPlugin(const QString& Path);
    void UnloadPlugin(const QString& Name);
    void UnloadAll();
    QList<IModule*> GetLoadedPlugins() const;
    QList<PluginInfo> GetPluginInfos() const;
    QStringList GetPluginDirectories() const;

signals:
    void PluginLoaded(const QString& Name);
    void PluginUnloaded(const QString& Name);
    void PluginError(const QString& Name, const QString& Error);

private:
    struct LoadedPlugin {
        QLibrary* Library;
        IModule* Module;
        PluginInfo Info;
    };

    using CreateModuleFunc = IModule* (*)();
    using PluginInfoFunc = const char* (*)();

    PluginInfo ParsePluginInfo(const QString& FilePath, PluginInfoFunc InfoFunc) const;

    QList<LoadedPlugin> LoadedPlugins;
    QStringList PluginDirectories;
};

}
