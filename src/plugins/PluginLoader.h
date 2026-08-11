#pragma once

#include <fidra/IPlugin.h>
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
    QString Description;
    QString Version;
    QString Author;
    QString FilePath;
    bool IsLoaded;
    PluginType Type;
    bool Enabled;
};

class PluginLoader : public QObject {
    Q_OBJECT

public:
    explicit PluginLoader(ICore* Core, QObject* Parent = nullptr);
    ~PluginLoader() override;

    QStringList ScanDirectory(const QString& Path);
    bool LoadPlugin(const QString& Path);
    void UnloadPlugin(const QString& Name);
    void UnloadAll();
    QVector<PluginInfo> GetLoadedPlugins() const;
    QStringList GetSearchPaths() const;
    void AddSearchPath(const QString& Path);
    void ScanDefaultDirectories();
    void SetPluginEnabled(const QString& Name, bool Enabled);
    bool IsPluginEnabled(const QString& Name) const;

signals:
    void PluginLoaded(const QString& Name);
    void PluginUnloaded(const QString& Name);
    void ErrorOccurred(const QString& Name, const QString& Error);

private:
    struct LoadedPluginRecord {
        QLibrary* Library;
        IPlugin* Plugin;
        DestroyPluginFunc Destroyer;
        PluginInfo Info;
    };

    QString PluginTypeToString(PluginType Type) const;

    ICore* CoreRef;
    QList<LoadedPluginRecord> Plugins;
    QStringList SearchPaths;
};

}
