#include "PluginManager.h"
#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>

namespace Fidra {

PluginManager::PluginManager(ICore* Core, QObject* Parent)
    : QObject(Parent)
    , CoreRef(Core)
{
    QString ConfigPath = QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation);
    PluginDirectories.append(ConfigPath + QStringLiteral("/fidra/plugins"));
#ifdef Q_OS_WIN
    PluginDirectories.append(QCoreApplication::applicationDirPath() + QStringLiteral("/plugins"));
#else
    PluginDirectories.append(QStringLiteral("/usr/lib/fidra/plugins"));
#endif
}

PluginManager::~PluginManager()
{
    UnloadAll();
}

QVector<PluginInfo> PluginManager::GetPlugins() const
{
    QVector<PluginInfo> Result;
    for (const LoadedPlugin& Lp : LoadedPlugins) {
        Result.append(Lp.Info);
    }
    return Result;
}

bool PluginManager::LoadPlugin(const QString& Path)
{
    QFileInfo FileInfo(Path);
    if (!FileInfo.exists() || !FileInfo.isFile()) {
        emit LogMessage(QStringLiteral("Plugin file does not exist: ") + Path);
        return false;
    }

    for (const LoadedPlugin& Lp : LoadedPlugins) {
        if (Lp.Info.Path == Path || Lp.Info.FilePath == Path) {
            emit LogMessage(QStringLiteral("Plugin already loaded: ") + Path);
            return false;
        }
    }

    QLibrary* Lib = new QLibrary(Path, this);
    Lib->setLoadHints(QLibrary::ResolveAllSymbolsHint);

    if (!Lib->load()) {
        QString ErrorMsg = Lib->errorString();
        emit LogMessage(QStringLiteral("Failed to load library: ") + ErrorMsg);
        delete Lib;
        return false;
    }

    auto CreateFunc = reinterpret_cast<CreateModuleFunc>(Lib->resolve("fidra_create_module"));
    if (!CreateFunc) {
        emit LogMessage(QStringLiteral("Missing fidra_create_module export in: ") + Path);
        Lib->unload();
        delete Lib;
        return false;
    }

    IModule* Module = CreateFunc();
    if (!Module) {
        emit LogMessage(QStringLiteral("fidra_create_module returned null in: ") + Path);
        Lib->unload();
        delete Lib;
        return false;
    }

    auto InfoFunc = reinterpret_cast<PluginInfoFunc>(Lib->resolve("fidra_plugin_info"));

    LoadedPlugin Record;
    Record.Library = Lib;
    Record.Module = Module;
    Record.Info = ParsePluginInfo(Path, InfoFunc);
    Record.Info.Loaded = true;

    if (Record.Info.Name.isEmpty()) {
        Record.Info.Name = Module->Name();
    }
    if (Record.Info.Description.isEmpty()) {
        Record.Info.Description = Module->Description();
    }

    for (const LoadedPlugin& Lp : LoadedPlugins) {
        if (Lp.Info.Name == Record.Info.Name) {
            emit LogMessage(QStringLiteral("Plugin with name already loaded: ") + Record.Info.Name);
            delete Module;
            Lib->unload();
            delete Lib;
            return false;
        }
    }

    Module->Initialize(CoreRef);

    LoadedPlugins.append(Record);
    emit PluginLoaded(Record.Info.Name);
    emit LogMessage(QStringLiteral("Loaded plugin: ") + Record.Info.Name);
    return true;
}

void PluginManager::UnloadPlugin(const QString& Name)
{
    for (int I = 0; I < LoadedPlugins.size(); ++I) {
        if (LoadedPlugins[I].Info.Name == Name) {
            LoadedPlugin Record = LoadedPlugins[I];

            Record.Module->Shutdown();
            delete Record.Module;

            if (Record.Library) {
                Record.Library->unload();
                delete Record.Library;
            }

            LoadedPlugins.removeAt(I);
            emit PluginUnloaded(Name);
            emit LogMessage(QStringLiteral("Unloaded plugin: ") + Name);
            return;
        }
    }
}

void PluginManager::UnloadAll()
{
    while (!LoadedPlugins.isEmpty()) {
        UnloadPlugin(LoadedPlugins.last().Info.Name);
    }
}

void PluginManager::ScanDirectory(const QString& Dir)
{
    if (!PluginDirectories.contains(Dir)) {
        PluginDirectories.append(Dir);
    }

    QStringList NameFilters;
#ifdef Q_OS_WIN
    NameFilters << QStringLiteral("*.dll");
#elif defined(Q_OS_MAC)
    NameFilters << QStringLiteral("*.dylib");
#else
    NameFilters << QStringLiteral("*.so");
#endif

    QDir Directory(Dir);
    if (!Directory.exists()) {
        emit LogMessage(QStringLiteral("Plugin directory does not exist: ") + Dir);
        return;
    }

    QDirIterator Iterator(Dir, NameFilters, QDir::Files, QDirIterator::NoIteratorFlags);
    int Count = 0;
    while (Iterator.hasNext()) {
        Iterator.next();
        QString AbsolutePath = Iterator.fileInfo().absoluteFilePath();
        bool AlreadyLoaded = false;
        for (const LoadedPlugin& Lp : LoadedPlugins) {
            if (Lp.Info.Path == AbsolutePath || Lp.Info.FilePath == AbsolutePath) {
                AlreadyLoaded = true;
                break;
            }
        }
        if (!AlreadyLoaded) {
            if (LoadPlugin(AbsolutePath)) {
                ++Count;
            }
        }
    }

    emit LogMessage(QStringLiteral("Scanned %1: loaded %2 plugins").arg(Dir).arg(Count));
}

void PluginManager::ScanDefaultDirectories()
{
    for (const QString& Dir : PluginDirectories) {
        QDir Directory(Dir);
        if (Directory.exists()) {
            ScanDirectory(Dir);
        }
    }
}

QList<IModule*> PluginManager::GetLoadedModules() const
{
    QList<IModule*> Modules;
    for (const LoadedPlugin& Lp : LoadedPlugins) {
        if (Lp.Module) {
            Modules.append(Lp.Module);
        }
    }
    return Modules;
}

void PluginManager::ExecutePlugin(const QString& Name)
{
    for (const LoadedPlugin& Lp : LoadedPlugins) {
        if (Lp.Info.Name == Name && Lp.Module) {
            emit LogMessage(QStringLiteral("Executing plugin: ") + Name);
            return;
        }
    }
    emit LogMessage(QStringLiteral("Plugin not found: ") + Name);
}

PluginInfo PluginManager::ParsePluginInfo(const QString& FilePath, PluginInfoFunc InfoFunc) const
{
    PluginInfo Info;
    Info.Path = FilePath;
    Info.FilePath = FilePath;
    Info.Loaded = false;
    Info.Version = QStringLiteral("1.0.0");
    Info.Author = QStringLiteral("Unknown");

    QFileInfo FileInfo(FilePath);
    Info.Name = FileInfo.baseName();
    if (Info.Name.startsWith(QStringLiteral("lib"))) {
        Info.Name = Info.Name.mid(3);
    }

    if (InfoFunc) {
        const char* JsonStr = InfoFunc();
        if (JsonStr) {
            QJsonDocument Doc = QJsonDocument::fromJson(QByteArray(JsonStr));
            if (!Doc.isNull() && Doc.isObject()) {
                QJsonObject Obj = Doc.object();
                if (Obj.contains(QStringLiteral("name"))) {
                    Info.Name = Obj.value(QStringLiteral("name")).toString();
                }
                if (Obj.contains(QStringLiteral("version"))) {
                    Info.Version = Obj.value(QStringLiteral("version")).toString();
                }
                if (Obj.contains(QStringLiteral("author"))) {
                    Info.Author = Obj.value(QStringLiteral("author")).toString();
                }
                if (Obj.contains(QStringLiteral("description"))) {
                    Info.Description = Obj.value(QStringLiteral("description")).toString();
                }
            }
        }
    }

    return Info;
}

}
