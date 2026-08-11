#include "PluginLoader.h"
#include <QDir>
#include <QDirIterator>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>

namespace Fidra {

PluginLoader::PluginLoader(QObject* Parent)
    : QObject(Parent)
{
    QString ConfigPath = QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation);
    PluginDirectories.append(ConfigPath + QStringLiteral("/fidra/plugins"));
    PluginDirectories.append(QStringLiteral("/usr/lib/fidra/plugins"));
}

PluginLoader::~PluginLoader()
{
    UnloadAll();
}

void PluginLoader::SetPluginDirectory(const QString& Path)
{
    if (!PluginDirectories.contains(Path)) {
        PluginDirectories.append(Path);
    }
}

QStringList PluginLoader::DiscoverPlugins() const
{
    QStringList FoundPlugins;
    QStringList NameFilters;
    NameFilters << QStringLiteral("*.so");

    for (const QString& DirPath : PluginDirectories) {
        QDir Dir(DirPath);
        if (!Dir.exists()) {
            continue;
        }

        QDirIterator Iterator(DirPath, NameFilters, QDir::Files, QDirIterator::NoIteratorFlags);
        while (Iterator.hasNext()) {
            Iterator.next();
            QString AbsolutePath = Iterator.fileInfo().absoluteFilePath();
            bool AlreadyLoaded = false;
            for (const LoadedPlugin& Lp : LoadedPlugins) {
                if (Lp.Info.Path == AbsolutePath) {
                    AlreadyLoaded = true;
                    break;
                }
            }
            if (!AlreadyLoaded && !FoundPlugins.contains(AbsolutePath)) {
                FoundPlugins.append(AbsolutePath);
            }
        }
    }

    return FoundPlugins;
}

bool PluginLoader::LoadPlugin(const QString& Path)
{
    QFileInfo FileInfo(Path);
    if (!FileInfo.exists() || !FileInfo.isFile()) {
        emit PluginError(FileInfo.fileName(), QStringLiteral("File does not exist: ") + Path);
        return false;
    }

    for (const LoadedPlugin& Lp : LoadedPlugins) {
        if (Lp.Info.Path == Path) {
            emit PluginError(FileInfo.fileName(), QStringLiteral("Plugin already loaded: ") + Path);
            return false;
        }
    }

    QLibrary* Lib = new QLibrary(Path, this);
    Lib->setLoadHints(QLibrary::ResolveAllSymbolsHint);

    if (!Lib->load()) {
        QString ErrorMsg = Lib->errorString();
        emit PluginError(FileInfo.fileName(), QStringLiteral("Failed to load library: ") + ErrorMsg);
        delete Lib;
        return false;
    }

    auto CreateFunc = reinterpret_cast<CreateModuleFunc>(Lib->resolve("fidra_create_module"));
    if (!CreateFunc) {
        emit PluginError(FileInfo.fileName(), QStringLiteral("Missing fidra_create_module export"));
        Lib->unload();
        delete Lib;
        return false;
    }

    IModule* Module = CreateFunc();
    if (!Module) {
        emit PluginError(FileInfo.fileName(), QStringLiteral("fidra_create_module returned null"));
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
            emit PluginError(Record.Info.Name, QStringLiteral("Plugin with this name already loaded"));
            delete Module;
            Lib->unload();
            delete Lib;
            return false;
        }
    }

    LoadedPlugins.append(Record);
    emit PluginLoaded(Record.Info.Name);
    return true;
}

void PluginLoader::UnloadPlugin(const QString& Name)
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
            return;
        }
    }
}

void PluginLoader::UnloadAll()
{
    while (!LoadedPlugins.isEmpty()) {
        UnloadPlugin(LoadedPlugins.last().Info.Name);
    }
}

QList<IModule*> PluginLoader::GetLoadedPlugins() const
{
    QList<IModule*> Modules;
    for (const LoadedPlugin& Lp : LoadedPlugins) {
        Modules.append(Lp.Module);
    }
    return Modules;
}

QList<PluginLoader::PluginInfo> PluginLoader::GetPluginInfos() const
{
    QList<PluginInfo> Infos;
    for (const LoadedPlugin& Lp : LoadedPlugins) {
        Infos.append(Lp.Info);
    }
    return Infos;
}

QStringList PluginLoader::GetPluginDirectories() const
{
    return PluginDirectories;
}

PluginLoader::PluginInfo PluginLoader::ParsePluginInfo(const QString& FilePath, PluginInfoFunc InfoFunc) const
{
    PluginInfo Info;
    Info.Path = FilePath;
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
