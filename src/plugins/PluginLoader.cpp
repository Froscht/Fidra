#include "PluginLoader.h"
#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QFileInfo>
#include <QStandardPaths>

namespace Fidra {

PluginLoader::PluginLoader(ICore* Core, QObject* Parent)
    : QObject(Parent)
    , CoreRef(Core)
{
    SearchPaths.append(QCoreApplication::applicationDirPath() + QStringLiteral("/plugins/"));

    QString HomePath = QDir::homePath();
    SearchPaths.append(HomePath + QStringLiteral("/.fidra/plugins/"));
}

PluginLoader::~PluginLoader()
{
    UnloadAll();
}

QStringList PluginLoader::ScanDirectory(const QString& Path)
{
    QStringList FoundFiles;
    QDir Dir(Path);

    if (!Dir.exists()) {
        emit ErrorOccurred(QStringLiteral("Scanner"), QStringLiteral("Directory does not exist: ") + Path);
        return FoundFiles;
    }

    QStringList NameFilters;
#ifdef Q_OS_WIN
    NameFilters << QStringLiteral("*.dll");
#elif defined(Q_OS_MAC)
    NameFilters << QStringLiteral("*.dylib");
#else
    NameFilters << QStringLiteral("*.so");
#endif

    QDirIterator Iterator(Path, NameFilters, QDir::Files, QDirIterator::NoIteratorFlags);
    while (Iterator.hasNext()) {
        Iterator.next();
        QString AbsolutePath = Iterator.fileInfo().absoluteFilePath();
        bool AlreadyLoaded = false;
        for (const LoadedPluginRecord& Record : Plugins) {
            if (Record.Info.FilePath == AbsolutePath) {
                AlreadyLoaded = true;
                break;
            }
        }
        if (!AlreadyLoaded && !FoundFiles.contains(AbsolutePath)) {
            FoundFiles.append(AbsolutePath);
        }
    }

    if (!SearchPaths.contains(Path)) {
        SearchPaths.append(Path);
    }

    return FoundFiles;
}

bool PluginLoader::LoadPlugin(const QString& Path)
{
    QFileInfo FileInfo(Path);
    if (!FileInfo.exists() || !FileInfo.isFile()) {
        emit ErrorOccurred(FileInfo.fileName(), QStringLiteral("File does not exist: ") + Path);
        return false;
    }

    for (const LoadedPluginRecord& Record : Plugins) {
        if (Record.Info.FilePath == Path) {
            emit ErrorOccurred(FileInfo.fileName(), QStringLiteral("Plugin already loaded: ") + Path);
            return false;
        }
    }

    QLibrary* Lib = new QLibrary(Path, this);
    Lib->setLoadHints(QLibrary::ResolveAllSymbolsHint);

    if (!Lib->load()) {
        QString ErrorMsg = Lib->errorString();
        emit ErrorOccurred(FileInfo.fileName(), QStringLiteral("Failed to load: ") + ErrorMsg);
        delete Lib;
        return false;
    }

    auto Creator = reinterpret_cast<CreatePluginFunc>(Lib->resolve("CreatePlugin"));
    if (!Creator) {
        emit ErrorOccurred(FileInfo.fileName(), QStringLiteral("Missing CreatePlugin export"));
        Lib->unload();
        delete Lib;
        return false;
    }

    auto Destroyer = reinterpret_cast<DestroyPluginFunc>(Lib->resolve("DestroyPlugin"));
    if (!Destroyer) {
        emit ErrorOccurred(FileInfo.fileName(), QStringLiteral("Missing DestroyPlugin export"));
        Lib->unload();
        delete Lib;
        return false;
    }

    IPlugin* PluginInstance = Creator();
    if (!PluginInstance) {
        emit ErrorOccurred(FileInfo.fileName(), QStringLiteral("CreatePlugin returned null"));
        Lib->unload();
        delete Lib;
        return false;
    }

    for (const LoadedPluginRecord& Record : Plugins) {
        if (Record.Info.Name == PluginInstance->Name()) {
            emit ErrorOccurred(PluginInstance->Name(), QStringLiteral("Plugin with this name already loaded"));
            Destroyer(PluginInstance);
            Lib->unload();
            delete Lib;
            return false;
        }
    }

    if (!PluginInstance->Initialize(CoreRef)) {
        emit ErrorOccurred(PluginInstance->Name(), QStringLiteral("Initialize() returned false"));
        Destroyer(PluginInstance);
        Lib->unload();
        delete Lib;
        return false;
    }

    LoadedPluginRecord Record;
    Record.Library = Lib;
    Record.Plugin = PluginInstance;
    Record.Destroyer = Destroyer;
    Record.Info.Name = PluginInstance->Name();
    Record.Info.Description = PluginInstance->Description();
    Record.Info.Version = PluginInstance->Version();
    Record.Info.Author = PluginInstance->Author();
    Record.Info.FilePath = Path;
    Record.Info.IsLoaded = true;
    Record.Info.Type = PluginInstance->Type();
    Record.Info.Enabled = true;

    Plugins.append(Record);

    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Loaded plugin: ") + Record.Info.Name);
    }

    emit PluginLoaded(Record.Info.Name);
    return true;
}

void PluginLoader::UnloadPlugin(const QString& Name)
{
    for (int I = 0; I < Plugins.size(); ++I) {
        if (Plugins[I].Info.Name == Name) {
            LoadedPluginRecord Record = Plugins[I];

            if (Record.Plugin) {
                Record.Plugin->Shutdown();
                if (Record.Destroyer) {
                    Record.Destroyer(Record.Plugin);
                } else {
                    delete Record.Plugin;
                }
            }

            if (Record.Library) {
                Record.Library->unload();
                delete Record.Library;
            }

            Plugins.removeAt(I);

            if (CoreRef) {
                CoreRef->Log(QStringLiteral("Unloaded plugin: ") + Name);
            }

            emit PluginUnloaded(Name);
            return;
        }
    }
}

void PluginLoader::UnloadAll()
{
    while (!Plugins.isEmpty()) {
        UnloadPlugin(Plugins.last().Info.Name);
    }
}

QVector<PluginInfo> PluginLoader::GetLoadedPlugins() const
{
    QVector<PluginInfo> Result;
    for (const LoadedPluginRecord& Record : Plugins) {
        Result.append(Record.Info);
    }
    return Result;
}

QStringList PluginLoader::GetSearchPaths() const
{
    return SearchPaths;
}

void PluginLoader::AddSearchPath(const QString& Path)
{
    if (!SearchPaths.contains(Path)) {
        SearchPaths.append(Path);
    }
}

void PluginLoader::ScanDefaultDirectories()
{
    for (const QString& Dir : SearchPaths) {
        QDir Directory(Dir);
        if (Directory.exists()) {
            QStringList Found = ScanDirectory(Dir);
            for (const QString& PluginPath : Found) {
                LoadPlugin(PluginPath);
            }
        }
    }
}

void PluginLoader::SetPluginEnabled(const QString& Name, bool Enabled)
{
    for (int I = 0; I < Plugins.size(); ++I) {
        if (Plugins[I].Info.Name == Name) {
            Plugins[I].Info.Enabled = Enabled;
            return;
        }
    }
}

bool PluginLoader::IsPluginEnabled(const QString& Name) const
{
    for (const LoadedPluginRecord& Record : Plugins) {
        if (Record.Info.Name == Name) {
            return Record.Info.Enabled;
        }
    }
    return false;
}

QString PluginLoader::PluginTypeToString(PluginType Type) const
{
    switch (Type) {
        case PluginType::Analysis: return QStringLiteral("Analysis");
        case PluginType::UI: return QStringLiteral("UI");
        case PluginType::Import: return QStringLiteral("Import");
        case PluginType::Export: return QStringLiteral("Export");
        case PluginType::Custom: return QStringLiteral("Custom");
    }
    return QStringLiteral("Unknown");
}

}
