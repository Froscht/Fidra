#pragma once

#include <fidra/Types.h>
#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>

namespace Fidra {
class AnalysisDatabase;
class ICore;

struct ProjectInfo {
    QString Name;
    QString FilePath;
    QString BinaryPath;
    QString Created;
    QString LastModified;
    int Version;
};

class ProjectManager : public QObject {
    Q_OBJECT
public:
    explicit ProjectManager(QObject* Parent = nullptr);
    ~ProjectManager() override;

    void SetCore(ICore* Core);
    void SetDatabase(AnalysisDatabase* Db);

    bool SaveProject(const QString& Path);
    bool LoadProject(const QString& Path);
    bool IsProjectLoaded() const;
    ProjectInfo GetProjectInfo() const;
    QString CurrentProjectPath() const;

    bool ExportDatabase(const QString& Path);
    bool ImportDatabase(const QString& Path);

    void StartAutoSave();
    void StopAutoSave();

    static QJsonObject SerializeDatabase(const AnalysisDatabase* Db);
    static bool DeserializeDatabase(AnalysisDatabase* Db, const QJsonObject& Json);

signals:
    void ProjectSaved(const QString& Path);
    void ProjectLoaded(const QString& Path);
    void ProjectError(const QString& Error);

private:
    QJsonObject SerializeNames() const;
    QJsonObject SerializeComments() const;
    QJsonObject SerializeFunctions() const;
    QJsonObject SerializeStrings() const;
    QJsonObject SerializeBookmarks() const;
    QJsonObject SerializeXrefs() const;
    void DeserializeNames(const QJsonObject& Json);
    void DeserializeComments(const QJsonObject& Json);
    void DeserializeFunctions(const QJsonObject& Json);
    void DeserializeStrings(const QJsonObject& Json);
    void DeserializeXrefs(const QJsonArray& Arr);
    void OnAutoSaveTimer();
    static QString ComputeFileHash(const QString& FilePath);
    static Address ParseHexAddress(const QString& Str);
    static QString AddressToHex(Address Addr);

    ICore* CoreRef;
    AnalysisDatabase* DbRef;
    ProjectInfo Info;
    bool Loaded;
    QTimer* AutoSaveTimer;
};
}
