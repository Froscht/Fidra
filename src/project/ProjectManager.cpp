#include "ProjectManager.h"
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <fidra/ICore.h>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QTextStream>
#include <QCryptographicHash>
#include <QSettings>

namespace Fidra {

ProjectManager::ProjectManager(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , DbRef(nullptr)
    , Loaded(false)
    , AutoSaveTimer(new QTimer(this))
{
    AutoSaveTimer->setInterval(300000);
    connect(AutoSaveTimer, &QTimer::timeout, this, &ProjectManager::OnAutoSaveTimer);
}

ProjectManager::~ProjectManager() {
    StopAutoSave();
}

void ProjectManager::SetCore(ICore* Core) { CoreRef = Core; }
void ProjectManager::SetDatabase(AnalysisDatabase* Db) { DbRef = Db; }

QString ProjectManager::AddressToHex(Address Addr) {
    return QStringLiteral("0x%1").arg(Addr, 0, 16);
}

Address ProjectManager::ParseHexAddress(const QString& Str) {
    QString Cleaned = Str;
    if (Cleaned.startsWith(QStringLiteral("0x")) || Cleaned.startsWith(QStringLiteral("0X")))
        Cleaned = Cleaned.mid(2);
    bool Ok = false;
    Address Result = Cleaned.toULongLong(&Ok, 16);
    return Ok ? Result : 0;
}

QString ProjectManager::ComputeFileHash(const QString& FilePath) {
    QFile File(FilePath);
    if (!File.open(QIODevice::ReadOnly))
        return {};
    QCryptographicHash Hash(QCryptographicHash::Sha256);
    Hash.addData(&File);
    return Hash.result().toHex();
}

bool ProjectManager::SaveProject(const QString& Path) {
    if (!DbRef) {
        emit ProjectError(QStringLiteral("No analysis database"));
        return false;
    }

    QJsonObject Root;
    Root[QStringLiteral("version")] = 2;
    Root[QStringLiteral("tool")] = QStringLiteral("Fidra");
    Root[QStringLiteral("save_date")] = QDateTime::currentDateTime().toString(Qt::ISODate);
    Root[QStringLiteral("binary_path")] = DbRef->GetBinaryInfo().FilePath;
    Root[QStringLiteral("binary_hash")] = ComputeFileHash(DbRef->GetBinaryInfo().FilePath);

    Root[QStringLiteral("names")] = SerializeNames();
    Root[QStringLiteral("comments")] = SerializeComments();
    Root[QStringLiteral("functions")] = SerializeFunctions();
    Root[QStringLiteral("strings")] = SerializeStrings();
    Root[QStringLiteral("bookmarks")] = SerializeBookmarks();
    Root[QStringLiteral("xrefs")] = SerializeXrefs();

    QJsonDocument Doc(Root);
    QByteArray Data = Doc.toJson(QJsonDocument::Compact);
    QByteArray Compressed = qCompress(Data, 9);

    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        emit ProjectError(QStringLiteral("Cannot write: ") + File.errorString());
        return false;
    }

    File.write("FDRA", 4);
    uint32_t Ver = 2;
    File.write(reinterpret_cast<const char*>(&Ver), 4);
    File.write(Compressed);
    File.close();

    Loaded = true;
    Info.FilePath = Path;
    Info.Name = QFileInfo(Path).baseName();
    Info.BinaryPath = DbRef->GetBinaryInfo().FilePath;
    Info.Version = 2;
    Info.LastModified = QDateTime::currentDateTime().toString(Qt::ISODate);

    emit ProjectSaved(Path);
    return true;
}

bool ProjectManager::LoadProject(const QString& Path) {
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly)) {
        emit ProjectError(QStringLiteral("Cannot open: ") + File.errorString());
        return false;
    }

    char Magic[4];
    if (File.read(Magic, 4) != 4 || QByteArray(Magic, 4) != QByteArray("FDRA", 4)) {
        emit ProjectError(QStringLiteral("Invalid project file format"));
        return false;
    }

    uint32_t Ver = 0;
    File.read(reinterpret_cast<char*>(&Ver), 4);
    QByteArray Compressed = File.readAll();
    File.close();

    QByteArray Decompressed = qUncompress(Compressed);
    if (Decompressed.isEmpty()) {
        emit ProjectError(QStringLiteral("Decompression failed"));
        return false;
    }

    QJsonParseError ParseError;
    QJsonDocument Doc = QJsonDocument::fromJson(Decompressed, &ParseError);
    if (Doc.isNull()) {
        emit ProjectError(QStringLiteral("JSON error: ") + ParseError.errorString());
        return false;
    }

    QJsonObject Root = Doc.object();

    if (DbRef) {
        DeserializeNames(Root[QStringLiteral("names")].toObject());
        DeserializeComments(Root[QStringLiteral("comments")].toObject());
        DeserializeFunctions(Root[QStringLiteral("functions")].toObject());
        DeserializeStrings(Root[QStringLiteral("strings")].toObject());
        DeserializeXrefs(Root[QStringLiteral("xrefs")].toArray());
    }

    Loaded = true;
    Info.FilePath = Path;
    Info.Name = QFileInfo(Path).baseName();
    Info.BinaryPath = Root[QStringLiteral("binary_path")].toString();
    Info.Version = static_cast<int>(Ver);
    Info.LastModified = Root[QStringLiteral("save_date")].toString();

    emit ProjectLoaded(Path);
    return true;
}

bool ProjectManager::IsProjectLoaded() const { return Loaded; }
ProjectInfo ProjectManager::GetProjectInfo() const { return Info; }
QString ProjectManager::CurrentProjectPath() const { return Info.FilePath; }

bool ProjectManager::ExportDatabase(const QString& Path) {
    if (!DbRef) {
        emit ProjectError(QStringLiteral("No database"));
        return false;
    }
    QJsonObject Root = SerializeDatabase(DbRef);
    QJsonDocument Doc(Root);
    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly | QIODevice::Text)) {
        emit ProjectError(QStringLiteral("Cannot write: ") + File.errorString());
        return false;
    }
    File.write(Doc.toJson(QJsonDocument::Indented));
    File.close();
    return true;
}

bool ProjectManager::ImportDatabase(const QString& Path) {
    if (!DbRef) {
        emit ProjectError(QStringLiteral("No database"));
        return false;
    }
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly | QIODevice::Text)) {
        emit ProjectError(QStringLiteral("Cannot read: ") + File.errorString());
        return false;
    }
    QJsonParseError Err;
    QJsonDocument Doc = QJsonDocument::fromJson(File.readAll(), &Err);
    File.close();
    if (Doc.isNull()) {
        emit ProjectError(QStringLiteral("JSON error: ") + Err.errorString());
        return false;
    }
    return DeserializeDatabase(DbRef, Doc.object());
}

void ProjectManager::StartAutoSave() {
    if (!AutoSaveTimer->isActive()) AutoSaveTimer->start();
}

void ProjectManager::StopAutoSave() {
    if (AutoSaveTimer->isActive()) AutoSaveTimer->stop();
}

void ProjectManager::OnAutoSaveTimer() {
    if (Loaded && !Info.FilePath.isEmpty() && DbRef)
        SaveProject(Info.FilePath);
}

QJsonObject ProjectManager::SerializeNames() const {
    QJsonObject Obj;
    if (!DbRef) return Obj;
    QMap<Address, QString> Names = DbRef->GetAllNames();
    for (auto It = Names.constBegin(); It != Names.constEnd(); ++It)
        Obj[AddressToHex(It.key())] = It.value();
    return Obj;
}

QJsonObject ProjectManager::SerializeComments() const {
    QJsonObject Obj;
    if (!DbRef) return Obj;
    QMap<Address, QString> Comments = DbRef->GetAllComments();
    for (auto It = Comments.constBegin(); It != Comments.constEnd(); ++It)
        Obj[AddressToHex(It.key())] = It.value();
    return Obj;
}

QJsonObject ProjectManager::SerializeFunctions() const {
    QJsonObject Obj;
    if (!DbRef) return Obj;
    QList<AnalyzedFunction> Functions = DbRef->GetAllFunctions();
    for (const auto& Func : Functions) {
        QJsonObject FuncObj;
        FuncObj[QStringLiteral("end")] = AddressToHex(Func.End);
        FuncObj[QStringLiteral("name")] = Func.Name;
        FuncObj[QStringLiteral("size")] = static_cast<qint64>(Func.End - Func.Start);
        Obj[AddressToHex(Func.Start)] = FuncObj;
    }
    return Obj;
}

QJsonObject ProjectManager::SerializeStrings() const {
    QJsonObject Obj;
    if (!DbRef) return Obj;
    QList<AnalyzedString> Strings = DbRef->GetAllStrings();
    for (const auto& Str : Strings)
        Obj[AddressToHex(Str.Addr)] = Str.Value;
    return Obj;
}

QJsonObject ProjectManager::SerializeBookmarks() const {
    return {};
}

QJsonObject ProjectManager::SerializeXrefs() const {
    return {};
}

void ProjectManager::DeserializeNames(const QJsonObject& Json) {
    for (auto It = Json.constBegin(); It != Json.constEnd(); ++It) {
        Address Addr = ParseHexAddress(It.key());
        if (Addr) DbRef->SetName(Addr, It.value().toString());
    }
}

void ProjectManager::DeserializeComments(const QJsonObject& Json) {
    for (auto It = Json.constBegin(); It != Json.constEnd(); ++It) {
        Address Addr = ParseHexAddress(It.key());
        if (Addr) DbRef->SetComment(Addr, It.value().toString());
    }
}

void ProjectManager::DeserializeFunctions(const QJsonObject& Json) {
    for (auto It = Json.constBegin(); It != Json.constEnd(); ++It) {
        Address Start = ParseHexAddress(It.key());
        if (!Start) continue;
        QJsonObject FuncObj = It.value().toObject();
        QString Name = FuncObj[QStringLiteral("name")].toString();
        if (!Name.isEmpty()) {
            if (DbRef->HasFunction(Start)) {
                AnalyzedFunction Func = DbRef->GetFunction(Start);
                Func.Name = Name;
                DbRef->UpdateFunction(Start, Func);
            }
            DbRef->SetName(Start, Name);
        }
    }
}

void ProjectManager::DeserializeStrings(const QJsonObject& Json) {
    for (auto It = Json.constBegin(); It != Json.constEnd(); ++It) {
        Address Addr = ParseHexAddress(It.key());
        if (Addr) DbRef->SetName(Addr, It.value().toString());
    }
}

void ProjectManager::DeserializeXrefs(const QJsonArray& Arr) {
    Q_UNUSED(Arr);
}

QJsonObject ProjectManager::SerializeDatabase(const AnalysisDatabase* Db) {
    QJsonObject Root;
    Root[QStringLiteral("binary_path")] = Db->GetBinaryInfo().FilePath;

    QJsonObject NamesObj;
    QMap<Address, QString> Names = Db->GetAllNames();
    for (auto It = Names.constBegin(); It != Names.constEnd(); ++It)
        NamesObj[AddressToHex(It.key())] = It.value();
    Root[QStringLiteral("names")] = NamesObj;

    QJsonObject CommentsObj;
    QMap<Address, QString> Comments = Db->GetAllComments();
    for (auto It = Comments.constBegin(); It != Comments.constEnd(); ++It)
        CommentsObj[AddressToHex(It.key())] = It.value();
    Root[QStringLiteral("comments")] = CommentsObj;

    QJsonArray FuncsArr;
    QList<AnalyzedFunction> Functions = Db->GetAllFunctions();
    for (const auto& Func : Functions) {
        QJsonObject FuncObj;
        FuncObj[QStringLiteral("start")] = AddressToHex(Func.Start);
        FuncObj[QStringLiteral("end")] = AddressToHex(Func.End);
        FuncObj[QStringLiteral("name")] = Func.Name;
        FuncsArr.append(FuncObj);
    }
    Root[QStringLiteral("functions")] = FuncsArr;

    return Root;
}

bool ProjectManager::DeserializeDatabase(AnalysisDatabase* Db, const QJsonObject& Json) {
    QJsonObject NamesObj = Json[QStringLiteral("names")].toObject();
    for (auto It = NamesObj.constBegin(); It != NamesObj.constEnd(); ++It) {
        Address Addr = ParseHexAddress(It.key());
        if (Addr) Db->SetName(Addr, It.value().toString());
    }

    QJsonObject CommentsObj = Json[QStringLiteral("comments")].toObject();
    for (auto It = CommentsObj.constBegin(); It != CommentsObj.constEnd(); ++It) {
        Address Addr = ParseHexAddress(It.key());
        if (Addr) Db->SetComment(Addr, It.value().toString());
    }

    QJsonArray FuncsArr = Json[QStringLiteral("functions")].toArray();
    for (const auto& Val : FuncsArr) {
        QJsonObject FuncObj = Val.toObject();
        Address Start = ParseHexAddress(FuncObj[QStringLiteral("start")].toString());
        QString Name = FuncObj[QStringLiteral("name")].toString();
        if (Start && !Name.isEmpty()) {
            if (Db->HasFunction(Start)) {
                AnalyzedFunction Func = Db->GetFunction(Start);
                Func.Name = Name;
                Db->UpdateFunction(Start, Func);
            }
            Db->SetName(Start, Name);
        }
    }

    return true;
}

}
