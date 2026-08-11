#pragma once

#include <fidra/Types.h>
#include <QObject>
#include <QByteArray>
#include <QDateTime>
#include <QList>
#include <QMap>
#include <QString>

namespace Fidra {

class AnalysisDatabase;

struct PatchEntry {
    Address Addr;
    QByteArray OriginalBytes;
    QByteArray PatchedBytes;
    QString Description;
    bool IsApplied;
    QDateTime Timestamp;
};

class PatchEngine : public QObject {
    Q_OBJECT

public:
    explicit PatchEngine(QObject* Parent = nullptr);
    ~PatchEngine() override;

    bool PatchBytes(AnalysisDatabase* Db, Address Addr, const QByteArray& NewBytes, const QString& Desc = {});
    bool NopOut(AnalysisDatabase* Db, Address Addr, int Size);
    bool NopFunction(AnalysisDatabase* Db, Address FuncAddr);
    bool RevertPatch(int PatchIndex);
    bool RevertAll();

    bool Assemble(const QString& Assembly, Address Addr, QByteArray& OutBytes, QString& OutError);

    bool SavePatchedBinary(AnalysisDatabase* Db, const QString& OutputPath);
    bool ExportPatches(const QString& Path);
    bool ImportPatches(const QString& Path);

    QList<PatchEntry> GetPatches() const;
    int PatchCount() const;

signals:
    void PatchApplied(Address Addr, const QString& Desc);
    void PatchReverted(int Index);

private:
    bool WriteToSegment(AnalysisDatabase* Db, Address Addr, const QByteArray& Bytes);
    bool AssembleLine(const QString& Line, Address Addr, QByteArray& OutBytes, QString& OutError);

    int ParseRegister64(const QString& Name) const;
    int ParseRegister32(const QString& Name) const;
    int ParseRegister8(const QString& Name) const;
    bool ParseImmediate(const QString& Text, int64_t& OutValue) const;
    bool NeedsRexW(const QString& RegName) const;
    bool NeedsRex(int Reg) const;
    uint8_t RexByte(bool W, bool R, bool X, bool B) const;
    uint8_t ModRmByte(uint8_t Mod, uint8_t Reg, uint8_t Rm) const;

    QList<PatchEntry> Patches;
    QMap<QString, int> RegisterMap64;
    QMap<QString, int> RegisterMap32;
    QMap<QString, int> RegisterMap8;
};

}
