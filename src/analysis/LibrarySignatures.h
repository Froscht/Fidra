#pragma once

#include "AnalysisTypes.h"
#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>

namespace Fidra {

class AnalysisDatabase;

// Library function recognition (the idea behind IDA's FLIRT). A signature is
// the hash of a function's bytes after masking everything the linker or
// loader changes: relative call/jump targets, RIP-relative displacements and
// absolute addresses into the image. The same library function linked into
// another binary hashes the same, so a stripped binary gets its names back.
//
// File format (.fsig, text):
//   # comment
//   fsig 1 <arch: x86|x86_64> <module name>
//   <size-dec> <hash-hex> <name>
// A size/hash pair listed with two different names is ambiguous and skipped.
class LibrarySignatures {
public:
    struct Entry {
        uint32_t Size = 0;
        uint64_t Hash = 0;
        QString Name;
        QString Module;
    };

    // Functions shorter than this match too often by accident.
    static constexpr uint32_t MinFunctionSize = 24;
    // Only this many leading bytes are hashed (plus the full size).
    static constexpr uint32_t MaxHashedBytes = 1024;

    // Hash of one function's bytes. Returns 0 if the bytes cannot be decoded.
    static uint64_t HashFunction(const uint8_t* Bytes, size_t Size, Address Start, bool Is64Bit,
                                 Address ImageLow, Address ImageHigh);

    // Builds signatures for every named, non-thunk function in Db.
    static QList<Entry> Generate(AnalysisDatabase* Db, const QString& Module);
    static bool Save(const QString& Path, const QList<Entry>& Entries, bool Is64Bit, const QString& Module,
                     QString* Error = nullptr);

    // Loads one .fsig file; skips files for another architecture.
    bool LoadFile(const QString& Path, bool Is64Bit, QString* Error = nullptr);
    // Loads every .fsig in the default directories and $FIDRA_SIG_PATH
    // (a list of directories or files).
    int LoadDefaultDirectories(bool Is64Bit, QStringList* LoadedFiles = nullptr);
    static QStringList DefaultDirectories();

    int Count() const { return static_cast<int>(Table.size()); }

    // Renames matching sub_ functions. Returns the number renamed.
    int Apply(AnalysisDatabase* Db, QStringList* Log = nullptr) const;

private:
    struct Key {
        uint32_t Size;
        uint64_t Hash;
        bool operator==(const Key& O) const { return Size == O.Size && Hash == O.Hash; }
    };
    friend size_t qHash(const Key& K, size_t Seed) { return qHashMulti(Seed, K.Size, K.Hash); }

    void Insert(const Entry& E);

    QHash<Key, Entry> Table;
    QHash<Key, bool> Ambiguous;
};

}
