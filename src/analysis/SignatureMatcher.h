#pragma once

#include "AnalysisTypes.h"
#include "AnalysisDatabase.h"
#include <QObject>
#include <QList>
#include <QByteArray>

namespace Fidra {

struct FunctionSignature {
    QString Name;
    QString Module;
    QList<int16_t> Pattern;
    int MinSize;
};

struct SignatureMatch {
    Address Addr;
    QString Name;
    QString Module;
    int Confidence;
};

class SignatureMatcher {
public:
    SignatureMatcher();
    ~SignatureMatcher();

    void LoadBuiltinSignatures(bool Is64Bit);
    void AddSignature(const QString& Name, const QString& Module, const QString& HexPattern, int MinSize = 0);

    QList<SignatureMatch> MatchFunctions(AnalysisDatabase* Db);
    SignatureMatch MatchSingle(const uint8_t* Data, size_t Size, Address Addr);

    int SignatureCount() const;

private:
    QList<int16_t> ParsePattern(const QString& HexPattern);
    bool MatchPattern(const uint8_t* Data, size_t Size, const QList<int16_t>& Pattern);

    QList<FunctionSignature> Signatures;
};

}
