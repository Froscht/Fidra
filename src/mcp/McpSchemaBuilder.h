#pragma once

#include <QJsonObject>
#include <QJsonArray>
#include <QString>
#include <initializer_list>
#include <utility>

namespace Fidra {
namespace Schema {

inline QJsonObject String(const QString& Desc) {
    QJsonObject P;
    P[QStringLiteral("type")] = QStringLiteral("string");
    P[QStringLiteral("description")] = Desc;
    return P;
}

inline QJsonObject StringEnum(const QString& Desc, std::initializer_list<QString> Values) {
    QJsonObject P;
    P[QStringLiteral("type")] = QStringLiteral("string");
    P[QStringLiteral("description")] = Desc;
    QJsonArray Arr;
    for (const auto& V : Values) Arr.append(V);
    P[QStringLiteral("enum")] = Arr;
    return P;
}

inline QJsonObject Integer(const QString& Desc, int Min = -1, int Max = -1) {
    QJsonObject P;
    P[QStringLiteral("type")] = QStringLiteral("integer");
    P[QStringLiteral("description")] = Desc;
    if (Min >= 0) P[QStringLiteral("minimum")] = Min;
    if (Max >= 0) P[QStringLiteral("maximum")] = Max;
    return P;
}

inline QJsonObject Number(const QString& Desc) {
    QJsonObject P;
    P[QStringLiteral("type")] = QStringLiteral("number");
    P[QStringLiteral("description")] = Desc;
    return P;
}

inline QJsonObject Boolean(const QString& Desc) {
    QJsonObject P;
    P[QStringLiteral("type")] = QStringLiteral("boolean");
    P[QStringLiteral("description")] = Desc;
    return P;
}

inline QJsonObject Array(const QString& Desc, const QJsonObject& Items = QJsonObject()) {
    QJsonObject P;
    P[QStringLiteral("type")] = QStringLiteral("array");
    P[QStringLiteral("description")] = Desc;
    if (!Items.isEmpty()) P[QStringLiteral("items")] = Items;
    return P;
}

inline QJsonObject Object(const QString& Desc) {
    QJsonObject P;
    P[QStringLiteral("type")] = QStringLiteral("object");
    P[QStringLiteral("description")] = Desc;
    return P;
}

inline QJsonObject Build(std::initializer_list<std::pair<QString, QJsonObject>> Props,
                          std::initializer_list<QString> Required = {}) {
    QJsonObject S;
    S[QStringLiteral("type")] = QStringLiteral("object");
    QJsonObject Properties;
    for (const auto& Pair : Props) {
        Properties[Pair.first] = Pair.second;
    }
    S[QStringLiteral("properties")] = Properties;
    if (Required.size() > 0) {
        QJsonArray Req;
        for (const auto& R : Required) Req.append(R);
        S[QStringLiteral("required")] = Req;
    }
    return S;
}

inline QJsonObject Empty() {
    QJsonObject S;
    S[QStringLiteral("type")] = QStringLiteral("object");
    S[QStringLiteral("properties")] = QJsonObject();
    return S;
}

inline QJsonObject Ok(const QString& Msg = QStringLiteral("success")) {
    QJsonObject R;
    R[QStringLiteral("success")] = true;
    R[QStringLiteral("message")] = Msg;
    return R;
}

inline QJsonObject Err(const QString& Msg) {
    QJsonObject R;
    R[QStringLiteral("error")] = Msg;
    return R;
}

inline QJsonObject NotAttached() {
    return Err(QStringLiteral("No process attached"));
}

inline QJsonObject NoCore() {
    return Err(QStringLiteral("Core not initialized"));
}

inline Address ParseHexAddress(const QString& AddrStr) {
    QString Cleaned = AddrStr.trimmed();
    if (Cleaned.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
        Cleaned = Cleaned.mid(2);
    }
    bool Ok = false;
    Address Addr = Cleaned.toULongLong(&Ok, 16);
    return Ok ? Addr : 0;
}

inline QString FormatAddress(Address Addr) {
    return QStringLiteral("0x") + QString::number(Addr, 16).toUpper();
}

}
}
