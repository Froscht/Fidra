#pragma once

#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QWebEngineProfile>
#include <QWebEngineScript>

namespace Fidra {

struct FingerprintConfig {
    QString UserAgent;
    QString AcceptLanguage;
    QString Platform;
    QString Vendor;
    QString WebGlVendor;
    QString WebGlRenderer;
    QString Timezone;
    int ScreenWidth;
    int ScreenHeight;
    int ColorDepth;
    int HardwareConcurrency;
    double DeviceMemory;
    bool CanvasNoise;
    bool WebGlNoise;

    FingerprintConfig();
    QJsonObject ToJson() const;
    static FingerprintConfig FromJson(const QJsonObject& Json);
};

class BrowserProfile : public QObject {
    Q_OBJECT

public:
    explicit BrowserProfile(const QString& ProfileName, QObject* Parent = nullptr);
    ~BrowserProfile() override;

    QWebEngineProfile* Profile() const;
    QString ProfileName() const;

    void SetFingerprint(const FingerprintConfig& Config);
    FingerprintConfig GetFingerprint() const;

    void SaveToFile(const QString& FilePath);
    bool LoadFromFile(const QString& FilePath);

    static FingerprintConfig GenerateRandomFingerprint();

    QWebEngineScript BuildFingerprintScript() const;

signals:
    void FingerprintChanged();

private:
    void ApplyFingerprint();
    QString GenerateSpoofScript() const;

    QWebEngineProfile* EngineProfile;
    QString Name;
    FingerprintConfig Fingerprint;
};

}
