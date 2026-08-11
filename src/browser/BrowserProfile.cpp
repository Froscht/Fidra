#include "BrowserProfile.h"

#include <QJsonDocument>
#include <QJsonArray>
#include <QFile>
#include <QRandomGenerator>
#include <QWebEngineScript>
#include <QWebEngineScriptCollection>

namespace Fidra {

FingerprintConfig::FingerprintConfig()
    : UserAgent(QStringLiteral("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"))
    , AcceptLanguage(QStringLiteral("en-US,en;q=0.9"))
    , Platform(QStringLiteral("Win32"))
    , Vendor(QStringLiteral("Google Inc."))
    , WebGlVendor(QStringLiteral("Google Inc. (NVIDIA)"))
    , WebGlRenderer(QStringLiteral("ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11)"))
    , Timezone(QStringLiteral("America/New_York"))
    , ScreenWidth(1920)
    , ScreenHeight(1080)
    , ColorDepth(24)
    , HardwareConcurrency(8)
    , DeviceMemory(8.0)
    , CanvasNoise(true)
    , WebGlNoise(true) {
}

QJsonObject FingerprintConfig::ToJson() const {
    QJsonObject Json;
    Json[QStringLiteral("userAgent")] = UserAgent;
    Json[QStringLiteral("acceptLanguage")] = AcceptLanguage;
    Json[QStringLiteral("platform")] = Platform;
    Json[QStringLiteral("vendor")] = Vendor;
    Json[QStringLiteral("webGlVendor")] = WebGlVendor;
    Json[QStringLiteral("webGlRenderer")] = WebGlRenderer;
    Json[QStringLiteral("timezone")] = Timezone;
    Json[QStringLiteral("screenWidth")] = ScreenWidth;
    Json[QStringLiteral("screenHeight")] = ScreenHeight;
    Json[QStringLiteral("colorDepth")] = ColorDepth;
    Json[QStringLiteral("hardwareConcurrency")] = HardwareConcurrency;
    Json[QStringLiteral("deviceMemory")] = DeviceMemory;
    Json[QStringLiteral("canvasNoise")] = CanvasNoise;
    Json[QStringLiteral("webGlNoise")] = WebGlNoise;
    return Json;
}

FingerprintConfig FingerprintConfig::FromJson(const QJsonObject& Json) {
    FingerprintConfig Config;
    if (Json.contains(QStringLiteral("userAgent")))
        Config.UserAgent = Json[QStringLiteral("userAgent")].toString();
    if (Json.contains(QStringLiteral("acceptLanguage")))
        Config.AcceptLanguage = Json[QStringLiteral("acceptLanguage")].toString();
    if (Json.contains(QStringLiteral("platform")))
        Config.Platform = Json[QStringLiteral("platform")].toString();
    if (Json.contains(QStringLiteral("vendor")))
        Config.Vendor = Json[QStringLiteral("vendor")].toString();
    if (Json.contains(QStringLiteral("webGlVendor")))
        Config.WebGlVendor = Json[QStringLiteral("webGlVendor")].toString();
    if (Json.contains(QStringLiteral("webGlRenderer")))
        Config.WebGlRenderer = Json[QStringLiteral("webGlRenderer")].toString();
    if (Json.contains(QStringLiteral("timezone")))
        Config.Timezone = Json[QStringLiteral("timezone")].toString();
    if (Json.contains(QStringLiteral("screenWidth")))
        Config.ScreenWidth = Json[QStringLiteral("screenWidth")].toInt();
    if (Json.contains(QStringLiteral("screenHeight")))
        Config.ScreenHeight = Json[QStringLiteral("screenHeight")].toInt();
    if (Json.contains(QStringLiteral("colorDepth")))
        Config.ColorDepth = Json[QStringLiteral("colorDepth")].toInt();
    if (Json.contains(QStringLiteral("hardwareConcurrency")))
        Config.HardwareConcurrency = Json[QStringLiteral("hardwareConcurrency")].toInt();
    if (Json.contains(QStringLiteral("deviceMemory")))
        Config.DeviceMemory = Json[QStringLiteral("deviceMemory")].toDouble();
    if (Json.contains(QStringLiteral("canvasNoise")))
        Config.CanvasNoise = Json[QStringLiteral("canvasNoise")].toBool();
    if (Json.contains(QStringLiteral("webGlNoise")))
        Config.WebGlNoise = Json[QStringLiteral("webGlNoise")].toBool();
    return Config;
}

BrowserProfile::BrowserProfile(const QString& ProfileName, QObject* Parent)
    : QObject(Parent)
    , EngineProfile(new QWebEngineProfile(ProfileName, this))
    , Name(ProfileName) {
    ApplyFingerprint();
}

BrowserProfile::~BrowserProfile() {
}

QWebEngineProfile* BrowserProfile::Profile() const {
    return EngineProfile;
}

QString BrowserProfile::ProfileName() const {
    return Name;
}

void BrowserProfile::SetFingerprint(const FingerprintConfig& Config) {
    Fingerprint = Config;
    ApplyFingerprint();
    emit FingerprintChanged();
}

FingerprintConfig BrowserProfile::GetFingerprint() const {
    return Fingerprint;
}

void BrowserProfile::SaveToFile(const QString& FilePath) {
    QJsonObject Root;
    Root[QStringLiteral("profileName")] = Name;
    Root[QStringLiteral("fingerprint")] = Fingerprint.ToJson();

    QJsonDocument Doc(Root);
    QFile File(FilePath);
    if (File.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        File.write(Doc.toJson(QJsonDocument::Indented));
        File.close();
    }
}

bool BrowserProfile::LoadFromFile(const QString& FilePath) {
    QFile File(FilePath);
    if (!File.open(QIODevice::ReadOnly)) {
        return false;
    }

    QByteArray Data = File.readAll();
    File.close();

    QJsonParseError ParseError;
    QJsonDocument Doc = QJsonDocument::fromJson(Data, &ParseError);
    if (ParseError.error != QJsonParseError::NoError) {
        return false;
    }

    QJsonObject Root = Doc.object();
    if (Root.contains(QStringLiteral("profileName"))) {
        Name = Root[QStringLiteral("profileName")].toString();
    }
    if (Root.contains(QStringLiteral("fingerprint"))) {
        Fingerprint = FingerprintConfig::FromJson(Root[QStringLiteral("fingerprint")].toObject());
    }

    ApplyFingerprint();
    emit FingerprintChanged();
    return true;
}

FingerprintConfig BrowserProfile::GenerateRandomFingerprint() {
    FingerprintConfig Config;

    QStringList UserAgents = {
        QStringLiteral("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        QStringLiteral("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"),
        QStringLiteral("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        QStringLiteral("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"),
        QStringLiteral("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"),
        QStringLiteral("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        QStringLiteral("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"),
    };

    QStringList Platforms = {
        QStringLiteral("Win32"),
        QStringLiteral("MacIntel"),
        QStringLiteral("Linux x86_64"),
    };

    QStringList Languages = {
        QStringLiteral("en-US,en;q=0.9"),
        QStringLiteral("en-GB,en;q=0.9"),
        QStringLiteral("de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"),
        QStringLiteral("fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"),
        QStringLiteral("ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7"),
    };

    QStringList Timezones = {
        QStringLiteral("America/New_York"),
        QStringLiteral("America/Chicago"),
        QStringLiteral("America/Los_Angeles"),
        QStringLiteral("Europe/London"),
        QStringLiteral("Europe/Berlin"),
        QStringLiteral("Asia/Tokyo"),
        QStringLiteral("Australia/Sydney"),
    };

    QStringList GpuRenderers = {
        QStringLiteral("ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        QStringLiteral("ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        QStringLiteral("ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        QStringLiteral("ANGLE (AMD, AMD Radeon RX 6800 XT Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        QStringLiteral("ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        QStringLiteral("ANGLE (Apple, Apple M1 Pro, OpenGL 4.1)"),
    };

    struct ScreenRes {
        int Width;
        int Height;
    };
    QList<ScreenRes> Resolutions = {
        {1920, 1080}, {2560, 1440}, {3840, 2160}, {1366, 768}, {1536, 864}, {1440, 900},
    };

    auto* Rng = QRandomGenerator::global();

    Config.UserAgent = UserAgents[Rng->bounded(UserAgents.size())];
    Config.Platform = Platforms[Rng->bounded(Platforms.size())];
    Config.AcceptLanguage = Languages[Rng->bounded(Languages.size())];
    Config.Timezone = Timezones[Rng->bounded(Timezones.size())];
    Config.WebGlRenderer = GpuRenderers[Rng->bounded(GpuRenderers.size())];

    if (Config.WebGlRenderer.contains(QStringLiteral("NVIDIA"))) {
        Config.WebGlVendor = QStringLiteral("Google Inc. (NVIDIA)");
        Config.Vendor = QStringLiteral("Google Inc.");
    } else if (Config.WebGlRenderer.contains(QStringLiteral("AMD"))) {
        Config.WebGlVendor = QStringLiteral("Google Inc. (AMD)");
        Config.Vendor = QStringLiteral("Google Inc.");
    } else if (Config.WebGlRenderer.contains(QStringLiteral("Intel"))) {
        Config.WebGlVendor = QStringLiteral("Google Inc. (Intel)");
        Config.Vendor = QStringLiteral("Google Inc.");
    } else if (Config.WebGlRenderer.contains(QStringLiteral("Apple"))) {
        Config.WebGlVendor = QStringLiteral("Apple Inc.");
        Config.Vendor = QStringLiteral("Apple Computer, Inc.");
    }

    ScreenRes Res = Resolutions[Rng->bounded(static_cast<int>(Resolutions.size()))];
    Config.ScreenWidth = Res.Width;
    Config.ScreenHeight = Res.Height;
    Config.ColorDepth = 24;

    QList<int> CoreCounts = {4, 6, 8, 12, 16};
    Config.HardwareConcurrency = CoreCounts[Rng->bounded(CoreCounts.size())];

    QList<double> MemoryValues = {4.0, 8.0, 16.0, 32.0};
    Config.DeviceMemory = MemoryValues[Rng->bounded(MemoryValues.size())];

    Config.CanvasNoise = true;
    Config.WebGlNoise = true;

    return Config;
}

QWebEngineScript BrowserProfile::BuildFingerprintScript() const {
    QString Source = GenerateSpoofScript();
    QWebEngineScript Script;
    Script.setName(QStringLiteral("FidraFingerprint"));
    Script.setSourceCode(Source);
    Script.setInjectionPoint(QWebEngineScript::DocumentCreation);
    Script.setWorldId(QWebEngineScript::MainWorld);
    Script.setRunsOnSubFrames(true);
    return Script;
}

void BrowserProfile::ApplyFingerprint() {
    EngineProfile->setHttpUserAgent(Fingerprint.UserAgent);
    EngineProfile->setHttpAcceptLanguage(Fingerprint.AcceptLanguage);

    QWebEngineScriptCollection* Scripts = EngineProfile->scripts();

    auto ExistingList = Scripts->find(QStringLiteral("FidraFingerprint"));
    for (const auto& Existing : ExistingList) {
        Scripts->remove(Existing);
    }

    Scripts->insert(BuildFingerprintScript());
}

QString BrowserProfile::GenerateSpoofScript() const {
    QString Script;

    Script += QStringLiteral("(function() {\n");
    Script += QStringLiteral("'use strict';\n\n");

    Script += QStringLiteral("Object.defineProperty(navigator, 'platform', {\n");
    Script += QStringLiteral("    get: function() { return '%1'; }\n").arg(Fingerprint.Platform);
    Script += QStringLiteral("});\n\n");

    Script += QStringLiteral("Object.defineProperty(navigator, 'vendor', {\n");
    Script += QStringLiteral("    get: function() { return '%1'; }\n").arg(Fingerprint.Vendor);
    Script += QStringLiteral("});\n\n");

    Script += QStringLiteral("Object.defineProperty(navigator, 'hardwareConcurrency', {\n");
    Script += QStringLiteral("    get: function() { return %1; }\n").arg(Fingerprint.HardwareConcurrency);
    Script += QStringLiteral("});\n\n");

    Script += QStringLiteral("Object.defineProperty(navigator, 'deviceMemory', {\n");
    Script += QStringLiteral("    get: function() { return %1; }\n").arg(Fingerprint.DeviceMemory);
    Script += QStringLiteral("});\n\n");

    Script += QStringLiteral("Object.defineProperty(navigator, 'languages', {\n");
    Script += QStringLiteral("    get: function() { return ['%1']; }\n").arg(Fingerprint.AcceptLanguage.split(QStringLiteral(",")).first().trimmed());
    Script += QStringLiteral("});\n\n");

    Script += QStringLiteral("Object.defineProperty(screen, 'width', {\n");
    Script += QStringLiteral("    get: function() { return %1; }\n").arg(Fingerprint.ScreenWidth);
    Script += QStringLiteral("});\n\n");

    Script += QStringLiteral("Object.defineProperty(screen, 'height', {\n");
    Script += QStringLiteral("    get: function() { return %1; }\n").arg(Fingerprint.ScreenHeight);
    Script += QStringLiteral("});\n\n");

    Script += QStringLiteral("Object.defineProperty(screen, 'availWidth', {\n");
    Script += QStringLiteral("    get: function() { return %1; }\n").arg(Fingerprint.ScreenWidth);
    Script += QStringLiteral("});\n\n");

    Script += QStringLiteral("Object.defineProperty(screen, 'availHeight', {\n");
    Script += QStringLiteral("    get: function() { return %1; }\n").arg(Fingerprint.ScreenHeight - 40);
    Script += QStringLiteral("});\n\n");

    Script += QStringLiteral("Object.defineProperty(screen, 'colorDepth', {\n");
    Script += QStringLiteral("    get: function() { return %1; }\n").arg(Fingerprint.ColorDepth);
    Script += QStringLiteral("});\n\n");

    Script += QStringLiteral("Object.defineProperty(screen, 'pixelDepth', {\n");
    Script += QStringLiteral("    get: function() { return %1; }\n").arg(Fingerprint.ColorDepth);
    Script += QStringLiteral("});\n\n");

    Script += QStringLiteral("var OriginalDateResolvedOptions = Intl.DateTimeFormat.prototype.resolvedOptions;\n");
    Script += QStringLiteral("Intl.DateTimeFormat.prototype.resolvedOptions = function() {\n");
    Script += QStringLiteral("    var Result = OriginalDateResolvedOptions.call(this);\n");
    Script += QStringLiteral("    Result.timeZone = '%1';\n").arg(Fingerprint.Timezone);
    Script += QStringLiteral("    return Result;\n");
    Script += QStringLiteral("};\n\n");

    Script += QStringLiteral("var OriginalGetTimezoneOffset = Date.prototype.getTimezoneOffset;\n");
    Script += QStringLiteral("Date.prototype.getTimezoneOffset = function() {\n");

    int TzOffset = 300;
    if (Fingerprint.Timezone == QStringLiteral("America/New_York")) TzOffset = 300;
    else if (Fingerprint.Timezone == QStringLiteral("America/Chicago")) TzOffset = 360;
    else if (Fingerprint.Timezone == QStringLiteral("America/Los_Angeles")) TzOffset = 480;
    else if (Fingerprint.Timezone == QStringLiteral("Europe/London")) TzOffset = 0;
    else if (Fingerprint.Timezone == QStringLiteral("Europe/Berlin")) TzOffset = -60;
    else if (Fingerprint.Timezone == QStringLiteral("Asia/Tokyo")) TzOffset = -540;
    else if (Fingerprint.Timezone == QStringLiteral("Australia/Sydney")) TzOffset = -660;

    Script += QStringLiteral("    return %1;\n").arg(TzOffset);
    Script += QStringLiteral("};\n\n");

    if (Fingerprint.CanvasNoise) {
        Script += QStringLiteral("var OriginalToDataURL = HTMLCanvasElement.prototype.toDataURL;\n");
        Script += QStringLiteral("HTMLCanvasElement.prototype.toDataURL = function(Type) {\n");
        Script += QStringLiteral("    var Ctx = this.getContext('2d');\n");
        Script += QStringLiteral("    if (Ctx) {\n");
        Script += QStringLiteral("        var ImageData = Ctx.getImageData(0, 0, this.width, this.height);\n");
        Script += QStringLiteral("        var Pixels = ImageData.data;\n");
        Script += QStringLiteral("        for (var I = 0; I < Pixels.length; I += 4) {\n");
        Script += QStringLiteral("            Pixels[I] = Pixels[I] ^ (I % 3 === 0 ? 1 : 0);\n");
        Script += QStringLiteral("        }\n");
        Script += QStringLiteral("        Ctx.putImageData(ImageData, 0, 0);\n");
        Script += QStringLiteral("    }\n");
        Script += QStringLiteral("    return OriginalToDataURL.apply(this, arguments);\n");
        Script += QStringLiteral("};\n\n");

        Script += QStringLiteral("var OriginalToBlob = HTMLCanvasElement.prototype.toBlob;\n");
        Script += QStringLiteral("HTMLCanvasElement.prototype.toBlob = function(Callback, Type, Quality) {\n");
        Script += QStringLiteral("    var Ctx = this.getContext('2d');\n");
        Script += QStringLiteral("    if (Ctx) {\n");
        Script += QStringLiteral("        var ImageData = Ctx.getImageData(0, 0, this.width, this.height);\n");
        Script += QStringLiteral("        var Pixels = ImageData.data;\n");
        Script += QStringLiteral("        for (var I = 0; I < Pixels.length; I += 4) {\n");
        Script += QStringLiteral("            Pixels[I] = Pixels[I] ^ (I % 3 === 0 ? 1 : 0);\n");
        Script += QStringLiteral("        }\n");
        Script += QStringLiteral("        Ctx.putImageData(ImageData, 0, 0);\n");
        Script += QStringLiteral("    }\n");
        Script += QStringLiteral("    return OriginalToBlob.apply(this, arguments);\n");
        Script += QStringLiteral("};\n\n");
    }

    if (Fingerprint.WebGlNoise) {
        Script += QStringLiteral("var OriginalGetParameter = WebGLRenderingContext.prototype.getParameter;\n");
        Script += QStringLiteral("WebGLRenderingContext.prototype.getParameter = function(Param) {\n");
        Script += QStringLiteral("    var DebugInfo = this.getExtension('WEBGL_debug_renderer_info');\n");
        Script += QStringLiteral("    if (DebugInfo) {\n");
        Script += QStringLiteral("        if (Param === DebugInfo.UNMASKED_VENDOR_WEBGL) {\n");
        Script += QStringLiteral("            return '%1';\n").arg(Fingerprint.WebGlVendor);
        Script += QStringLiteral("        }\n");
        Script += QStringLiteral("        if (Param === DebugInfo.UNMASKED_RENDERER_WEBGL) {\n");
        Script += QStringLiteral("            return '%1';\n").arg(Fingerprint.WebGlRenderer);
        Script += QStringLiteral("        }\n");
        Script += QStringLiteral("    }\n");
        Script += QStringLiteral("    return OriginalGetParameter.call(this, Param);\n");
        Script += QStringLiteral("};\n\n");

        Script += QStringLiteral("var OriginalGetParameter2 = WebGL2RenderingContext.prototype.getParameter;\n");
        Script += QStringLiteral("WebGL2RenderingContext.prototype.getParameter = function(Param) {\n");
        Script += QStringLiteral("    var DebugInfo = this.getExtension('WEBGL_debug_renderer_info');\n");
        Script += QStringLiteral("    if (DebugInfo) {\n");
        Script += QStringLiteral("        if (Param === DebugInfo.UNMASKED_VENDOR_WEBGL) {\n");
        Script += QStringLiteral("            return '%1';\n").arg(Fingerprint.WebGlVendor);
        Script += QStringLiteral("        }\n");
        Script += QStringLiteral("        if (Param === DebugInfo.UNMASKED_RENDERER_WEBGL) {\n");
        Script += QStringLiteral("            return '%1';\n").arg(Fingerprint.WebGlRenderer);
        Script += QStringLiteral("        }\n");
        Script += QStringLiteral("    }\n");
        Script += QStringLiteral("    return OriginalGetParameter2.call(this, Param);\n");
        Script += QStringLiteral("};\n\n");
    }

    Script += QStringLiteral("})();\n");

    return Script;
}

}
