#include "RequestInterceptor.h"

#include <QMutexLocker>
#include <QUrl>

namespace Fidra {

RequestInterceptor::RequestInterceptor(QObject* Parent)
    : QWebEngineUrlRequestInterceptor(Parent)
    , LoggingEnabled(true)
    , BlockingEnabled(true)
    , TotalRequests(0)
    , BlockedRequests(0) {
}

RequestInterceptor::~RequestInterceptor() {
}

void RequestInterceptor::interceptRequest(QWebEngineUrlRequestInfo& Info) {
    QMutexLocker Lock(&Mutex);

    TotalRequests++;

    QString Method;
    switch (Info.requestMethod().at(0)) {
    case 'G': Method = QStringLiteral("GET"); break;
    case 'P':
        if (Info.requestMethod() == "POST")
            Method = QStringLiteral("POST");
        else if (Info.requestMethod() == "PUT")
            Method = QStringLiteral("PUT");
        else if (Info.requestMethod() == "PATCH")
            Method = QStringLiteral("PATCH");
        else
            Method = QString::fromUtf8(Info.requestMethod());
        break;
    case 'D': Method = QStringLiteral("DELETE"); break;
    case 'H': Method = QStringLiteral("HEAD"); break;
    case 'O': Method = QStringLiteral("OPTIONS"); break;
    default: Method = QString::fromUtf8(Info.requestMethod()); break;
    }

    QUrl RequestUrl = Info.requestUrl();
    QString UrlString = RequestUrl.toString();

    if (LoggingEnabled) {
        QString ResType = ResourceTypeToString(Info.resourceType());
        emit RequestLogged(Method, RequestUrl, ResType);
    }

    if (BlockingEnabled) {
        for (auto& Rule : BlockRules) {
            if (!Rule.Enabled) {
                continue;
            }
            if (Rule.Regex.match(UrlString).hasMatch()) {
                Rule.HitCount++;
                BlockedRequests++;
                Info.block(true);
                emit RequestBlocked(RequestUrl, Rule.Pattern);
                return;
            }
        }
    }

    for (const auto& Override : HeaderOverrides) {
        if (!Override.Enabled) {
            continue;
        }
        Info.setHttpHeader(Override.HeaderName.toUtf8(), Override.HeaderValue.toUtf8());
    }
}

void RequestInterceptor::AddBlockRule(const QString& Pattern) {
    QMutexLocker Lock(&Mutex);

    for (const auto& Rule : BlockRules) {
        if (Rule.Pattern == Pattern) {
            return;
        }
    }

    BlockRule Rule;
    Rule.Pattern = Pattern;
    Rule.Regex = QRegularExpression(QRegularExpression::wildcardToRegularExpression(Pattern));
    Rule.Enabled = true;
    Rule.HitCount = 0;
    BlockRules.append(Rule);
}

void RequestInterceptor::RemoveBlockRule(const QString& Pattern) {
    QMutexLocker Lock(&Mutex);

    for (int I = 0; I < BlockRules.size(); I++) {
        if (BlockRules[I].Pattern == Pattern) {
            BlockRules.removeAt(I);
            return;
        }
    }
}

void RequestInterceptor::SetBlockRuleEnabled(const QString& Pattern, bool Enabled) {
    QMutexLocker Lock(&Mutex);

    for (auto& Rule : BlockRules) {
        if (Rule.Pattern == Pattern) {
            Rule.Enabled = Enabled;
            return;
        }
    }
}

void RequestInterceptor::ClearBlockRules() {
    QMutexLocker Lock(&Mutex);
    BlockRules.clear();
}

QList<BlockRule> RequestInterceptor::GetBlockRules() const {
    QMutexLocker Lock(&Mutex);
    return BlockRules;
}

void RequestInterceptor::AddHeaderOverride(const QString& Name, const QString& Value) {
    QMutexLocker Lock(&Mutex);

    for (auto& Override : HeaderOverrides) {
        if (Override.HeaderName == Name) {
            Override.HeaderValue = Value;
            Override.Enabled = true;
            return;
        }
    }

    HeaderOverride Override;
    Override.HeaderName = Name;
    Override.HeaderValue = Value;
    Override.Enabled = true;
    HeaderOverrides.append(Override);
}

void RequestInterceptor::RemoveHeaderOverride(const QString& Name) {
    QMutexLocker Lock(&Mutex);

    for (int I = 0; I < HeaderOverrides.size(); I++) {
        if (HeaderOverrides[I].HeaderName == Name) {
            HeaderOverrides.removeAt(I);
            return;
        }
    }
}

void RequestInterceptor::ClearHeaderOverrides() {
    QMutexLocker Lock(&Mutex);
    HeaderOverrides.clear();
}

QList<HeaderOverride> RequestInterceptor::GetHeaderOverrides() const {
    QMutexLocker Lock(&Mutex);
    return HeaderOverrides;
}

void RequestInterceptor::SetLoggingEnabled(bool Enabled) {
    QMutexLocker Lock(&Mutex);
    LoggingEnabled = Enabled;
}

bool RequestInterceptor::IsLoggingEnabled() const {
    QMutexLocker Lock(&Mutex);
    return LoggingEnabled;
}

void RequestInterceptor::SetBlockingEnabled(bool Enabled) {
    QMutexLocker Lock(&Mutex);
    BlockingEnabled = Enabled;
}

bool RequestInterceptor::IsBlockingEnabled() const {
    QMutexLocker Lock(&Mutex);
    return BlockingEnabled;
}

int RequestInterceptor::TotalRequestCount() const {
    QMutexLocker Lock(&Mutex);
    return TotalRequests;
}

int RequestInterceptor::BlockedRequestCount() const {
    QMutexLocker Lock(&Mutex);
    return BlockedRequests;
}

QString RequestInterceptor::ResourceTypeToString(QWebEngineUrlRequestInfo::ResourceType Type) const {
    switch (Type) {
    case QWebEngineUrlRequestInfo::ResourceTypeMainFrame: return QStringLiteral("MainFrame");
    case QWebEngineUrlRequestInfo::ResourceTypeSubFrame: return QStringLiteral("SubFrame");
    case QWebEngineUrlRequestInfo::ResourceTypeStylesheet: return QStringLiteral("Stylesheet");
    case QWebEngineUrlRequestInfo::ResourceTypeScript: return QStringLiteral("Script");
    case QWebEngineUrlRequestInfo::ResourceTypeImage: return QStringLiteral("Image");
    case QWebEngineUrlRequestInfo::ResourceTypeFontResource: return QStringLiteral("Font");
    case QWebEngineUrlRequestInfo::ResourceTypeSubResource: return QStringLiteral("SubResource");
    case QWebEngineUrlRequestInfo::ResourceTypeObject: return QStringLiteral("Object");
    case QWebEngineUrlRequestInfo::ResourceTypeMedia: return QStringLiteral("Media");
    case QWebEngineUrlRequestInfo::ResourceTypeWorker: return QStringLiteral("Worker");
    case QWebEngineUrlRequestInfo::ResourceTypeSharedWorker: return QStringLiteral("SharedWorker");
    case QWebEngineUrlRequestInfo::ResourceTypePrefetch: return QStringLiteral("Prefetch");
    case QWebEngineUrlRequestInfo::ResourceTypeFavicon: return QStringLiteral("Favicon");
    case QWebEngineUrlRequestInfo::ResourceTypeXhr: return QStringLiteral("XHR");
    case QWebEngineUrlRequestInfo::ResourceTypePing: return QStringLiteral("Ping");
    case QWebEngineUrlRequestInfo::ResourceTypeServiceWorker: return QStringLiteral("ServiceWorker");
    case QWebEngineUrlRequestInfo::ResourceTypeCspReport: return QStringLiteral("CSPReport");
    case QWebEngineUrlRequestInfo::ResourceTypePluginResource: return QStringLiteral("Plugin");
    case QWebEngineUrlRequestInfo::ResourceTypeNavigationPreloadMainFrame: return QStringLiteral("NavigationPreload");
    case QWebEngineUrlRequestInfo::ResourceTypeNavigationPreloadSubFrame: return QStringLiteral("NavigationPreloadSub");
    default: return QStringLiteral("Unknown");
    }
}

}
