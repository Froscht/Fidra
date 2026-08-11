#pragma once

#include <QWebEngineUrlRequestInterceptor>
#include <QString>
#include <QList>
#include <QMap>
#include <QRegularExpression>
#include <QMutex>

namespace Fidra {

struct BlockRule {
    QString Pattern;
    QRegularExpression Regex;
    bool Enabled;
    int HitCount;
};

struct HeaderOverride {
    QString HeaderName;
    QString HeaderValue;
    bool Enabled;
};

class RequestInterceptor : public QWebEngineUrlRequestInterceptor {
    Q_OBJECT

public:
    explicit RequestInterceptor(QObject* Parent = nullptr);
    ~RequestInterceptor() override;

    void interceptRequest(QWebEngineUrlRequestInfo& Info) override;

    void AddBlockRule(const QString& Pattern);
    void RemoveBlockRule(const QString& Pattern);
    void SetBlockRuleEnabled(const QString& Pattern, bool Enabled);
    void ClearBlockRules();
    QList<BlockRule> GetBlockRules() const;

    void AddHeaderOverride(const QString& Name, const QString& Value);
    void RemoveHeaderOverride(const QString& Name);
    void ClearHeaderOverrides();
    QList<HeaderOverride> GetHeaderOverrides() const;

    void SetLoggingEnabled(bool Enabled);
    bool IsLoggingEnabled() const;

    void SetBlockingEnabled(bool Enabled);
    bool IsBlockingEnabled() const;

    int TotalRequestCount() const;
    int BlockedRequestCount() const;

signals:
    void RequestLogged(const QString& Method, const QUrl& Url, const QString& ResourceType);
    void RequestBlocked(const QUrl& Url, const QString& Rule);

private:
    QString ResourceTypeToString(QWebEngineUrlRequestInfo::ResourceType Type) const;

    QList<BlockRule> BlockRules;
    QList<HeaderOverride> HeaderOverrides;
    bool LoggingEnabled;
    bool BlockingEnabled;
    int TotalRequests;
    int BlockedRequests;
    mutable QMutex Mutex;
};

}
