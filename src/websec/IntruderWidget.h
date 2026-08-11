#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QPlainTextEdit>
#include <QTableWidget>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QThread>
#include <QProgressBar>
#include <QStringList>

namespace Fidra {

enum class AttackType {
    Sniper,
    BatteringRam
};

struct IntruderResult {
    int PayloadIndex;
    QString Payload;
    int StatusCode;
    int ResponseLength;
    qint64 ResponseTime;
    QString Error;
};

class AttackWorker : public QObject {
    Q_OBJECT

public:
    explicit AttackWorker(QObject* Parent = nullptr);

    void SetTemplate(const QString& Template);
    void SetPayloads(const QStringList& Payloads);
    void SetAttackType(AttackType Type);
    void SetTargetUrl(const QString& Url);
    void Stop();

public slots:
    void Execute();

signals:
    void ResultReady(const IntruderResult& Result);
    void ProgressUpdate(int Current, int Total);
    void AttackFinished();

private:
    QStringList FindInsertionPoints(const QString& Template);
    QString SubstitutePayload(const QString& Template, const QStringList& Points, const QString& Payload, int PositionIndex);
    IntruderResult SendRequest(const QString& RawRequest, const QString& Payload, int Index);

    QString RequestTemplate;
    QStringList PayloadList;
    AttackType Type;
    QString TargetUrl;
    bool Stopped;
};

class IntruderWidget : public QWidget {
    Q_OBJECT

public:
    explicit IntruderWidget(QWidget* Parent = nullptr);
    ~IntruderWidget() override;

    void SetRequest(const HttpRequest& Request);

private slots:
    void OnStartAttack();
    void OnStopAttack();
    void OnResultReady(const IntruderResult& Result);
    void OnProgressUpdate(int Current, int Total);
    void OnAttackFinished();
    void OnLoadPayloads();
    void OnAddMarkers();
    void OnClearMarkers();

private:
    void PopulateBuiltinPayloads();
    QString RequestToRaw(const HttpRequest& Request);

    QPlainTextEdit* TemplateEditor;
    QTableWidget* ResultsTable;
    QComboBox* AttackTypeCombo;
    QComboBox* PayloadPresetCombo;
    QPlainTextEdit* PayloadEditor;
    QPushButton* StartButton;
    QPushButton* StopButton;
    QPushButton* LoadPayloadsButton;
    QPushButton* AddMarkersButton;
    QPushButton* ClearMarkersButton;
    QProgressBar* ProgressIndicator;
    QLabel* StatusLabel;

    QThread* WorkerThread;
    AttackWorker* Worker;
    bool AttackRunning;
};

}
