#pragma once

#include "../analysis/AnalysisTypes.h"
#include <QWidget>
#include <QLabel>
#include <QProgressBar>
#include <QVBoxLayout>
#include <QElapsedTimer>
#include <QTimer>

namespace Fidra {

class AnalysisDatabase;

class NavigatorBand : public QWidget {
    Q_OBJECT

public:
    explicit NavigatorBand(QWidget* Parent = nullptr);
    void SetSegments(const QList<Segment>& Segments);
    void SetCurrentAddress(Address Addr);

protected:
    void paintEvent(QPaintEvent* Event) override;
    void mousePressEvent(QMouseEvent* Event) override;
    void mouseMoveEvent(QMouseEvent* Event) override;
    QSize minimumSizeHint() const override { return QSize(100, 22); }
    QSize sizeHint() const override { return QSize(400, 22); }

signals:
    void AddressClicked(Address Addr);

private:
    QColor ColorForSegment(const Segment& Seg) const;
    int AddressToX(Address Addr) const;
    Address XToAddress(int X) const;
    QString SegmentAtX(int X) const;

    QList<Segment> Segs;
    Address CurrentAddr = 0;
    Address MinAddr = 0;
    Address MaxAddr = 0;
};

class AnalysisProgressWidget : public QWidget {
    Q_OBJECT

public:
    explicit AnalysisProgressWidget(QWidget* Parent = nullptr);
    void SetDatabase(AnalysisDatabase* Db);
    void OnProgress(const AnalysisProgress& Progress);
    void OnFinished(bool Success);
    void Reset();

private:
    void SetupUi();
    QString FormatDuration(qint64 Ms) const;
    QString FormatCount(int Count) const;
    QString StateToString(AnalysisState State) const;

    NavigatorBand* NavBand;
    QProgressBar* OverallProgress;
    QLabel* PhaseLabel;
    QLabel* StatsLabel;
    QLabel* ElapsedLabel;
    QTimer* ElapsedTimer;
    qint64 LastElapsedMs = 0;
    AnalysisDatabase* Db = nullptr;
    bool Finished = false;
};

}
