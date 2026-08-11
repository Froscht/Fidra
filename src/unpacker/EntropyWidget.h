#pragma once

#include <QWidget>
#include <QList>
#include <QPair>
#include <QString>

namespace Fidra {

class ICore;
struct PeSectionInfo;

class EntropyWidget : public QWidget {
    Q_OBJECT

public:
    explicit EntropyWidget(QWidget* Parent = nullptr);
    ~EntropyWidget() override;

    void SetCore(ICore* Core);
    void SetEntropyData(const QList<QPair<uint64_t, double>>& Data);
    void SetSections(const QList<PeSectionInfo>& Sections);
    void Clear();

protected:
    void paintEvent(QPaintEvent* Event) override;
    void mouseMoveEvent(QMouseEvent* Event) override;
    void resizeEvent(QResizeEvent* Event) override;

private:
    QColor EntropyToColor(double Entropy) const;

    ICore* CoreRef;
    QList<QPair<uint64_t, double>> EntropyData;
    QList<QPair<uint64_t, QString>> SectionBoundaries;
    uint64_t MaxOffset;
    int HoveredIndex;

    static constexpr int MarginLeft = 50;
    static constexpr int MarginRight = 20;
    static constexpr int MarginTop = 20;
    static constexpr int MarginBottom = 40;
};

}
