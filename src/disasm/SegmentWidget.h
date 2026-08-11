#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QTreeWidget>
#include <QLineEdit>

namespace Fidra {

class AnalysisDatabase;

class SegmentWidget : public QWidget {
    Q_OBJECT

public:
    explicit SegmentWidget(QWidget* Parent = nullptr);
    ~SegmentWidget() override;

    void LoadFromDatabase(AnalysisDatabase* Db);

signals:
    void NavigateToAddress(Address Addr);
    void GoToHexView(Address Addr);

private slots:
    void OnItemDoubleClicked(QTreeWidgetItem* Item, int Column);
    void OnFilterChanged(const QString& Text);
    void OnContextMenu(const QPoint& Pos);

private:
    QString SegmentTypeToString(int Type) const;
    QColor SegmentTypeColor(int Type) const;
    QColor EntropyColor(double Entropy) const;
    double CalculateEntropy(const QByteArray& Data) const;

    QTreeWidget* TreeWidget;
    QLineEdit* FilterInput;
};

}
