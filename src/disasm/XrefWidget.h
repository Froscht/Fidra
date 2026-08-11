#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QTreeWidget>
#include <QTabWidget>
#include <QLineEdit>

namespace Fidra {

class AnalysisDatabase;

class XrefWidget : public QWidget {
    Q_OBJECT

public:
    explicit XrefWidget(QWidget* Parent = nullptr);
    ~XrefWidget() override;

    void ShowXrefs(AnalysisDatabase* Db, Address Addr);

signals:
    void NavigateToAddress(Address Addr);

private slots:
    void OnItemDoubleClicked(QTreeWidgetItem* Item, int Column);
    void OnFilterChanged(const QString& Text);

private:
    void PopulateXrefsTo(AnalysisDatabase* Db, Address Addr);
    void PopulateXrefsFrom(AnalysisDatabase* Db, Address Addr);
    QString FormatAddress(Address Addr) const;

    QLineEdit* FilterInput;
    QTabWidget* TabWidget;
    QTreeWidget* XrefsToTree;
    QTreeWidget* XrefsFromTree;
};

}
