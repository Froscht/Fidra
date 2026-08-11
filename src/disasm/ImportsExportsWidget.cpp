#include "ImportsExportsWidget.h"
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QMap>

namespace Fidra {

ImportsExportsWidget::ImportsExportsWidget(QWidget* Parent)
    : QWidget(Parent)
    , TotalImportCount(0)
    , TotalExportCount(0)
{
    auto* Layout = new QVBoxLayout(this);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(2);

    FilterInput = new QLineEdit(this);
    FilterInput->setPlaceholderText("Filter imports/exports...");
    Layout->addWidget(FilterInput);

    TabWidget = new QTabWidget(this);

    ImportsTree = new QTreeWidget();
    ImportsTree->setHeaderLabels({"Ordinal", "Name", "IAT Address"});
    ImportsTree->setAlternatingRowColors(true);
    ImportsTree->setSelectionMode(QAbstractItemView::SingleSelection);
    ImportsTree->setRootIsDecorated(true);
    ImportsTree->setSortingEnabled(true);
    ImportsTree->header()->setStretchLastSection(true);
    ImportsTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ImportsTree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    ImportsTree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);

    ExportsTree = new QTreeWidget();
    ExportsTree->setHeaderLabels({"Ordinal", "Name", "RVA", "Address", "Forwarder"});
    ExportsTree->setAlternatingRowColors(true);
    ExportsTree->setSelectionMode(QAbstractItemView::SingleSelection);
    ExportsTree->setRootIsDecorated(false);
    ExportsTree->setSortingEnabled(true);
    ExportsTree->header()->setStretchLastSection(true);
    ExportsTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ExportsTree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    ExportsTree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ExportsTree->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    ExportsTree->header()->setSectionResizeMode(4, QHeaderView::ResizeToContents);

    TabWidget->addTab(ImportsTree, "Imports");
    TabWidget->addTab(ExportsTree, "Exports");
    Layout->addWidget(TabWidget);

    connect(FilterInput, &QLineEdit::textChanged, this, &ImportsExportsWidget::OnFilterChanged);
    connect(ImportsTree, &QTreeWidget::itemDoubleClicked, this, &ImportsExportsWidget::OnImportDoubleClicked);
    connect(ExportsTree, &QTreeWidget::itemDoubleClicked, this, &ImportsExportsWidget::OnExportDoubleClicked);
}

ImportsExportsWidget::~ImportsExportsWidget() = default;

void ImportsExportsWidget::LoadFromDatabase(AnalysisDatabase* Db) {
    if (!Db)
        return;

    ImportsTree->clear();
    ExportsTree->clear();
    TotalImportCount = 0;
    TotalExportCount = 0;

    PopulateImports(Db);
    PopulateExports(Db);

    TabWidget->setTabText(0, QString("Imports (%1)").arg(TotalImportCount));
    TabWidget->setTabText(1, QString("Exports (%1)").arg(TotalExportCount));
}

void ImportsExportsWidget::PopulateImports(AnalysisDatabase* Db) {
    BinaryInfo Info = Db->GetBinaryInfo();
    const QList<ImportEntry>& Imports = Info.Imports;
    TotalImportCount = Imports.size();

    QMap<QString, QList<ImportEntry>> GroupedImports;
    for (const auto& Entry : Imports) {
        GroupedImports[Entry.DllName].append(Entry);
    }

    ImportsTree->setSortingEnabled(false);

    for (auto It = GroupedImports.constBegin(); It != GroupedImports.constEnd(); ++It) {
        const QString& DllName = It.key();
        const QList<ImportEntry>& Entries = It.value();

        auto* DllItem = new QTreeWidgetItem();
        DllItem->setText(0, "");
        DllItem->setText(1, QString("%1 (%2)").arg(DllName).arg(Entries.size()));
        DllItem->setText(2, "");
        DllItem->setData(0, Qt::UserRole, QVariant::fromValue(static_cast<Address>(0)));

        QFont BoldFont = DllItem->font(1);
        BoldFont.setBold(true);
        DllItem->setFont(1, BoldFont);

        for (const auto& Entry : Entries) {
            auto* Child = new QTreeWidgetItem();
            Child->setText(0, QString::number(Entry.Ordinal));
            Child->setText(1, Entry.FuncName);
            Child->setText(2, QString("0x%1").arg(Entry.IatAddress, 16, 16, QChar('0')));
            Child->setData(0, Qt::UserRole, QVariant::fromValue(Entry.IatAddress));
            DllItem->addChild(Child);
        }

        ImportsTree->addTopLevelItem(DllItem);
    }

    ImportsTree->expandAll();
    ImportsTree->setSortingEnabled(true);
}

void ImportsExportsWidget::PopulateExports(AnalysisDatabase* Db) {
    BinaryInfo Info = Db->GetBinaryInfo();
    const QList<ExportEntry>& Exports = Info.Exports;
    TotalExportCount = Exports.size();

    ExportsTree->setSortingEnabled(false);

    for (const auto& Entry : Exports) {
        auto* Item = new QTreeWidgetItem();
        Item->setText(0, QString::number(Entry.Ordinal));
        Item->setText(1, Entry.Name);
        Item->setText(2, QString("0x%1").arg(Entry.Rva, 8, 16, QChar('0')));
        Item->setText(3, QString("0x%1").arg(Entry.Addr, 16, 16, QChar('0')));
        Item->setText(4, Entry.IsForwarder ? Entry.ForwarderName : "-");
        Item->setData(0, Qt::UserRole, QVariant::fromValue(Entry.Addr));
        ExportsTree->addTopLevelItem(Item);
    }

    ExportsTree->setSortingEnabled(true);
}

void ImportsExportsWidget::OnImportDoubleClicked(QTreeWidgetItem* Item, int Column) {
    Q_UNUSED(Column);
    if (!Item)
        return;

    Address Addr = Item->data(0, Qt::UserRole).toULongLong();
    if (Addr != 0)
        emit NavigateToAddress(Addr);
}

void ImportsExportsWidget::OnExportDoubleClicked(QTreeWidgetItem* Item, int Column) {
    Q_UNUSED(Column);
    if (!Item)
        return;

    Address Addr = Item->data(0, Qt::UserRole).toULongLong();
    if (Addr != 0)
        emit NavigateToAddress(Addr);
}

void ImportsExportsWidget::OnFilterChanged(const QString& Text) {
    FilterImports(Text);
    FilterExports(Text);
}

void ImportsExportsWidget::FilterImports(const QString& Text) {
    for (int I = 0; I < ImportsTree->topLevelItemCount(); ++I) {
        QTreeWidgetItem* DllItem = ImportsTree->topLevelItem(I);
        bool AnyChildVisible = false;

        for (int J = 0; J < DllItem->childCount(); ++J) {
            QTreeWidgetItem* Child = DllItem->child(J);
            bool Matches = Text.isEmpty() ||
                Child->text(0).contains(Text, Qt::CaseInsensitive) ||
                Child->text(1).contains(Text, Qt::CaseInsensitive) ||
                Child->text(2).contains(Text, Qt::CaseInsensitive);
            Child->setHidden(!Matches);
            if (Matches)
                AnyChildVisible = true;
        }

        bool DllMatches = Text.isEmpty() ||
            DllItem->text(1).contains(Text, Qt::CaseInsensitive);
        DllItem->setHidden(!DllMatches && !AnyChildVisible);

        if (AnyChildVisible && !Text.isEmpty())
            DllItem->setExpanded(true);
    }
}

void ImportsExportsWidget::FilterExports(const QString& Text) {
    for (int I = 0; I < ExportsTree->topLevelItemCount(); ++I) {
        QTreeWidgetItem* Item = ExportsTree->topLevelItem(I);
        bool Matches = Text.isEmpty() ||
            Item->text(0).contains(Text, Qt::CaseInsensitive) ||
            Item->text(1).contains(Text, Qt::CaseInsensitive) ||
            Item->text(3).contains(Text, Qt::CaseInsensitive) ||
            Item->text(4).contains(Text, Qt::CaseInsensitive);
        Item->setHidden(!Matches);
    }
}

}
