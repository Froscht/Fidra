#include "XrefWidget.h"
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <QVBoxLayout>
#include <QHeaderView>

namespace Fidra {

static QString XrefTypeToString(XrefType Type) {
    switch (Type) {
        case XrefType::CodeCall:    return "call";
        case XrefType::CodeJump:    return "jmp";
        case XrefType::CodeCondJump: return "cond_jmp";
        case XrefType::DataRead:    return "read";
        case XrefType::DataWrite:   return "write";
        case XrefType::DataOffset:  return "offset";
    }
    return "unknown";
}

static QColor XrefTypeColor(XrefType Type) {
    switch (Type) {
        case XrefType::CodeCall:    return QColor(0x40, 0x40, 0xFF);
        case XrefType::CodeJump:    return QColor(0x00, 0xA0, 0x00);
        case XrefType::CodeCondJump: return QColor(0x00, 0xA0, 0x00);
        case XrefType::DataRead:    return QColor(0x80, 0x80, 0x80);
        case XrefType::DataWrite:   return QColor(0x80, 0x80, 0x80);
        case XrefType::DataOffset:  return QColor(0x80, 0x80, 0x80);
    }
    return QColor(0x80, 0x80, 0x80);
}

static QTreeWidget* CreateXrefTree(QWidget* Parent) {
    auto* Tree = new QTreeWidget(Parent);
    Tree->setHeaderLabels({"Address", "Type", "Context"});
    Tree->setAlternatingRowColors(true);
    Tree->setSelectionMode(QAbstractItemView::SingleSelection);
    Tree->setRootIsDecorated(false);
    Tree->setSortingEnabled(true);
    Tree->header()->setStretchLastSection(true);
    Tree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    Tree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    Tree->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    return Tree;
}

XrefWidget::XrefWidget(QWidget* Parent)
    : QWidget(Parent)
{
    auto* Layout = new QVBoxLayout(this);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(2);

    FilterInput = new QLineEdit(this);
    FilterInput->setPlaceholderText("Filter xrefs...");
    Layout->addWidget(FilterInput);

    TabWidget = new QTabWidget(this);

    XrefsToTree = CreateXrefTree(this);
    TabWidget->addTab(XrefsToTree, "Xrefs To");

    XrefsFromTree = CreateXrefTree(this);
    TabWidget->addTab(XrefsFromTree, "Xrefs From");

    Layout->addWidget(TabWidget);

    connect(FilterInput, &QLineEdit::textChanged, this, &XrefWidget::OnFilterChanged);
    connect(XrefsToTree, &QTreeWidget::itemDoubleClicked, this, &XrefWidget::OnItemDoubleClicked);
    connect(XrefsFromTree, &QTreeWidget::itemDoubleClicked, this, &XrefWidget::OnItemDoubleClicked);
}

XrefWidget::~XrefWidget() = default;

void XrefWidget::ShowXrefs(AnalysisDatabase* Db, Address Addr) {
    if (!Db)
        return;

    XrefsToTree->clear();
    XrefsFromTree->clear();
    FilterInput->clear();

    PopulateXrefsTo(Db, Addr);
    PopulateXrefsFrom(Db, Addr);
}

void XrefWidget::PopulateXrefsTo(AnalysisDatabase* Db, Address Addr) {
    QList<Xref> Refs = Db->GetXrefsTo(Addr);

    for (const auto& Ref : Refs) {
        auto* Item = new QTreeWidgetItem();
        Item->setText(0, FormatAddress(Ref.From));
        Item->setText(1, XrefTypeToString(Ref.Type));

        QString Context;
        if (Db->HasInstruction(Ref.From)) {
            AnalyzedInstruction Inst = Db->GetInstruction(Ref.From);
            Context = Inst.Mnemonic + " " + Inst.Operands;
        }
        Item->setText(2, Context);

        QColor Color = XrefTypeColor(Ref.Type);
        Item->setForeground(0, Color);
        Item->setForeground(1, Color);
        Item->setForeground(2, Color);

        Item->setData(0, Qt::UserRole, QVariant::fromValue(Ref.From));
        XrefsToTree->addTopLevelItem(Item);
    }

    TabWidget->setTabText(0, QString("Xrefs To (%1)").arg(Refs.size()));
}

void XrefWidget::PopulateXrefsFrom(AnalysisDatabase* Db, Address Addr) {
    QList<Xref> Refs = Db->GetXrefsFrom(Addr);

    for (const auto& Ref : Refs) {
        auto* Item = new QTreeWidgetItem();
        Item->setText(0, FormatAddress(Ref.To));
        Item->setText(1, XrefTypeToString(Ref.Type));

        QString Context;
        if (Db->HasInstruction(Ref.To)) {
            AnalyzedInstruction Inst = Db->GetInstruction(Ref.To);
            Context = Inst.Mnemonic + " " + Inst.Operands;
        }
        Item->setText(2, Context);

        QColor Color = XrefTypeColor(Ref.Type);
        Item->setForeground(0, Color);
        Item->setForeground(1, Color);
        Item->setForeground(2, Color);

        Item->setData(0, Qt::UserRole, QVariant::fromValue(Ref.To));
        XrefsFromTree->addTopLevelItem(Item);
    }

    TabWidget->setTabText(1, QString("Xrefs From (%1)").arg(Refs.size()));
}

void XrefWidget::OnItemDoubleClicked(QTreeWidgetItem* Item, int Column) {
    Q_UNUSED(Column);
    if (!Item)
        return;

    Address Addr = Item->data(0, Qt::UserRole).toULongLong();
    emit NavigateToAddress(Addr);
}

void XrefWidget::OnFilterChanged(const QString& Text) {
    auto FilterTree = [&](QTreeWidget* Tree) {
        for (int I = 0; I < Tree->topLevelItemCount(); ++I) {
            QTreeWidgetItem* Item = Tree->topLevelItem(I);
            bool Matches = Text.isEmpty() ||
                Item->text(0).contains(Text, Qt::CaseInsensitive) ||
                Item->text(1).contains(Text, Qt::CaseInsensitive) ||
                Item->text(2).contains(Text, Qt::CaseInsensitive);
            Item->setHidden(!Matches);
        }
    };

    FilterTree(XrefsToTree);
    FilterTree(XrefsFromTree);
}

QString XrefWidget::FormatAddress(Address Addr) const {
    return QString("0x") + QString("%1").arg(Addr, 16, 16, QChar('0')).toUpper();
}

}
