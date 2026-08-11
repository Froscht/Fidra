#include "SegmentWidget.h"
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QMenu>
#include <QClipboard>
#include <QApplication>
#include <cmath>
#include <array>

namespace Fidra {

SegmentWidget::SegmentWidget(QWidget* Parent)
    : QWidget(Parent)
{
    auto* Layout = new QVBoxLayout(this);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(2);

    FilterInput = new QLineEdit(this);
    FilterInput->setPlaceholderText("Filter segments...");
    Layout->addWidget(FilterInput);

    TreeWidget = new QTreeWidget(this);
    TreeWidget->setHeaderLabels({"Name", "Virtual Address", "Virtual Size", "Raw Size", "Raw Offset", "Type", "R", "W", "X", "Entropy"});
    TreeWidget->setAlternatingRowColors(true);
    TreeWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    TreeWidget->setRootIsDecorated(false);
    TreeWidget->setSortingEnabled(true);
    TreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    TreeWidget->header()->setStretchLastSection(true);
    TreeWidget->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(7, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(8, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(9, QHeaderView::Stretch);
    Layout->addWidget(TreeWidget);

    connect(FilterInput, &QLineEdit::textChanged, this, &SegmentWidget::OnFilterChanged);
    connect(TreeWidget, &QTreeWidget::itemDoubleClicked, this, &SegmentWidget::OnItemDoubleClicked);
    connect(TreeWidget, &QTreeWidget::customContextMenuRequested, this, &SegmentWidget::OnContextMenu);
}

SegmentWidget::~SegmentWidget() = default;

void SegmentWidget::LoadFromDatabase(AnalysisDatabase* Db) {
    TreeWidget->clear();
    if (!Db) return;

    BinaryInfo Info = Db->GetBinaryInfo();

    for (const auto& Seg : Info.Segments) {
        auto* Item = new QTreeWidgetItem();

        Item->setText(0, Seg.Name);
        Item->setText(1, QString("0x") + QString("%1").arg(Seg.VirtualAddress, 16, 16, QChar('0')).toUpper());
        Item->setText(2, QString("0x%1 (%2)").arg(QString("%1").arg(Seg.VirtualSize, 0, 16).toUpper()).arg(Seg.VirtualSize));
        Item->setText(3, QString("0x%1 (%2)").arg(QString("%1").arg(Seg.RawSize, 0, 16).toUpper()).arg(Seg.RawSize));
        Item->setText(4, QString("0x") + QString("%1").arg(Seg.RawOffset, 16, 16, QChar('0')).toUpper());
        Item->setText(5, SegmentTypeToString(static_cast<int>(Seg.Type)));

        Item->setText(6, Seg.IsReadable ? QString(QChar(0x2713)) : "");
        Item->setText(7, Seg.IsWritable ? QString(QChar(0x2713)) : "");
        Item->setText(8, Seg.IsExecutable ? QString(QChar(0x2713)) : "");
        Item->setTextAlignment(6, Qt::AlignCenter);
        Item->setTextAlignment(7, Qt::AlignCenter);
        Item->setTextAlignment(8, Qt::AlignCenter);

        double Entropy = CalculateEntropy(Seg.Data);
        Item->setText(9, QString::number(Entropy, 'f', 2));
        Item->setBackground(9, EntropyColor(Entropy));

        QColor RowColor = SegmentTypeColor(static_cast<int>(Seg.Type));
        for (int Col = 0; Col < 9; ++Col) {
            Item->setBackground(Col, RowColor);
        }

        Item->setData(0, Qt::UserRole, QVariant::fromValue(Seg.VirtualAddress));

        TreeWidget->addTopLevelItem(Item);
    }
}

void SegmentWidget::OnItemDoubleClicked(QTreeWidgetItem* Item, int Column) {
    Q_UNUSED(Column);
    if (!Item) return;

    Address Addr = Item->data(0, Qt::UserRole).toULongLong();
    emit NavigateToAddress(Addr);
}

void SegmentWidget::OnFilterChanged(const QString& Text) {
    for (int I = 0; I < TreeWidget->topLevelItemCount(); ++I) {
        QTreeWidgetItem* Item = TreeWidget->topLevelItem(I);
        bool Matches = Text.isEmpty();
        if (!Matches) {
            for (int Col = 0; Col < TreeWidget->columnCount(); ++Col) {
                if (Item->text(Col).contains(Text, Qt::CaseInsensitive)) {
                    Matches = true;
                    break;
                }
            }
        }
        Item->setHidden(!Matches);
    }
}

void SegmentWidget::OnContextMenu(const QPoint& Pos) {
    QTreeWidgetItem* Item = TreeWidget->itemAt(Pos);
    if (!Item) return;

    Address Addr = Item->data(0, Qt::UserRole).toULongLong();

    QMenu Menu(this);

    QAction* CopyAction = Menu.addAction("Copy Address");
    QAction* DisasmAction = Menu.addAction("Go to in Disassembly");
    QAction* HexAction = Menu.addAction("Go to in Hex View");

    QAction* Selected = Menu.exec(TreeWidget->viewport()->mapToGlobal(Pos));

    if (Selected == CopyAction) {
        QString AddrStr = QString("0x") + QString("%1").arg(Addr, 16, 16, QChar('0')).toUpper();
        QApplication::clipboard()->setText(AddrStr);
    } else if (Selected == DisasmAction) {
        emit NavigateToAddress(Addr);
    } else if (Selected == HexAction) {
        emit GoToHexView(Addr);
    }
}

QString SegmentWidget::SegmentTypeToString(int Type) const {
    switch (static_cast<SegmentType>(Type)) {
        case SegmentType::Code:     return "Code";
        case SegmentType::Data:     return "Data";
        case SegmentType::Bss:      return "BSS";
        case SegmentType::Import:   return "Import";
        case SegmentType::Export:   return "Export";
        case SegmentType::Resource: return "Resource";
        case SegmentType::Reloc:    return "Reloc";
        case SegmentType::Unknown:  return "Unknown";
    }
    return "Unknown";
}

QColor SegmentWidget::SegmentTypeColor(int Type) const {
    switch (static_cast<SegmentType>(Type)) {
        case SegmentType::Code:     return QColor(0xE0, 0xF0, 0xFF);
        case SegmentType::Data:     return QColor(0xFF, 0xFF, 0xF0);
        case SegmentType::Bss:      return QColor(0xF0, 0xF0, 0xF0);
        case SegmentType::Import:   return QColor(0xF0, 0xF0, 0xF0);
        case SegmentType::Export:   return QColor(0xF0, 0xF0, 0xF0);
        case SegmentType::Resource: return QColor(0xF0, 0xF0, 0xF0);
        case SegmentType::Reloc:    return QColor(0xF0, 0xF0, 0xF0);
        case SegmentType::Unknown:  return QColor(0xF0, 0xF0, 0xF0);
    }
    return QColor(0xF0, 0xF0, 0xF0);
}

QColor SegmentWidget::EntropyColor(double Entropy) const {
    if (Entropy < 1.0)
        return QColor(0xFA, 0xFA, 0xFA);
    if (Entropy < 4.0)
        return QColor(0xD0, 0xF0, 0xD0);
    if (Entropy < 6.0)
        return QColor(0xFF, 0xFF, 0xC0);
    if (Entropy < 7.0)
        return QColor(0xFF, 0xD0, 0x90);
    return QColor(0xFF, 0xA0, 0xA0);
}

double SegmentWidget::CalculateEntropy(const QByteArray& Data) const {
    if (Data.isEmpty()) return 0.0;

    std::array<uint64_t, 256> Freq{};
    for (unsigned char Byte : Data) {
        Freq[Byte]++;
    }

    double Entropy = 0.0;
    double Length = static_cast<double>(Data.size());

    for (int I = 0; I < 256; ++I) {
        if (Freq[I] == 0) continue;
        double P = static_cast<double>(Freq[I]) / Length;
        Entropy -= P * std::log2(P);
    }

    return Entropy;
}

}
