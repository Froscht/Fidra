#include "BookmarkWidget.h"
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <QVBoxLayout>
#include <QToolBar>
#include <QHeaderView>
#include <QMenu>
#include <QClipboard>
#include <QApplication>
#include <QDialog>
#include <QFormLayout>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QColorDialog>
#include <QInputDialog>
#include <QFileDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QKeyEvent>
#include <QMessageBox>

namespace Fidra {

BookmarkWidget::BookmarkWidget(QWidget* Parent)
    : QWidget(Parent)
    , Database(nullptr)
{
    auto* Layout = new QVBoxLayout(this);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(2);

    ToolBar = new QToolBar(this);
    auto* AddAction = ToolBar->addAction("Add Bookmark");
    auto* RemoveAction = ToolBar->addAction("Remove");
    auto* ClearAction = ToolBar->addAction("Clear All");
    ToolBar->addSeparator();
    auto* ImportAction = ToolBar->addAction("Import");
    auto* ExportAction = ToolBar->addAction("Export");
    Layout->addWidget(ToolBar);

    FilterInput = new QLineEdit(this);
    FilterInput->setPlaceholderText("Filter bookmarks...");
    Layout->addWidget(FilterInput);

    TreeWidget = new QTreeWidget(this);
    TreeWidget->setHeaderLabels({"Color", "Address", "Name", "Description"});
    TreeWidget->setAlternatingRowColors(true);
    TreeWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    TreeWidget->setRootIsDecorated(true);
    TreeWidget->setSortingEnabled(true);
    TreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    TreeWidget->setDragDropMode(QAbstractItemView::InternalMove);
    TreeWidget->setDefaultDropAction(Qt::MoveAction);
    TreeWidget->header()->setSectionResizeMode(0, QHeaderView::Fixed);
    TreeWidget->header()->resizeSection(0, 30);
    TreeWidget->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(3, QHeaderView::Stretch);
    Layout->addWidget(TreeWidget);

    connect(FilterInput, &QLineEdit::textChanged, this, &BookmarkWidget::OnFilterChanged);
    connect(TreeWidget, &QTreeWidget::itemDoubleClicked, this, &BookmarkWidget::OnItemDoubleClicked);
    connect(TreeWidget, &QTreeWidget::customContextMenuRequested, this, &BookmarkWidget::OnContextMenu);
    connect(AddAction, &QAction::triggered, this, &BookmarkWidget::OnAddBookmark);
    connect(RemoveAction, &QAction::triggered, this, &BookmarkWidget::OnRemoveSelected);
    connect(ClearAction, &QAction::triggered, this, &BookmarkWidget::OnClearAll);
    connect(ImportAction, &QAction::triggered, this, &BookmarkWidget::OnImport);
    connect(ExportAction, &QAction::triggered, this, &BookmarkWidget::OnExport);
}

BookmarkWidget::~BookmarkWidget() = default;

void BookmarkWidget::AddBookmark(Address Addr, const QString& Name, const QString& Desc,
                                  const QColor& Color, const QString& Category) {
    Bookmark Bm;
    Bm.Addr = Addr;
    Bm.Name = Name;
    Bm.Description = Desc;
    Bm.Color = Color;
    Bm.Category = Category;
    Bm.Created = QDateTime::currentDateTime();

    if (Bm.Name.isEmpty() && Database && Database->HasName(Addr)) {
        Bm.Name = Database->GetName(Addr);
    }

    Bookmarks.insert(Addr, Bm);
    RefreshTree();
    emit BookmarkAdded(Addr);
}

void BookmarkWidget::RemoveBookmark(Address Addr) {
    if (Bookmarks.remove(Addr)) {
        RefreshTree();
        emit BookmarkRemoved(Addr);
    }
}

bool BookmarkWidget::HasBookmark(Address Addr) const {
    return Bookmarks.contains(Addr);
}

Bookmark BookmarkWidget::GetBookmark(Address Addr) const {
    return Bookmarks.value(Addr);
}

QList<Bookmark> BookmarkWidget::GetAllBookmarks() const {
    return Bookmarks.values();
}

void BookmarkWidget::SetAnalysisDatabase(AnalysisDatabase* Db) {
    Database = Db;
}

QJsonObject BookmarkWidget::SaveToJson() const {
    QJsonArray Arr;
    for (auto It = Bookmarks.constBegin(); It != Bookmarks.constEnd(); ++It) {
        const Bookmark& Bm = It.value();
        QJsonObject Obj;
        Obj["addr"] = QString("0x%1").arg(Bm.Addr, 16, 16, QChar('0')).toUpper();
        Obj["name"] = Bm.Name;
        Obj["description"] = Bm.Description;
        Obj["color"] = Bm.Color.name();
        Obj["category"] = Bm.Category;
        Obj["created"] = Bm.Created.toString(Qt::ISODate);
        Arr.append(Obj);
    }
    QJsonObject Root;
    Root["bookmarks"] = Arr;
    return Root;
}

void BookmarkWidget::LoadFromJson(const QJsonObject& Root) {
    QJsonArray Arr = Root["bookmarks"].toArray();
    Bookmarks.clear();

    for (const auto& Val : Arr) {
        QJsonObject Obj = Val.toObject();
        Bookmark Bm;
        QString AddrStr = Obj["addr"].toString();
        Bm.Addr = AddrStr.toULongLong(nullptr, 16);
        Bm.Name = Obj["name"].toString();
        Bm.Description = Obj["description"].toString();
        Bm.Color = QColor(Obj["color"].toString());
        Bm.Category = Obj["category"].toString();
        Bm.Created = QDateTime::fromString(Obj["created"].toString(), Qt::ISODate);

        if (Bm.Category.isEmpty()) {
            Bm.Category = "Default";
        }
        if (!Bm.Color.isValid()) {
            Bm.Color = QColor(255, 200, 50);
        }

        Bookmarks.insert(Bm.Addr, Bm);
    }

    RefreshTree();
}

void BookmarkWidget::OnItemDoubleClicked(QTreeWidgetItem* Item, int Column) {
    Q_UNUSED(Column);
    if (!Item || !Item->parent()) return;

    Address Addr = Item->data(0, Qt::UserRole).toULongLong();
    emit NavigateToAddress(Addr);
}

void BookmarkWidget::OnFilterChanged(const QString& Text) {
    for (int I = 0; I < TreeWidget->topLevelItemCount(); ++I) {
        QTreeWidgetItem* CategoryItem = TreeWidget->topLevelItem(I);
        bool AnyChildVisible = false;

        for (int J = 0; J < CategoryItem->childCount(); ++J) {
            QTreeWidgetItem* Child = CategoryItem->child(J);
            bool Matches = Text.isEmpty();

            if (!Matches) {
                for (int Col = 0; Col < TreeWidget->columnCount(); ++Col) {
                    if (Child->text(Col).contains(Text, Qt::CaseInsensitive)) {
                        Matches = true;
                        break;
                    }
                }
            }

            Child->setHidden(!Matches);
            if (Matches) AnyChildVisible = true;
        }

        CategoryItem->setHidden(!AnyChildVisible);
    }
}

void BookmarkWidget::OnContextMenu(const QPoint& Pos) {
    QTreeWidgetItem* Item = TreeWidget->itemAt(Pos);
    if (!Item || !Item->parent()) return;

    Address Addr = Item->data(0, Qt::UserRole).toULongLong();
    if (!Bookmarks.contains(Addr)) return;

    QMenu Menu(this);
    QAction* EditAction = Menu.addAction("Edit");
    QAction* RemoveAction = Menu.addAction("Remove");
    Menu.addSeparator();
    QAction* ColorAction = Menu.addAction("Change Color");
    QAction* CategoryAction = Menu.addAction("Change Category");
    Menu.addSeparator();
    QAction* CopyAction = Menu.addAction("Copy Address");

    QAction* Selected = Menu.exec(TreeWidget->viewport()->mapToGlobal(Pos));

    if (Selected == EditAction) {
        ShowEditDialog(Addr);
    } else if (Selected == RemoveAction) {
        RemoveBookmark(Addr);
    } else if (Selected == ColorAction) {
        QColor NewColor = QColorDialog::getColor(Bookmarks[Addr].Color, this, "Bookmark Color");
        if (NewColor.isValid()) {
            Bookmarks[Addr].Color = NewColor;
            RefreshTree();
        }
    } else if (Selected == CategoryAction) {
        bool Ok = false;
        QString NewCategory = QInputDialog::getText(this, "Change Category", "Category:",
                                                     QLineEdit::Normal, Bookmarks[Addr].Category, &Ok);
        if (Ok && !NewCategory.isEmpty()) {
            Bookmarks[Addr].Category = NewCategory;
            RefreshTree();
        }
    } else if (Selected == CopyAction) {
        QApplication::clipboard()->setText(FormatAddress(Addr));
    }
}

void BookmarkWidget::OnAddBookmark() {
    QDialog Dlg(this);
    Dlg.setWindowTitle("Add Bookmark");
    Dlg.setMinimumWidth(400);

    auto* Form = new QFormLayout(&Dlg);

    auto* AddrInput = new QLineEdit("0x", &Dlg);
    auto* NameInput = new QLineEdit(&Dlg);
    auto* DescInput = new QLineEdit(&Dlg);

    QColor SelectedColor(255, 200, 50);
    auto* ColorBtn = new QPushButton(&Dlg);
    ColorBtn->setFixedSize(60, 24);
    ColorBtn->setStyleSheet(QString("background-color: %1; border: 1px solid #888;").arg(SelectedColor.name()));

    connect(ColorBtn, &QPushButton::clicked, &Dlg, [&]() {
        QColor C = QColorDialog::getColor(SelectedColor, &Dlg, "Bookmark Color");
        if (C.isValid()) {
            SelectedColor = C;
            ColorBtn->setStyleSheet(QString("background-color: %1; border: 1px solid #888;").arg(C.name()));
        }
    });

    auto* CategoryCombo = new QComboBox(&Dlg);
    CategoryCombo->setEditable(true);
    QSet<QString> Categories;
    for (auto It = Bookmarks.constBegin(); It != Bookmarks.constEnd(); ++It) {
        Categories.insert(It.value().Category);
    }
    if (!Categories.contains("Default")) {
        Categories.insert("Default");
    }
    for (const QString& Cat : Categories) {
        CategoryCombo->addItem(Cat);
    }
    CategoryCombo->setCurrentText("Default");

    Form->addRow("Address:", AddrInput);
    Form->addRow("Name:", NameInput);
    Form->addRow("Description:", DescInput);
    Form->addRow("Color:", ColorBtn);
    Form->addRow("Category:", CategoryCombo);

    auto* Buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &Dlg);
    Form->addRow(Buttons);

    connect(Buttons, &QDialogButtonBox::accepted, &Dlg, &QDialog::accept);
    connect(Buttons, &QDialogButtonBox::rejected, &Dlg, &QDialog::reject);

    if (Dlg.exec() == QDialog::Accepted) {
        QString AddrStr = AddrInput->text().trimmed();
        bool Ok = false;
        Address Addr = AddrStr.toULongLong(&Ok, 16);
        if (!Ok && AddrStr.startsWith("0x", Qt::CaseInsensitive)) {
            Addr = AddrStr.mid(2).toULongLong(&Ok, 16);
        }
        if (Ok) {
            AddBookmark(Addr, NameInput->text().trimmed(), DescInput->text().trimmed(),
                        SelectedColor, CategoryCombo->currentText().trimmed());
        }
    }
}

void BookmarkWidget::OnRemoveSelected() {
    QTreeWidgetItem* Item = TreeWidget->currentItem();
    if (!Item || !Item->parent()) return;

    Address Addr = Item->data(0, Qt::UserRole).toULongLong();
    RemoveBookmark(Addr);
}

void BookmarkWidget::OnClearAll() {
    if (Bookmarks.isEmpty()) return;

    auto Result = QMessageBox::question(this, "Clear All Bookmarks",
                                         "Remove all bookmarks?",
                                         QMessageBox::Yes | QMessageBox::No);
    if (Result == QMessageBox::Yes) {
        QList<Address> Addrs = Bookmarks.keys();
        Bookmarks.clear();
        RefreshTree();
        for (Address Addr : Addrs) {
            emit BookmarkRemoved(Addr);
        }
    }
}

void BookmarkWidget::OnImport() {
    QString Path = QFileDialog::getOpenFileName(this, "Import Bookmarks", QString(),
                                                 "JSON Files (*.json);;All Files (*)");
    if (Path.isEmpty()) return;

    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly)) return;

    QJsonParseError Err;
    QJsonDocument Doc = QJsonDocument::fromJson(File.readAll(), &Err);
    File.close();

    if (Err.error != QJsonParseError::NoError) return;

    LoadFromJson(Doc.object());
}

void BookmarkWidget::OnExport() {
    QString Path = QFileDialog::getSaveFileName(this, "Export Bookmarks", "bookmarks.json",
                                                 "JSON Files (*.json);;All Files (*)");
    if (Path.isEmpty()) return;

    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly)) return;

    QJsonDocument Doc(SaveToJson());
    File.write(Doc.toJson(QJsonDocument::Indented));
    File.close();
}

void BookmarkWidget::RefreshTree() {
    TreeWidget->clear();

    QMap<QString, QList<const Bookmark*>> Grouped;
    for (auto It = Bookmarks.constBegin(); It != Bookmarks.constEnd(); ++It) {
        Grouped[It.value().Category].append(&It.value());
    }

    for (auto It = Grouped.constBegin(); It != Grouped.constEnd(); ++It) {
        QTreeWidgetItem* CategoryItem = CreateCategoryItem(It.key());

        for (const Bookmark* Bm : It.value()) {
            auto* Item = new QTreeWidgetItem(CategoryItem);
            Item->setBackground(0, Bm->Color);
            Item->setText(1, FormatAddress(Bm->Addr));
            Item->setText(2, Bm->Name);
            Item->setText(3, Bm->Description);
            Item->setData(0, Qt::UserRole, QVariant::fromValue(Bm->Addr));
        }

        CategoryItem->setExpanded(true);
    }
}

void BookmarkWidget::ShowEditDialog(Address Addr) {
    if (!Bookmarks.contains(Addr)) return;

    Bookmark& Bm = Bookmarks[Addr];

    QDialog Dlg(this);
    Dlg.setWindowTitle("Edit Bookmark");
    Dlg.setMinimumWidth(400);

    auto* Form = new QFormLayout(&Dlg);

    auto* AddrInput = new QLineEdit(FormatAddress(Bm.Addr), &Dlg);
    AddrInput->setReadOnly(true);
    auto* NameInput = new QLineEdit(Bm.Name, &Dlg);
    auto* DescInput = new QLineEdit(Bm.Description, &Dlg);

    QColor SelectedColor = Bm.Color;
    auto* ColorBtn = new QPushButton(&Dlg);
    ColorBtn->setFixedSize(60, 24);
    ColorBtn->setStyleSheet(QString("background-color: %1; border: 1px solid #888;").arg(SelectedColor.name()));

    connect(ColorBtn, &QPushButton::clicked, &Dlg, [&]() {
        QColor C = QColorDialog::getColor(SelectedColor, &Dlg, "Bookmark Color");
        if (C.isValid()) {
            SelectedColor = C;
            ColorBtn->setStyleSheet(QString("background-color: %1; border: 1px solid #888;").arg(C.name()));
        }
    });

    auto* CategoryCombo = new QComboBox(&Dlg);
    CategoryCombo->setEditable(true);
    QSet<QString> Categories;
    for (auto It = Bookmarks.constBegin(); It != Bookmarks.constEnd(); ++It) {
        Categories.insert(It.value().Category);
    }
    for (const QString& Cat : Categories) {
        CategoryCombo->addItem(Cat);
    }
    CategoryCombo->setCurrentText(Bm.Category);

    Form->addRow("Address:", AddrInput);
    Form->addRow("Name:", NameInput);
    Form->addRow("Description:", DescInput);
    Form->addRow("Color:", ColorBtn);
    Form->addRow("Category:", CategoryCombo);

    auto* Buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &Dlg);
    Form->addRow(Buttons);

    connect(Buttons, &QDialogButtonBox::accepted, &Dlg, &QDialog::accept);
    connect(Buttons, &QDialogButtonBox::rejected, &Dlg, &QDialog::reject);

    if (Dlg.exec() == QDialog::Accepted) {
        Bm.Name = NameInput->text().trimmed();
        Bm.Description = DescInput->text().trimmed();
        Bm.Color = SelectedColor;
        Bm.Category = CategoryCombo->currentText().trimmed();
        RefreshTree();
    }
}

QTreeWidgetItem* BookmarkWidget::FindCategoryItem(const QString& Category) {
    for (int I = 0; I < TreeWidget->topLevelItemCount(); ++I) {
        QTreeWidgetItem* Item = TreeWidget->topLevelItem(I);
        if (Item->text(0) == Category) {
            return Item;
        }
    }
    return nullptr;
}

QTreeWidgetItem* BookmarkWidget::CreateCategoryItem(const QString& Category) {
    QTreeWidgetItem* Existing = FindCategoryItem(Category);
    if (Existing) return Existing;

    auto* Item = new QTreeWidgetItem(TreeWidget);
    Item->setText(0, Category);
    QFont BoldFont = Item->font(0);
    BoldFont.setBold(true);
    Item->setFont(0, BoldFont);
    Item->setFlags(Item->flags() | Qt::ItemIsDropEnabled);
    Item->setFlags(Item->flags() & ~Qt::ItemIsDragEnabled);
    return Item;
}

QString BookmarkWidget::FormatAddress(Address Addr) const {
    return QString("0x%1").arg(Addr, 16, 16, QChar('0')).toUpper();
}

void BookmarkWidget::keyPressEvent(QKeyEvent* Event) {
    if (Event->key() == Qt::Key_Delete) {
        OnRemoveSelected();
        return;
    }
    QWidget::keyPressEvent(Event);
}

}
