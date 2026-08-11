#include "StructEditorWidget.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QLabel>
#include <QHeaderView>
#include <QFileDialog>
#include <QMenu>
#include <QMessageBox>
#include <QInputDialog>
#include <QJsonDocument>
#include <QFile>
#include <QTextStream>
#include <QApplication>
#include <QStyle>
#include <QDrag>
#include <QMimeData>
#include <algorithm>

namespace Fidra {

StructEditorWidget::StructEditorWidget(QWidget* Parent, ICore* Core)
    : QWidget(Parent)
    , CoreRef(Core)
    , Database(new TypeDatabase())
    , ProcessAttached(false)
    , BaseAddress(0)
    , UpdatingTable(false)
{
    SetupUi();
    SetupToolBar();

    AutoRefreshTimer = new QTimer(this);
    AutoRefreshTimer->setInterval(1000);
    connect(AutoRefreshTimer, &QTimer::timeout, this, &StructEditorWidget::OnRefreshLiveValues);
}

StructEditorWidget::~StructEditorWidget()
{
    AutoRefreshTimer->stop();
    delete Database;
}

void StructEditorWidget::SetupUi()
{
    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(4, 4, 4, 4);
    MainLayout->setSpacing(4);

    ToolBar = new QToolBar(this);
    MainLayout->addWidget(ToolBar);

    auto* AddressRow = new QHBoxLayout();
    AddressRow->addWidget(new QLabel("Base Address:", this));
    BaseAddressEdit = new QLineEdit(this);
    BaseAddressEdit->setPlaceholderText("0x00000000");
    BaseAddressEdit->setMaximumWidth(200);
    AddressRow->addWidget(BaseAddressEdit);
    RefreshBtn = new QPushButton("Refresh", this);
    AddressRow->addWidget(RefreshBtn);
    AddressRow->addWidget(new QLabel("Interval (ms):", this));
    RefreshIntervalSpin = new QSpinBox(this);
    RefreshIntervalSpin->setRange(100, 10000);
    RefreshIntervalSpin->setValue(1000);
    RefreshIntervalSpin->setSingleStep(100);
    AddressRow->addWidget(RefreshIntervalSpin);
    AutoRefreshBtn = new QPushButton("Auto", this);
    AutoRefreshBtn->setCheckable(true);
    AddressRow->addWidget(AutoRefreshBtn);
    StatusLabel = new QLabel(this);
    AddressRow->addWidget(StatusLabel);
    AddressRow->addStretch();
    MainLayout->addLayout(AddressRow);

    MainSplitter = new QSplitter(Qt::Horizontal, this);

    StructTree = new QTreeWidget(MainSplitter);
    StructTree->setHeaderLabels({"Name", "Size"});
    StructTree->setContextMenuPolicy(Qt::CustomContextMenu);
    StructTree->setMinimumWidth(200);
    StructTree->setMaximumWidth(350);
    StructTree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    StructTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);

    FieldTable = new QTableWidget(0, 7, MainSplitter);
    FieldTable->setHorizontalHeaderLabels({"Offset", "Name", "Type", "Size", "Array", "Value", "Comment"});
    FieldTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    FieldTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    FieldTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    FieldTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    FieldTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    FieldTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    FieldTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    FieldTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    FieldTable->setSelectionMode(QAbstractItemView::SingleSelection);
    FieldTable->setContextMenuPolicy(Qt::CustomContextMenu);
    FieldTable->verticalHeader()->setVisible(false);
    FieldTable->setAlternatingRowColors(true);
    FieldTable->setDragEnabled(true);
    FieldTable->setAcceptDrops(true);
    FieldTable->setDragDropMode(QAbstractItemView::InternalMove);
    FieldTable->setDropIndicatorShown(true);

    MainSplitter->addWidget(StructTree);
    MainSplitter->addWidget(FieldTable);
    MainSplitter->setStretchFactor(0, 1);
    MainSplitter->setStretchFactor(1, 3);

    MainLayout->addWidget(MainSplitter, 1);

    connect(StructTree, &QTreeWidget::currentItemChanged, this, &StructEditorWidget::OnStructTreeItemChanged);
    connect(FieldTable, &QTableWidget::cellChanged, this, &StructEditorWidget::OnFieldCellChanged);
    connect(FieldTable, &QTableWidget::customContextMenuRequested, this, &StructEditorWidget::OnFieldContextMenu);
    connect(BaseAddressEdit, &QLineEdit::editingFinished, this, &StructEditorWidget::OnBaseAddressChanged);
    connect(RefreshBtn, &QPushButton::clicked, this, &StructEditorWidget::OnRefreshLiveValues);
    connect(AutoRefreshBtn, &QPushButton::toggled, this, &StructEditorWidget::OnAutoRefreshToggled);
    connect(RefreshIntervalSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, &StructEditorWidget::OnRefreshIntervalChanged);
}

void StructEditorWidget::SetupToolBar()
{
    auto* AddStructAction = ToolBar->addAction(
        QApplication::style()->standardIcon(QStyle::SP_FileIcon), "Add Struct");
    connect(AddStructAction, &QAction::triggered, this, &StructEditorWidget::OnAddStruct);

    auto* DeleteStructAction = ToolBar->addAction(
        QApplication::style()->standardIcon(QStyle::SP_TrashIcon), "Delete Struct");
    connect(DeleteStructAction, &QAction::triggered, this, &StructEditorWidget::OnDeleteStruct);

    ToolBar->addSeparator();

    auto* AddFieldAction = ToolBar->addAction(
        QApplication::style()->standardIcon(QStyle::SP_FileDialogNewFolder), "Add Field");
    connect(AddFieldAction, &QAction::triggered, this, &StructEditorWidget::OnAddField);

    auto* DeleteFieldAction = ToolBar->addAction(
        QApplication::style()->standardIcon(QStyle::SP_DialogDiscardButton), "Delete Field");
    connect(DeleteFieldAction, &QAction::triggered, this, &StructEditorWidget::OnDeleteField);

    ToolBar->addSeparator();

    auto* AddEnumAction = ToolBar->addAction(
        QApplication::style()->standardIcon(QStyle::SP_FileDialogListView), "Add Enum");
    connect(AddEnumAction, &QAction::triggered, this, &StructEditorWidget::OnAddEnum);

    ToolBar->addSeparator();

    auto* ExportAction = ToolBar->addAction(
        QApplication::style()->standardIcon(QStyle::SP_DialogSaveButton), "Export JSON");
    connect(ExportAction, &QAction::triggered, this, &StructEditorWidget::OnExportJson);

    auto* ImportAction = ToolBar->addAction(
        QApplication::style()->standardIcon(QStyle::SP_DialogOpenButton), "Import JSON");
    connect(ImportAction, &QAction::triggered, this, &StructEditorWidget::OnImportJson);

    ToolBar->addSeparator();

    auto* GenerateAction = ToolBar->addAction(
        QApplication::style()->standardIcon(QStyle::SP_FileDialogContentsView), "Generate Header");
    connect(GenerateAction, &QAction::triggered, this, &StructEditorWidget::OnGenerateHeader);
}

void StructEditorWidget::OnProcessAttached(const ProcessInfo& Info)
{
    Q_UNUSED(Info);
    ProcessAttached = true;
    StatusLabel->setText("Attached");
}

void StructEditorWidget::OnProcessDetached()
{
    ProcessAttached = false;
    AutoRefreshBtn->setChecked(false);
    AutoRefreshTimer->stop();
    StatusLabel->setText("Detached");
    LiveBuffer.clear();

    UpdatingTable = true;
    for (int Row = 0; Row < FieldTable->rowCount(); ++Row) {
        auto* ValueItem = FieldTable->item(Row, 5);
        if (ValueItem) {
            ValueItem->setText("");
        }
    }
    UpdatingTable = false;
}

void StructEditorWidget::OnAddStruct()
{
    bool Ok = false;
    QString Name = QInputDialog::getText(this, "New Struct", "Struct name:", QLineEdit::Normal, "NewStruct", &Ok);
    if (!Ok || Name.isEmpty())
        return;

    if (Database->GetStruct(Name)) {
        QMessageBox::warning(this, "Struct Editor", "A struct with that name already exists.");
        return;
    }

    StructDefinition Def;
    Def.Name = Name;
    Def.Size = 0;
    Database->AddStruct(Def);
    RefreshStructTree();

    QTreeWidgetItem* StructsRoot = StructTree->topLevelItem(0);
    if (StructsRoot) {
        for (int I = 0; I < StructsRoot->childCount(); ++I) {
            auto* ChildItem = StructsRoot->child(I);
            if (ChildItem->data(0, Qt::UserRole).toUuid() == Def.Id) {
                StructTree->setCurrentItem(ChildItem);
                break;
            }
        }
    }
}

void StructEditorWidget::OnDeleteStruct()
{
    if (CurrentStructId.isNull())
        return;

    StructDefinition* Def = Database->GetStructById(CurrentStructId);
    if (!Def)
        return;

    auto Result = QMessageBox::question(this, "Delete Struct",
        QString("Delete struct '%1'?").arg(Def->Name));
    if (Result != QMessageBox::Yes)
        return;

    Database->RemoveStruct(CurrentStructId);
    CurrentStructId = QUuid();
    RefreshStructTree();
    RefreshFieldTable();
}

void StructEditorWidget::OnAddEnum()
{
    bool Ok = false;
    QString Name = QInputDialog::getText(this, "New Enum", "Enum name:", QLineEdit::Normal, "NewEnum", &Ok);
    if (!Ok || Name.isEmpty())
        return;

    if (Database->GetEnum(Name)) {
        QMessageBox::warning(this, "Struct Editor", "An enum with that name already exists.");
        return;
    }

    EnumDefinition Def;
    Def.Name = Name;
    Def.UnderlyingType = "uint32_t";
    Database->AddEnum(Def);
    RefreshStructTree();
}

void StructEditorWidget::OnAddField()
{
    if (CurrentStructId.isNull())
        return;

    StructDefinition* Def = Database->GetStructById(CurrentStructId);
    if (!Def)
        return;

    StructField NewField;
    NewField.Name = QString("Field_%1").arg(Def->Fields.size());
    NewField.Type = StructFieldType::UInt32;
    NewField.Size = TypeDatabase::FieldTypeSize(StructFieldType::UInt32);
    NewField.Offset = Def->Size;
    NewField.ArrayCount = 1;

    Def->Fields.append(NewField);
    Def->RecalculateSize();

    RefreshFieldTable();
    RefreshStructTree();
}

void StructEditorWidget::OnDeleteField()
{
    if (CurrentStructId.isNull())
        return;

    int Row = FieldTable->currentRow();
    if (Row < 0)
        return;

    StructDefinition* Def = Database->GetStructById(CurrentStructId);
    if (!Def || Row >= Def->Fields.size())
        return;

    QUuid FieldId = Def->Fields[Row].Id;
    Def->RemoveField(FieldId);
    Def->RecalculateSize();

    RefreshFieldTable();
    RefreshStructTree();
}

void StructEditorWidget::OnStructTreeItemChanged(QTreeWidgetItem* Current, QTreeWidgetItem* Previous)
{
    Q_UNUSED(Previous);

    if (!Current) {
        CurrentStructId = QUuid();
        RefreshFieldTable();
        return;
    }

    QUuid Id = Current->data(0, Qt::UserRole).toUuid();
    QString ItemType = Current->data(0, Qt::UserRole + 1).toString();

    if (ItemType == "struct") {
        CurrentStructId = Id;
        RefreshFieldTable();
    } else {
        CurrentStructId = QUuid();
        RefreshFieldTable();
    }
}

void StructEditorWidget::OnFieldCellChanged(int Row, int Column)
{
    if (UpdatingTable)
        return;

    if (CurrentStructId.isNull())
        return;

    StructDefinition* Def = Database->GetStructById(CurrentStructId);
    if (!Def || Row >= Def->Fields.size())
        return;

    StructField& Field = Def->Fields[Row];
    QTableWidgetItem* Item = FieldTable->item(Row, Column);
    if (!Item)
        return;

    switch (Column) {
        case 0: {
            QString Text = Item->text().trimmed();
            bool Ok = false;
            int NewOffset = 0;
            if (Text.startsWith("0x") || Text.startsWith("0X")) {
                NewOffset = Text.mid(2).toInt(&Ok, 16);
            } else {
                NewOffset = Text.toInt(&Ok);
            }
            if (Ok) {
                Field.Offset = NewOffset;
                SortFieldsByOffset();
                Def->RecalculateSize();
                RefreshFieldTable();
                RefreshStructTree();
            }
            break;
        }
        case 1:
            Field.Name = Item->text().trimmed();
            break;
        case 3: {
            bool Ok = false;
            int NewSize = Item->text().toInt(&Ok);
            if (Ok && NewSize > 0) {
                Field.Size = NewSize;
                Def->RecalculateSize();
                RefreshStructTree();
            }
            break;
        }
        case 4: {
            bool Ok = false;
            int NewCount = Item->text().toInt(&Ok);
            if (Ok && NewCount > 0) {
                Field.ArrayCount = NewCount;
                Def->RecalculateSize();
                RefreshStructTree();
            }
            break;
        }
        case 6:
            Field.Comment = Item->text();
            break;
    }
}

void StructEditorWidget::OnFieldContextMenu(const QPoint& Pos)
{
    QTableWidgetItem* Item = FieldTable->itemAt(Pos);
    if (!Item)
        return;

    int Row = Item->row();
    if (CurrentStructId.isNull())
        return;

    StructDefinition* Def = Database->GetStructById(CurrentStructId);
    if (!Def || Row >= Def->Fields.size())
        return;

    QMenu ContextMenu(this);

    QMenu* TypeMenu = ContextMenu.addMenu("Change Type");
    QStringList TypeStrings = GetAllTypeStrings();
    for (const auto& TypeStr : TypeStrings) {
        QAction* Action = TypeMenu->addAction(TypeStr);
        Action->setData(TypeStr);
    }

    ContextMenu.addSeparator();
    QAction* InsertPadAction = ContextMenu.addAction("Insert Padding Before");
    QAction* ConvertArrayAction = ContextMenu.addAction("Convert to Array");
    QAction* FollowPtrAction = ContextMenu.addAction("Follow Pointer");

    StructFieldType FieldType = Def->Fields[Row].Type;
    FollowPtrAction->setEnabled(
        FieldType == StructFieldType::Pointer ||
        FieldType == StructFieldType::Pointer32 ||
        FieldType == StructFieldType::Pointer64);

    ContextMenu.addSeparator();
    QAction* DeleteAction = ContextMenu.addAction("Delete Field");

    QAction* Selected = ContextMenu.exec(FieldTable->viewport()->mapToGlobal(Pos));
    if (!Selected)
        return;

    if (Selected == InsertPadAction) {
        InsertPaddingAtRow(Row);
    } else if (Selected == ConvertArrayAction) {
        ConvertToArray(Row);
    } else if (Selected == FollowPtrAction) {
        FollowPointer(Row);
    } else if (Selected == DeleteAction) {
        QUuid FieldId = Def->Fields[Row].Id;
        Def->RemoveField(FieldId);
        Def->RecalculateSize();
        RefreshFieldTable();
        RefreshStructTree();
    } else if (Selected->parent() && Selected->parent() == TypeMenu->menuAction()) {
        QString TypeStr = Selected->data().toString();
        StructFieldType NewType = TypeDatabase::StringToFieldType(TypeStr);
        ChangeFieldType(Row, NewType);
    }
}

void StructEditorWidget::OnBaseAddressChanged()
{
    QString Text = BaseAddressEdit->text().trimmed();
    bool Ok = false;
    if (Text.startsWith("0x") || Text.startsWith("0X")) {
        BaseAddress = Text.mid(2).toULongLong(&Ok, 16);
    } else {
        BaseAddress = Text.toULongLong(&Ok, 16);
    }

    if (!Ok) {
        BaseAddress = 0;
    }

    if (ProcessAttached && BaseAddress != 0) {
        OnRefreshLiveValues();
    }
}

void StructEditorWidget::OnRefreshLiveValues()
{
    if (!ProcessAttached || !CoreRef || BaseAddress == 0)
        return;

    if (CurrentStructId.isNull())
        return;

    StructDefinition* Def = Database->GetStructById(CurrentStructId);
    if (!Def || Def->Size == 0)
        return;

    ReadLiveValues();
}

void StructEditorWidget::OnAutoRefreshToggled(bool Enabled)
{
    if (Enabled) {
        AutoRefreshTimer->setInterval(RefreshIntervalSpin->value());
        AutoRefreshTimer->start();
    } else {
        AutoRefreshTimer->stop();
    }
}

void StructEditorWidget::OnRefreshIntervalChanged(int Ms)
{
    AutoRefreshTimer->setInterval(Ms);
}

void StructEditorWidget::OnExportJson()
{
    QString FilePath = QFileDialog::getSaveFileName(this, "Export Types", QString(), "JSON Files (*.json);;All Files (*)");
    if (FilePath.isEmpty())
        return;

    QJsonObject Root = Database->ExportToJson();
    QFile File(FilePath);
    if (!File.open(QIODevice::WriteOnly)) {
        QMessageBox::critical(this, "Export Error", "Failed to open file for writing.");
        return;
    }
    File.write(QJsonDocument(Root).toJson(QJsonDocument::Indented));
    File.close();
    StatusLabel->setText("Exported successfully");
}

void StructEditorWidget::OnImportJson()
{
    QString FilePath = QFileDialog::getOpenFileName(this, "Import Types", QString(), "JSON Files (*.json);;All Files (*)");
    if (FilePath.isEmpty())
        return;

    QFile File(FilePath);
    if (!File.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Import Error", "Failed to open file for reading.");
        return;
    }

    QJsonDocument Doc = QJsonDocument::fromJson(File.readAll());
    File.close();

    if (!Doc.isObject()) {
        QMessageBox::critical(this, "Import Error", "Invalid JSON format.");
        return;
    }

    Database->ImportFromJson(Doc.object());
    RefreshStructTree();
    CurrentStructId = QUuid();
    RefreshFieldTable();
    StatusLabel->setText("Imported successfully");
}

void StructEditorWidget::OnGenerateHeader()
{
    QString FilePath = QFileDialog::getSaveFileName(this, "Generate C/C++ Header", QString(), "Header Files (*.h);;All Files (*)");
    if (FilePath.isEmpty())
        return;

    QString Content = GenerateHeaderText();
    QFile File(FilePath);
    if (!File.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Generate Error", "Failed to open file for writing.");
        return;
    }

    QTextStream Out(&File);
    Out << Content;
    File.close();
    StatusLabel->setText("Header generated");
}

void StructEditorWidget::RefreshStructTree()
{
    StructTree->clear();

    auto* StructsRoot = new QTreeWidgetItem(StructTree);
    StructsRoot->setText(0, "Structs");
    StructsRoot->setExpanded(true);

    auto AllStructs = Database->GetAllStructs();
    std::sort(AllStructs.begin(), AllStructs.end(),
        [](const StructDefinition& A, const StructDefinition& B) { return A.Name < B.Name; });

    for (const auto& Def : AllStructs) {
        auto* Item = new QTreeWidgetItem(StructsRoot);
        Item->setText(0, Def.Name);
        Item->setText(1, QString("0x%1").arg(Def.Size, 0, 16, QChar('0')).toUpper());
        Item->setData(0, Qt::UserRole, Def.Id);
        Item->setData(0, Qt::UserRole + 1, "struct");
    }

    auto* EnumsRoot = new QTreeWidgetItem(StructTree);
    EnumsRoot->setText(0, "Enums");
    EnumsRoot->setExpanded(true);

    auto AllEnums = Database->GetAllEnums();
    std::sort(AllEnums.begin(), AllEnums.end(),
        [](const EnumDefinition& A, const EnumDefinition& B) { return A.Name < B.Name; });

    for (const auto& Def : AllEnums) {
        auto* Item = new QTreeWidgetItem(EnumsRoot);
        Item->setText(0, Def.Name);
        Item->setText(1, Def.UnderlyingType);
        Item->setData(0, Qt::UserRole, Def.Id);
        Item->setData(0, Qt::UserRole + 1, "enum");
    }
}

void StructEditorWidget::RefreshFieldTable()
{
    UpdatingTable = true;
    FieldTable->setRowCount(0);

    if (CurrentStructId.isNull()) {
        UpdatingTable = false;
        return;
    }

    StructDefinition* Def = Database->GetStructById(CurrentStructId);
    if (!Def) {
        UpdatingTable = false;
        return;
    }

    FieldTable->setRowCount(Def->Fields.size());

    for (int I = 0; I < Def->Fields.size(); ++I) {
        const StructField& Field = Def->Fields[I];

        auto* OffsetItem = new QTableWidgetItem(
            QString("0x%1").arg(Field.Offset, 4, 16, QChar('0')).toUpper());
        FieldTable->setItem(I, 0, OffsetItem);

        auto* NameItem = new QTableWidgetItem(Field.Name);
        FieldTable->setItem(I, 1, NameItem);

        auto* TypeItem = new QTableWidgetItem(TypeDatabase::FieldTypeToString(Field.Type));
        TypeItem->setFlags(TypeItem->flags() & ~Qt::ItemIsEditable);
        FieldTable->setItem(I, 2, TypeItem);

        auto* SizeItem = new QTableWidgetItem(QString::number(Field.Size));
        FieldTable->setItem(I, 3, SizeItem);

        auto* ArrayItem = new QTableWidgetItem(QString::number(Field.ArrayCount));
        FieldTable->setItem(I, 4, ArrayItem);

        auto* ValueItem = new QTableWidgetItem();
        ValueItem->setFlags(ValueItem->flags() & ~Qt::ItemIsEditable);
        FieldTable->setItem(I, 5, ValueItem);

        auto* CommentItem = new QTableWidgetItem(Field.Comment);
        FieldTable->setItem(I, 6, CommentItem);

        if (Field.Type == StructFieldType::Padding) {
            for (int Col = 0; Col < 7; ++Col) {
                auto* CellItem = FieldTable->item(I, Col);
                if (CellItem) {
                    CellItem->setBackground(QColor(80, 80, 80, 60));
                }
            }
        }
    }

    UpdatingTable = false;

    if (ProcessAttached && BaseAddress != 0 && Def->Size > 0) {
        ReadLiveValues();
    }
}

void StructEditorWidget::ReadLiveValues()
{
    if (!CoreRef || !CoreRef->IsAttached() || BaseAddress == 0)
        return;

    StructDefinition* Def = Database->GetStructById(CurrentStructId);
    if (!Def || Def->Size == 0)
        return;

    LiveBuffer.resize(Def->Size);
    bool ReadOk = CoreRef->ReadMemory(BaseAddress, LiveBuffer.data(), LiveBuffer.size());

    UpdatingTable = true;

    for (int I = 0; I < Def->Fields.size() && I < FieldTable->rowCount(); ++I) {
        auto* ValueItem = FieldTable->item(I, 5);
        if (!ValueItem)
            continue;

        if (!ReadOk) {
            ValueItem->setText("???");
            continue;
        }

        const StructField& Field = Def->Fields[I];
        int FieldEnd = Field.Offset + Field.TotalSize();
        if (FieldEnd > LiveBuffer.size()) {
            ValueItem->setText("OOB");
            continue;
        }

        const uint8_t* DataPtr = reinterpret_cast<const uint8_t*>(LiveBuffer.constData()) + Field.Offset;
        int Available = LiveBuffer.size() - Field.Offset;
        ValueItem->setText(FormatLiveValue(Field, DataPtr, Available));
    }

    UpdatingTable = false;
}

QString StructEditorWidget::FormatLiveValue(const StructField& Field, const uint8_t* Data, int DataSize)
{
    if (DataSize < Field.Size)
        return "?";

    switch (Field.Type) {
        case StructFieldType::Int8: {
            int8_t Val = 0;
            memcpy(&Val, Data, sizeof(Val));
            return QString::number(Val);
        }
        case StructFieldType::UInt8: {
            uint8_t Val = 0;
            memcpy(&Val, Data, sizeof(Val));
            return QString::number(Val);
        }
        case StructFieldType::Bool: {
            uint8_t Val = 0;
            memcpy(&Val, Data, sizeof(Val));
            return Val ? "true" : "false";
        }
        case StructFieldType::Int16: {
            int16_t Val = 0;
            memcpy(&Val, Data, sizeof(Val));
            return QString::number(Val);
        }
        case StructFieldType::UInt16: {
            uint16_t Val = 0;
            memcpy(&Val, Data, sizeof(Val));
            return QString::number(Val);
        }
        case StructFieldType::Int32: {
            int32_t Val = 0;
            memcpy(&Val, Data, sizeof(Val));
            return QString::number(Val);
        }
        case StructFieldType::UInt32: {
            uint32_t Val = 0;
            memcpy(&Val, Data, sizeof(Val));
            return QString::number(Val);
        }
        case StructFieldType::Int64: {
            int64_t Val = 0;
            memcpy(&Val, Data, sizeof(Val));
            return QString::number(Val);
        }
        case StructFieldType::UInt64: {
            uint64_t Val = 0;
            memcpy(&Val, Data, sizeof(Val));
            return QString("0x%1").arg(Val, 16, 16, QChar('0')).toUpper();
        }
        case StructFieldType::Float: {
            float Val = 0;
            memcpy(&Val, Data, sizeof(Val));
            return QString::number(static_cast<double>(Val), 'g', 6);
        }
        case StructFieldType::Double: {
            double Val = 0;
            memcpy(&Val, Data, sizeof(Val));
            return QString::number(Val, 'g', 10);
        }
        case StructFieldType::Pointer:
        case StructFieldType::Pointer64: {
            uint64_t Val = 0;
            memcpy(&Val, Data, sizeof(Val));
            return QString("0x%1").arg(Val, 16, 16, QChar('0')).toUpper();
        }
        case StructFieldType::Pointer32: {
            uint32_t Val = 0;
            memcpy(&Val, Data, sizeof(Val));
            return QString("0x%1").arg(Val, 8, 16, QChar('0')).toUpper();
        }
        case StructFieldType::VTable:
        case StructFieldType::FunctionPtr: {
            uint64_t Val = 0;
            memcpy(&Val, Data, sizeof(Val));
            return QString("0x%1").arg(Val, 16, 16, QChar('0')).toUpper();
        }
        case StructFieldType::CharArray: {
            int Len = qMin(Field.TotalSize(), DataSize);
            QByteArray Bytes(reinterpret_cast<const char*>(Data), Len);
            int NullPos = Bytes.indexOf('\0');
            if (NullPos >= 0) {
                Bytes.truncate(NullPos);
            }
            return QString("\"%1\"").arg(QString::fromLatin1(Bytes));
        }
        case StructFieldType::WCharArray: {
            int Len = qMin(Field.TotalSize(), DataSize);
            int CharCount = Len / 2;
            const char16_t* WData = reinterpret_cast<const char16_t*>(Data);
            QString Str;
            for (int I = 0; I < CharCount; ++I) {
                if (WData[I] == 0) break;
                Str.append(QChar(WData[I]));
            }
            return QString("L\"%1\"").arg(Str);
        }
        case StructFieldType::Padding: {
            int Len = qMin(Field.TotalSize(), qMin(DataSize, 16));
            QString Hex;
            for (int I = 0; I < Len; ++I) {
                if (I > 0) Hex += " ";
                Hex += QString("%1").arg(Data[I], 2, 16, QChar('0')).toUpper();
            }
            if (Field.TotalSize() > 16) {
                Hex += " ...";
            }
            return Hex;
        }
        case StructFieldType::Bitfield: {
            if (Field.Size <= 4) {
                uint32_t Val = 0;
                memcpy(&Val, Data, qMin(Field.Size, 4));
                uint32_t Mask = ((1u << Field.BitSize) - 1) << Field.BitOffset;
                uint32_t Extracted = (Val & Mask) >> Field.BitOffset;
                return QString("0b%1 (%2)").arg(Extracted, Field.BitSize, 2, QChar('0')).arg(Extracted);
            }
            return "?";
        }
        case StructFieldType::Enum: {
            if (Field.Size == 4) {
                int32_t Val = 0;
                memcpy(&Val, Data, sizeof(Val));
                EnumDefinition* EnumDef = Database->GetEnum(Field.ReferencedType);
                if (EnumDef && EnumDef->Values.contains(Val)) {
                    return QString("%1 (%2)").arg(EnumDef->Values[Val]).arg(Val);
                }
                return QString::number(Val);
            }
            return "?";
        }
        case StructFieldType::Unknown:
        case StructFieldType::Struct:
        case StructFieldType::Array: {
            int Len = qMin(Field.TotalSize(), qMin(DataSize, 16));
            QString Hex;
            for (int I = 0; I < Len; ++I) {
                if (I > 0) Hex += " ";
                Hex += QString("%1").arg(Data[I], 2, 16, QChar('0')).toUpper();
            }
            if (Field.TotalSize() > 16) {
                Hex += " ...";
            }
            return Hex;
        }
    }
    return "";
}

void StructEditorWidget::ChangeFieldType(int Row, StructFieldType NewType)
{
    if (CurrentStructId.isNull())
        return;

    StructDefinition* Def = Database->GetStructById(CurrentStructId);
    if (!Def || Row >= Def->Fields.size())
        return;

    StructField& Field = Def->Fields[Row];
    Field.Type = NewType;

    int NewSize = TypeDatabase::FieldTypeSize(NewType);
    if (NewSize > 0) {
        Field.Size = NewSize;
    } else if (NewType == StructFieldType::CharArray || NewType == StructFieldType::WCharArray) {
        if (Field.Size <= 0) {
            Field.Size = 32;
        }
    } else if (NewType == StructFieldType::Padding || NewType == StructFieldType::Unknown) {
        if (Field.Size <= 0) {
            Field.Size = 1;
        }
    } else if (NewType == StructFieldType::Struct) {
        bool Ok = false;
        QStringList StructNames;
        auto AllStructs = Database->GetAllStructs();
        for (const auto& S : AllStructs) {
            if (S.Id != CurrentStructId) {
                StructNames.append(S.Name);
            }
        }
        if (!StructNames.isEmpty()) {
            QString Selected = QInputDialog::getItem(this, "Select Struct", "Referenced struct:", StructNames, 0, false, &Ok);
            if (Ok) {
                Field.ReferencedType = Selected;
                StructDefinition* RefDef = Database->GetStruct(Selected);
                if (RefDef) {
                    Field.Size = RefDef->Size;
                }
            }
        }
    } else if (NewType == StructFieldType::Enum) {
        bool Ok = false;
        QStringList EnumNames;
        auto AllEnums = Database->GetAllEnums();
        for (const auto& E : AllEnums) {
            EnumNames.append(E.Name);
        }
        if (!EnumNames.isEmpty()) {
            QString Selected = QInputDialog::getItem(this, "Select Enum", "Referenced enum:", EnumNames, 0, false, &Ok);
            if (Ok) {
                Field.ReferencedType = Selected;
                Field.Size = 4;
            }
        }
    } else if (NewType == StructFieldType::Bitfield) {
        bool Ok = false;
        int BitWidth = QInputDialog::getInt(this, "Bitfield Width", "Number of bits:", 1, 1, 32, 1, &Ok);
        if (Ok) {
            Field.BitSize = BitWidth;
            Field.Size = (BitWidth + 7) / 8;
        }
    } else if (NewType == StructFieldType::Array) {
        if (Field.Size <= 0) {
            Field.Size = 1;
        }
        bool Ok = false;
        int Count = QInputDialog::getInt(this, "Array Count", "Number of elements:", Field.ArrayCount, 1, 65536, 1, &Ok);
        if (Ok) {
            Field.ArrayCount = Count;
        }
    }

    Def->RecalculateSize();
    RefreshFieldTable();
    RefreshStructTree();
}

void StructEditorWidget::InsertPaddingAtRow(int Row)
{
    if (CurrentStructId.isNull())
        return;

    StructDefinition* Def = Database->GetStructById(CurrentStructId);
    if (!Def || Row >= Def->Fields.size())
        return;

    bool Ok = false;
    int PadSize = QInputDialog::getInt(this, "Insert Padding", "Padding size (bytes):", 4, 1, 4096, 1, &Ok);
    if (!Ok)
        return;

    int InsertOffset = Def->Fields[Row].Offset;

    for (auto& Field : Def->Fields) {
        if (Field.Offset >= InsertOffset) {
            Field.Offset += PadSize;
        }
    }

    StructField Pad;
    Pad.Name = QString("Pad_%1").arg(InsertOffset, 4, 16, QChar('0'));
    Pad.Type = StructFieldType::Padding;
    Pad.Offset = InsertOffset;
    Pad.Size = PadSize;
    Pad.ArrayCount = 1;

    Def->InsertField(InsertOffset, Pad);
    SortFieldsByOffset();
    Def->RecalculateSize();
    RefreshFieldTable();
    RefreshStructTree();
}

void StructEditorWidget::ConvertToArray(int Row)
{
    if (CurrentStructId.isNull())
        return;

    StructDefinition* Def = Database->GetStructById(CurrentStructId);
    if (!Def || Row >= Def->Fields.size())
        return;

    bool Ok = false;
    int Count = QInputDialog::getInt(this, "Convert to Array", "Array count:", 2, 2, 65536, 1, &Ok);
    if (!Ok)
        return;

    Def->Fields[Row].ArrayCount = Count;
    Def->RecalculateSize();
    RefreshFieldTable();
    RefreshStructTree();
}

void StructEditorWidget::FollowPointer(int Row)
{
    if (!ProcessAttached || !CoreRef || BaseAddress == 0)
        return;

    if (CurrentStructId.isNull())
        return;

    StructDefinition* Def = Database->GetStructById(CurrentStructId);
    if (!Def || Row >= Def->Fields.size())
        return;

    const StructField& Field = Def->Fields[Row];
    int FieldEnd = Field.Offset + Field.Size;
    if (FieldEnd > LiveBuffer.size())
        return;

    uint64_t PointerValue = 0;
    if (Field.Type == StructFieldType::Pointer32) {
        uint32_t Val32 = 0;
        memcpy(&Val32, LiveBuffer.constData() + Field.Offset, sizeof(Val32));
        PointerValue = Val32;
    } else {
        memcpy(&PointerValue, LiveBuffer.constData() + Field.Offset, sizeof(PointerValue));
    }

    if (PointerValue == 0) {
        QMessageBox::information(this, "Follow Pointer", "Pointer is null.");
        return;
    }

    BaseAddress = PointerValue;
    BaseAddressEdit->setText(QString("0x%1").arg(PointerValue, 16, 16, QChar('0')).toUpper());
    OnRefreshLiveValues();
}

QStringList StructEditorWidget::GetAllTypeStrings() const
{
    return {
        "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t",
        "int64_t", "uint64_t", "float", "double", "bool",
        "void*", "uint32_t*", "uint64_t*",
        "char[]", "wchar_t[]",
        "padding", "unknown",
        "struct", "enum", "bitfield", "array", "vtable*", "func*"
    };
}

void StructEditorWidget::PopulateTypeCombo(QComboBox* Combo, StructFieldType CurrentType)
{
    Combo->clear();
    QStringList Types = GetAllTypeStrings();
    for (const auto& T : Types) {
        Combo->addItem(T);
    }
    QString CurrentStr = TypeDatabase::FieldTypeToString(CurrentType);
    int Idx = Types.indexOf(CurrentStr);
    if (Idx >= 0) {
        Combo->setCurrentIndex(Idx);
    }
}

QString StructEditorWidget::GenerateHeaderText() const
{
    QString Output;
    QTextStream Out(&Output);

    Out << "#pragma once\n\n";
    Out << "#include <stdint.h>\n";
    Out << "#include <stdbool.h>\n\n";

    auto AllEnums = Database->GetAllEnums();
    std::sort(AllEnums.begin(), AllEnums.end(),
        [](const EnumDefinition& A, const EnumDefinition& B) { return A.Name < B.Name; });

    for (const auto& Def : AllEnums) {
        Out << "enum " << Def.Name << " : " << Def.UnderlyingType << " {\n";
        for (auto It = Def.Values.constBegin(); It != Def.Values.constEnd(); ++It) {
            Out << "    " << It.value() << " = " << It.key() << ",\n";
        }
        Out << "};\n\n";
    }

    auto AllStructs = Database->GetAllStructs();
    std::sort(AllStructs.begin(), AllStructs.end(),
        [](const StructDefinition& A, const StructDefinition& B) { return A.Name < B.Name; });

    for (const auto& Def : AllStructs) {
        Out << "struct " << Def.Name << ";\n";
    }
    if (!AllStructs.isEmpty()) {
        Out << "\n";
    }

    for (const auto& Def : AllStructs) {
        if (!Def.ParentStruct.isEmpty()) {
            Out << "struct " << Def.Name << " : public " << Def.ParentStruct << " {\n";
        } else {
            Out << "struct " << Def.Name << " {\n";
        }

        QVector<StructField> Sorted = Def.Fields;
        std::sort(Sorted.begin(), Sorted.end(),
            [](const StructField& A, const StructField& B) { return A.Offset < B.Offset; });

        for (const auto& Field : Sorted) {
            Out << "    ";

            QString TypeStr;
            switch (Field.Type) {
                case StructFieldType::Int8: TypeStr = "int8_t"; break;
                case StructFieldType::UInt8: TypeStr = "uint8_t"; break;
                case StructFieldType::Int16: TypeStr = "int16_t"; break;
                case StructFieldType::UInt16: TypeStr = "uint16_t"; break;
                case StructFieldType::Int32: TypeStr = "int32_t"; break;
                case StructFieldType::UInt32: TypeStr = "uint32_t"; break;
                case StructFieldType::Int64: TypeStr = "int64_t"; break;
                case StructFieldType::UInt64: TypeStr = "uint64_t"; break;
                case StructFieldType::Float: TypeStr = "float"; break;
                case StructFieldType::Double: TypeStr = "double"; break;
                case StructFieldType::Bool: TypeStr = "bool"; break;
                case StructFieldType::Pointer:
                    if (!Field.ReferencedType.isEmpty()) {
                        TypeStr = Field.ReferencedType + "*";
                    } else {
                        TypeStr = "void*";
                    }
                    break;
                case StructFieldType::Pointer32: TypeStr = "uint32_t*"; break;
                case StructFieldType::Pointer64: TypeStr = "uint64_t*"; break;
                case StructFieldType::CharArray: TypeStr = "char"; break;
                case StructFieldType::WCharArray: TypeStr = "wchar_t"; break;
                case StructFieldType::FunctionPtr: TypeStr = "void*"; break;
                case StructFieldType::VTable: TypeStr = "void**"; break;
                case StructFieldType::Struct:
                    TypeStr = Field.ReferencedType.isEmpty() ? "uint8_t" : Field.ReferencedType;
                    break;
                case StructFieldType::Enum:
                    TypeStr = Field.ReferencedType.isEmpty() ? "uint32_t" : Field.ReferencedType;
                    break;
                case StructFieldType::Padding: TypeStr = "uint8_t"; break;
                case StructFieldType::Unknown: TypeStr = "uint8_t"; break;
                case StructFieldType::Array: TypeStr = "uint8_t"; break;
                case StructFieldType::Bitfield: TypeStr = "uint32_t"; break;
            }

            Out << TypeStr << " " << Field.Name;

            if (Field.Type == StructFieldType::CharArray || Field.Type == StructFieldType::WCharArray) {
                Out << "[" << Field.TotalSize() / (Field.Type == StructFieldType::WCharArray ? 2 : 1) << "]";
            } else if (Field.ArrayCount > 1) {
                Out << "[" << Field.ArrayCount << "]";
            } else if (Field.Type == StructFieldType::Padding || Field.Type == StructFieldType::Unknown) {
                Out << "[" << Field.Size << "]";
            }

            if (Field.Type == StructFieldType::Bitfield && Field.BitSize > 0) {
                Out << " : " << Field.BitSize;
            }

            Out << "; /* 0x" << QString::number(Field.Offset, 16).toUpper() << " */\n";
        }

        Out << "}; /* 0x" << QString::number(Def.Size, 16).toUpper() << " */\n\n";
    }

    return Output;
}

void StructEditorWidget::SortFieldsByOffset()
{
    if (CurrentStructId.isNull())
        return;

    StructDefinition* Def = Database->GetStructById(CurrentStructId);
    if (!Def)
        return;

    std::sort(Def->Fields.begin(), Def->Fields.end(),
        [](const StructField& A, const StructField& B) { return A.Offset < B.Offset; });
}

}
