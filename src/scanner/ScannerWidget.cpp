#include "ScannerWidget.h"
#include "ScanEngine.h"
#include "AddressList.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableView>
#include <QProgressBar>
#include <QHeaderView>
#include <QFileDialog>
#include <QTimer>
#include <QMenu>
#include <QMessageBox>

namespace Fidra {

ScannerWidget::ScannerWidget(QWidget* Parent, ICore* Core)
    : QWidget(Parent)
    , CoreRef(Core)
    , Engine(new ScanEngine(this))
    , Addresses(new AddressList(this))
    , ScanInProgress(false)
{
    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(4, 4, 4, 4);
    MainLayout->setSpacing(4);

    auto* Splitter = new QSplitter(Qt::Vertical, this);

    auto* TopWidget = new QWidget(Splitter);
    auto* TopLayout = new QVBoxLayout(TopWidget);
    TopLayout->setContentsMargins(0, 0, 0, 0);
    TopLayout->setSpacing(4);

    auto* ValueRow = new QHBoxLayout();
    ValueRow->addWidget(new QLabel("Value:", TopWidget));
    ValueInput = new QLineEdit(TopWidget);
    ValueInput->setPlaceholderText("Enter value to scan for...");
    ValueRow->addWidget(ValueInput);
    Value2Label = new QLabel("Value 2:", TopWidget);
    Value2Label->setVisible(false);
    ValueRow->addWidget(Value2Label);
    Value2Input = new QLineEdit(TopWidget);
    Value2Input->setPlaceholderText("Upper bound...");
    Value2Input->setVisible(false);
    ValueRow->addWidget(Value2Input);
    TopLayout->addLayout(ValueRow);

    auto* ScanTypeRow = new QHBoxLayout();
    ScanTypeRow->addWidget(new QLabel("Scan Type:", TopWidget));
    ScanTypeCombo = new QComboBox(TopWidget);
    ScanTypeCombo->addItem("Exact");
    ScanTypeCombo->addItem("Greater Than");
    ScanTypeCombo->addItem("Less Than");
    ScanTypeCombo->addItem("Between");
    ScanTypeCombo->addItem("Unknown Value");
    ScanTypeCombo->addItem("Changed");
    ScanTypeCombo->addItem("Unchanged");
    ScanTypeRow->addWidget(ScanTypeCombo, 1);
    TopLayout->addLayout(ScanTypeRow);

    auto* ValueTypeRow = new QHBoxLayout();
    ValueTypeRow->addWidget(new QLabel("Value Type:", TopWidget));
    ValueTypeCombo = new QComboBox(TopWidget);
    ValueTypeCombo->addItem("Byte");
    ValueTypeCombo->addItem("Int16");
    ValueTypeCombo->addItem("Int32");
    ValueTypeCombo->addItem("Int64");
    ValueTypeCombo->addItem("Float");
    ValueTypeCombo->addItem("Double");
    ValueTypeCombo->addItem("String");
    ValueTypeCombo->addItem("Byte Array");
    ValueTypeCombo->setCurrentIndex(2);
    ValueTypeRow->addWidget(ValueTypeCombo, 1);
    TopLayout->addLayout(ValueTypeRow);

    auto* ButtonRow = new QHBoxLayout();
    FirstScanBtn = new QPushButton("First Scan", TopWidget);
    NextScanBtn = new QPushButton("Next Scan", TopWidget);
    NewScanBtn = new QPushButton("New Scan", TopWidget);
    NextScanBtn->setEnabled(false);
    ButtonRow->addWidget(FirstScanBtn);
    ButtonRow->addWidget(NextScanBtn);
    ButtonRow->addWidget(NewScanBtn);
    TopLayout->addLayout(ButtonRow);

    ScanProgress = new QProgressBar(TopWidget);
    ScanProgress->setRange(0, 100);
    ScanProgress->setValue(0);
    ScanProgress->setTextVisible(true);
    TopLayout->addWidget(ScanProgress);

    FoundLabel = new QLabel("Found: 0", TopWidget);
    TopLayout->addWidget(FoundLabel);

    ResultsTable = new QTableWidget(0, 3, TopWidget);
    ResultsTable->setHorizontalHeaderLabels({"Address", "Value", "Previous Value"});
    ResultsTable->horizontalHeader()->setStretchLastSection(true);
    ResultsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ResultsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ResultsTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    ResultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ResultsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    ResultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ResultsTable->setContextMenuPolicy(Qt::CustomContextMenu);
    ResultsTable->verticalHeader()->setVisible(false);
    ResultsTable->setAlternatingRowColors(true);
    TopLayout->addWidget(ResultsTable, 1);

    Splitter->addWidget(TopWidget);

    auto* BottomWidget = new QWidget(Splitter);
    auto* BottomLayout = new QVBoxLayout(BottomWidget);
    BottomLayout->setContentsMargins(0, 0, 0, 0);
    BottomLayout->setSpacing(4);

    auto* AddressHeaderRow = new QHBoxLayout();
    AddressHeaderRow->addWidget(new QLabel("Address List", BottomWidget));
    AddressHeaderRow->addStretch();
    SaveListBtn = new QPushButton("Save List", BottomWidget);
    LoadListBtn = new QPushButton("Load List", BottomWidget);
    AddressHeaderRow->addWidget(SaveListBtn);
    AddressHeaderRow->addWidget(LoadListBtn);
    BottomLayout->addLayout(AddressHeaderRow);

    AddressTableView = new QTableView(BottomWidget);
    AddressTableView->setModel(Addresses);
    AddressTableView->horizontalHeader()->setStretchLastSection(true);
    AddressTableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    AddressTableView->setSelectionMode(QAbstractItemView::SingleSelection);
    AddressTableView->setAlternatingRowColors(true);
    AddressTableView->verticalHeader()->setVisible(false);
    BottomLayout->addWidget(AddressTableView, 1);

    Splitter->addWidget(BottomWidget);
    Splitter->setStretchFactor(0, 3);
    Splitter->setStretchFactor(1, 1);

    MainLayout->addWidget(Splitter);

    FreezeTimer = new QTimer(this);
    FreezeTimer->setInterval(100);

    connect(FirstScanBtn, &QPushButton::clicked, this, &ScannerWidget::OnFirstScan);
    connect(NextScanBtn, &QPushButton::clicked, this, &ScannerWidget::OnNextScan);
    connect(NewScanBtn, &QPushButton::clicked, this, &ScannerWidget::OnNewScan);
    connect(ScanTypeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &ScannerWidget::OnScanTypeChanged);
    connect(Engine, &ScanEngine::ScanProgress, this, &ScannerWidget::OnScanProgressUpdate);
    connect(Engine, &ScanEngine::ScanComplete, this, &ScannerWidget::OnScanFinished);
    connect(ResultsTable, &QTableWidget::cellDoubleClicked, this, &ScannerWidget::OnResultDoubleClicked);
    connect(ResultsTable, &QTableWidget::customContextMenuRequested, this, &ScannerWidget::OnResultContextMenu);
    connect(SaveListBtn, &QPushButton::clicked, this, &ScannerWidget::OnSaveList);
    connect(LoadListBtn, &QPushButton::clicked, this, &ScannerWidget::OnLoadList);
    connect(FreezeTimer, &QTimer::timeout, this, [this]() {
        Addresses->WriteFrozenValues(CoreRef);
    });

    FreezeTimer->start();
}

ScannerWidget::~ScannerWidget()
{
    FreezeTimer->stop();
    Engine->Cancel();
}

AddressList* ScannerWidget::GetAddressList() const
{
    return Addresses;
}

void ScannerWidget::OnProcessAttached(const ProcessInfo& Info)
{
    Q_UNUSED(Info);
    FirstScanBtn->setEnabled(true);
    Addresses->UpdateValues(CoreRef);
}

void ScannerWidget::OnProcessDetached()
{
    if (ScanInProgress) {
        Engine->Cancel();
        ScanInProgress = false;
    }
    Engine->Reset();
    ResultsTable->setRowCount(0);
    FoundLabel->setText("Found: 0");
    ScanProgress->setValue(0);
    FirstScanBtn->setEnabled(true);
    NextScanBtn->setEnabled(false);
}

void ScannerWidget::OnFirstScan()
{
    if (ScanInProgress)
        return;

    if (!CoreRef->IsAttached()) {
        QMessageBox::warning(this, "Scanner", "No process attached.");
        return;
    }

    ScanInProgress = true;
    FirstScanBtn->setEnabled(false);
    NextScanBtn->setEnabled(false);
    NewScanBtn->setEnabled(false);
    ScanProgress->setValue(0);
    ResultsTable->setRowCount(0);

    ScanType SelectedScanType = GetSelectedScanType();
    ValueType SelectedValueType = GetSelectedValueType();
    QVariant Val = ParseValue(ValueInput->text());
    QVariant Val2 = ParseValue2(Value2Input->text());

    Engine->StartFirstScan(CoreRef, SelectedScanType, SelectedValueType, Val, Val2);
}

void ScannerWidget::OnNextScan()
{
    if (ScanInProgress)
        return;

    if (!CoreRef->IsAttached()) {
        QMessageBox::warning(this, "Scanner", "No process attached.");
        return;
    }

    ScanInProgress = true;
    FirstScanBtn->setEnabled(false);
    NextScanBtn->setEnabled(false);
    NewScanBtn->setEnabled(false);
    ScanProgress->setValue(0);

    ScanType SelectedScanType = GetSelectedScanType();
    QVariant Val = ParseValue(ValueInput->text());
    QVariant Val2 = ParseValue2(Value2Input->text());

    Engine->StartNextScan(CoreRef, SelectedScanType, Val, Val2);
}

void ScannerWidget::OnNewScan()
{
    if (ScanInProgress) {
        Engine->Cancel();
        ScanInProgress = false;
    }

    Engine->Reset();
    ResultsTable->setRowCount(0);
    FoundLabel->setText("Found: 0");
    ScanProgress->setValue(0);
    FirstScanBtn->setEnabled(true);
    NextScanBtn->setEnabled(false);
    ValueInput->clear();
    Value2Input->clear();
}

void ScannerWidget::OnScanTypeChanged(int Index)
{
    bool IsBetween = (Index == 3);
    Value2Label->setVisible(IsBetween);
    Value2Input->setVisible(IsBetween);

    bool NeedsValue = (Index < 4);
    ValueInput->setEnabled(NeedsValue);
}

void ScannerWidget::OnScanProgressUpdate(int Percent)
{
    ScanProgress->setValue(Percent);
}

void ScannerWidget::OnScanFinished(int Count)
{
    ScanInProgress = false;
    FirstScanBtn->setEnabled(false);
    NextScanBtn->setEnabled(true);
    NewScanBtn->setEnabled(true);
    FoundLabel->setText(QString("Found: %1").arg(Count));
    ScanProgress->setValue(100);

    PopulateResults();
}

void ScannerWidget::PopulateResults()
{
    const auto& Results = Engine->GetResults();
    ValueType CurrentType = GetSelectedValueType();
    int DisplayCount = qMin(Results.size(), static_cast<qsizetype>(10000));

    ResultsTable->setRowCount(0);
    ResultsTable->setSortingEnabled(false);
    ResultsTable->setRowCount(DisplayCount);

    for (int I = 0; I < DisplayCount; ++I) {
        const auto& Result = Results[I];

        auto* AddrItem = new QTableWidgetItem(FormatAddress(Result.Addr));
        AddrItem->setData(Qt::UserRole, QVariant::fromValue(Result.Addr));
        ResultsTable->setItem(I, 0, AddrItem);

        ResultsTable->setItem(I, 1, new QTableWidgetItem(FormatValueBytes(Result.Value, CurrentType)));
        ResultsTable->setItem(I, 2, new QTableWidgetItem(FormatValueBytes(Result.PreviousValue, CurrentType)));
    }

    ResultsTable->setSortingEnabled(true);
}

void ScannerWidget::OnResultDoubleClicked(int Row, int Column)
{
    Q_UNUSED(Column);
    AddSelectedToAddressList();
}

void ScannerWidget::OnResultContextMenu(const QPoint& Pos)
{
    QTableWidgetItem* Item = ResultsTable->itemAt(Pos);
    if (!Item)
        return;

    QMenu ContextMenu(this);
    QAction* AddAction = ContextMenu.addAction("Add to Address List");

    QAction* Selected = ContextMenu.exec(ResultsTable->viewport()->mapToGlobal(Pos));
    if (Selected == AddAction) {
        AddSelectedToAddressList();
    }
}

void ScannerWidget::AddSelectedToAddressList()
{
    int Row = ResultsTable->currentRow();
    if (Row < 0)
        return;

    QTableWidgetItem* AddrItem = ResultsTable->item(Row, 0);
    if (!AddrItem)
        return;

    Address Addr = AddrItem->data(Qt::UserRole).toULongLong();
    ValueType Type = GetSelectedValueType();

    const auto& Results = Engine->GetResults();
    QByteArray CurrentValue;
    if (Row < Results.size()) {
        CurrentValue = Results[Row].Value;
    }

    AddressEntry Entry;
    Entry.Label = FormatAddress(Addr);
    Entry.Addr = Addr;
    Entry.Type = Type;
    Entry.CurrentValue = CurrentValue;
    Entry.Frozen = false;
    Entry.FrozenValue = CurrentValue;

    Addresses->AddEntry(Entry);
}

void ScannerWidget::OnSaveList()
{
    QString FilePath = QFileDialog::getSaveFileName(this, "Save Address List", QString(), "JSON Files (*.json);;All Files (*)");
    if (FilePath.isEmpty())
        return;

    Addresses->SaveToJson(FilePath);
}

void ScannerWidget::OnLoadList()
{
    QString FilePath = QFileDialog::getOpenFileName(this, "Load Address List", QString(), "JSON Files (*.json);;All Files (*)");
    if (FilePath.isEmpty())
        return;

    Addresses->LoadFromJson(FilePath, CoreRef);
}

QVariant ScannerWidget::ParseValue(const QString& Text)
{
    if (Text.isEmpty())
        return QVariant();

    ValueType Type = GetSelectedValueType();

    switch (Type) {
    case ValueType::Byte:
        return QVariant(static_cast<uint8_t>(Text.toUInt()));
    case ValueType::Int16:
        return QVariant(static_cast<int16_t>(Text.toShort()));
    case ValueType::Int32:
        return QVariant(Text.toInt());
    case ValueType::Int64:
        return QVariant(Text.toLongLong());
    case ValueType::Float:
        return QVariant(Text.toFloat());
    case ValueType::Double:
        return QVariant(Text.toDouble());
    case ValueType::String:
        return QVariant(Text);
    case ValueType::ByteArray:
        return QVariant(Text);
    case ValueType::Pointer:
        return QVariant(Text.toULongLong(nullptr, 16));
    }

    return QVariant();
}

QVariant ScannerWidget::ParseValue2(const QString& Text)
{
    if (Text.isEmpty())
        return QVariant();

    return ParseValue(Text);
}

ValueType ScannerWidget::GetSelectedValueType() const
{
    switch (ValueTypeCombo->currentIndex()) {
    case 0: return ValueType::Byte;
    case 1: return ValueType::Int16;
    case 2: return ValueType::Int32;
    case 3: return ValueType::Int64;
    case 4: return ValueType::Float;
    case 5: return ValueType::Double;
    case 6: return ValueType::String;
    case 7: return ValueType::ByteArray;
    default: return ValueType::Int32;
    }
}

ScanType ScannerWidget::GetSelectedScanType() const
{
    switch (ScanTypeCombo->currentIndex()) {
    case 0: return ScanType::Exact;
    case 1: return ScanType::GreaterThan;
    case 2: return ScanType::LessThan;
    case 3: return ScanType::Between;
    case 4: return ScanType::Unknown;
    case 5: return ScanType::Changed;
    case 6: return ScanType::Unchanged;
    default: return ScanType::Exact;
    }
}

QString ScannerWidget::FormatAddress(Address Addr) const
{
    return QString::asprintf("0x%016llX", static_cast<unsigned long long>(Addr));
}

QString ScannerWidget::FormatValueBytes(const QByteArray& Data, ValueType Type) const
{
    if (Data.isEmpty())
        return QString();

    return AddressList::FormatValue(Data, Type);
}

}
