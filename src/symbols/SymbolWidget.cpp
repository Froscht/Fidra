#include "SymbolWidget.h"
#include "SymbolResolver.h"
#include "../analysis/AnalysisDatabase.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QSet>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTextStream>

namespace Fidra {

SymbolWidget::SymbolWidget(QWidget* Parent, SymbolResolver* Resolver, ICore* Core)
    : QWidget(Parent)
    , CoreRef(Core)
    , ResolverRef(Resolver)
    , DatabaseRef(nullptr)
    , SymbolTable(nullptr)
    , LoadButton(nullptr)
    , FetchButton(nullptr)
    , ExportButton(nullptr)
    , SetServerButton(nullptr)
    , TestButton(nullptr)
    , FilterEdit(nullptr)
    , ServerUrlEdit(nullptr)
    , StatsLabel(nullptr)
{
    SetupUi();

    connect(ResolverRef, &SymbolResolver::SymbolsLoaded, this, [this](int) {
        RefreshTable();
    });
    connect(ResolverRef, &SymbolResolver::FetchComplete, this, [this](const QString& Module, int Count) {
        if (CoreRef) {
            CoreRef->Log(QStringLiteral("Fetched %1 symbols for %2").arg(Count).arg(Module));
        }
        RefreshTable();
    });
    connect(ResolverRef, &SymbolResolver::FetchError, this, [this](const QString& Module, const QString& Error) {
        if (CoreRef) {
            CoreRef->Log(QStringLiteral("Symbol fetch error [%1]: %2").arg(Module, Error), LogLevel::Error);
        }
        QMessageBox::warning(this, QStringLiteral("Fetch Error"),
                             QStringLiteral("Failed to fetch symbols for '%1':\n%2").arg(Module, Error));
    });
}

void SymbolWidget::SetDatabase(AnalysisDatabase* Db)
{
    DatabaseRef = Db;
}

void SymbolWidget::SetupUi()
{
    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(4, 4, 4, 4);
    MainLayout->setSpacing(4);

    auto* TopLayout = new QHBoxLayout();
    TopLayout->setSpacing(4);

    LoadButton = new QPushButton(QStringLiteral("Load .sym"), this);
    FetchButton = new QPushButton(QStringLiteral("Fetch"), this);
    ExportButton = new QPushButton(QStringLiteral("Export"), this);

    TopLayout->addWidget(LoadButton);
    TopLayout->addWidget(FetchButton);
    TopLayout->addWidget(ExportButton);
    TopLayout->addStretch();

    MainLayout->addLayout(TopLayout);

    auto* ServerLayout = new QHBoxLayout();
    ServerLayout->setSpacing(4);

    auto* ServerLabel = new QLabel(QStringLiteral("Server:"), this);
    ServerUrlEdit = new QLineEdit(this);
    ServerUrlEdit->setPlaceholderText(QStringLiteral("http://symbols.example.com"));
    SetServerButton = new QPushButton(QStringLiteral("Set"), this);
    TestButton = new QPushButton(QStringLiteral("Test"), this);

    ServerLayout->addWidget(ServerLabel);
    ServerLayout->addWidget(ServerUrlEdit, 1);
    ServerLayout->addWidget(SetServerButton);
    ServerLayout->addWidget(TestButton);

    MainLayout->addLayout(ServerLayout);

    FilterEdit = new QLineEdit(this);
    FilterEdit->setPlaceholderText(QStringLiteral("Filter symbols..."));
    MainLayout->addWidget(FilterEdit);

    SymbolTable = new QTableWidget(this);
    SymbolTable->setColumnCount(5);
    SymbolTable->setHorizontalHeaderLabels({
        QStringLiteral("Address"),
        QStringLiteral("Name"),
        QStringLiteral("Module"),
        QStringLiteral("Source"),
        QStringLiteral("Size")
    });
    SymbolTable->horizontalHeader()->setStretchLastSection(true);
    SymbolTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    SymbolTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    SymbolTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    SymbolTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    SymbolTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    SymbolTable->verticalHeader()->setVisible(false);
    SymbolTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    SymbolTable->setSelectionMode(QAbstractItemView::SingleSelection);
    SymbolTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    SymbolTable->setAlternatingRowColors(true);
    SymbolTable->setSortingEnabled(true);

    MainLayout->addWidget(SymbolTable);

    StatsLabel = new QLabel(QStringLiteral("No symbols loaded"), this);
    MainLayout->addWidget(StatsLabel);

    connect(LoadButton, &QPushButton::clicked, this, &SymbolWidget::OnLoadSymFile);
    connect(FetchButton, &QPushButton::clicked, this, &SymbolWidget::OnFetchSymbols);
    connect(ExportButton, &QPushButton::clicked, this, &SymbolWidget::OnExportSymbols);
    connect(SetServerButton, &QPushButton::clicked, this, &SymbolWidget::OnSetServer);
    connect(TestButton, &QPushButton::clicked, this, &SymbolWidget::OnTestConnection);
    connect(FilterEdit, &QLineEdit::textChanged, this, &SymbolWidget::OnFilterChanged);
}

void SymbolWidget::RefreshTable()
{
    QString Filter = FilterEdit->text();

    QList<SymbolInfo> AllSymbols;
    if (Filter.isEmpty()) {
        AllSymbols = ResolverRef->GetAllSymbols();
    } else {
        AllSymbols = ResolverRef->Search(Filter);
    }

    SymbolTable->setSortingEnabled(false);
    SymbolTable->setRowCount(AllSymbols.size());

    for (int I = 0; I < AllSymbols.size(); ++I) {
        const SymbolInfo& Sym = AllSymbols[I];

        auto* AddrItem = new QTableWidgetItem(
            QStringLiteral("0x%1").arg(Sym.Addr, 16, 16, QLatin1Char('0')));
        AddrItem->setData(Qt::UserRole, QVariant::fromValue(static_cast<qulonglong>(Sym.Addr)));
        SymbolTable->setItem(I, 0, AddrItem);
        SymbolTable->setItem(I, 1, new QTableWidgetItem(Sym.Name));
        SymbolTable->setItem(I, 2, new QTableWidgetItem(Sym.Module));
        SymbolTable->setItem(I, 3, new QTableWidgetItem(Sym.Source));
        SymbolTable->setItem(I, 4, new QTableWidgetItem(
            Sym.Size > 0 ? QString::number(Sym.Size) : QStringLiteral("-")));
    }

    SymbolTable->setSortingEnabled(true);
    UpdateStats();
}

void SymbolWidget::UpdateStats()
{
    QList<SymbolInfo> AllSymbols = ResolverRef->GetAllSymbols();
    QSet<QString> Sources;
    for (const SymbolInfo& Sym : AllSymbols) {
        if (!Sym.Source.isEmpty()) {
            Sources.insert(Sym.Source);
        }
    }

    StatsLabel->setText(QStringLiteral("%1 symbols loaded from %2 sources")
        .arg(ResolverRef->SymbolCount())
        .arg(Sources.size()));
}

void SymbolWidget::OnLoadSymFile()
{
    QString Path = QFileDialog::getOpenFileName(this,
        QStringLiteral("Load Symbol File"),
        QString(),
        QStringLiteral("Symbol Files (*.sym);;All Files (*)"));

    if (Path.isEmpty()) return;

    ResolverRef->LoadFromSymbolFile(Path);

    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Loaded symbols from: %1").arg(Path));
    }
}

void SymbolWidget::OnFetchSymbols()
{
    if (!DatabaseRef) {
        QMessageBox::warning(this, QStringLiteral("No Analysis"),
                             QStringLiteral("Load a binary first before fetching symbols."));
        return;
    }

    BinaryInfo BinInfo = DatabaseRef->GetBinaryInfo();
    QString ModuleName = BinInfo.FileName;
    if (ModuleName.isEmpty()) {
        ModuleName = QInputDialog::getText(this, QStringLiteral("Module Name"),
                                           QStringLiteral("Enter module name:"));
        if (ModuleName.isEmpty()) return;
    }

    QString BuildId = QString::number(BinInfo.TimeDateStamp, 16).toUpper() +
                      QString::number(BinInfo.ImageSize, 16).toUpper();

    ResolverRef->FetchSymbolsAsync(ModuleName, BuildId);
}

void SymbolWidget::OnExportSymbols()
{
    QString Path = QFileDialog::getSaveFileName(this,
        QStringLiteral("Export Symbols"),
        QString(),
        QStringLiteral("Symbol Files (*.sym);;All Files (*)"));

    if (Path.isEmpty()) return;

    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, QStringLiteral("Export Error"),
                             QStringLiteral("Cannot open file for writing: %1").arg(Path));
        return;
    }

    QTextStream Stream(&File);
    QList<SymbolInfo> AllSymbols = ResolverRef->GetAllSymbols();
    for (const SymbolInfo& Sym : AllSymbols) {
        Stream << QString::number(Sym.Addr, 16) << " " << Sym.Name;
        if (Sym.Size > 0) {
            Stream << " " << Sym.Size;
        }
        Stream << "\n";
    }

    File.close();

    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Exported %1 symbols to: %2").arg(AllSymbols.size()).arg(Path));
    }
}

void SymbolWidget::OnSetServer()
{
    QString Url = ServerUrlEdit->text().trimmed();
    if (Url.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Invalid URL"),
                             QStringLiteral("Enter a symbol server URL."));
        return;
    }

    ResolverRef->SetSymbolServer(Url);

    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Symbol server set to: %1").arg(Url));
    }
}

void SymbolWidget::OnTestConnection()
{
    QString Url = ServerUrlEdit->text().trimmed();
    if (Url.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Invalid URL"),
                             QStringLiteral("Enter a symbol server URL first."));
        return;
    }

    QNetworkAccessManager* TestManager = new QNetworkAccessManager(this);
    QNetworkRequest Request{QUrl(Url)};

    QNetworkReply* Reply = TestManager->get(Request);
    connect(Reply, &QNetworkReply::finished, this, [this, Reply, TestManager]() {
        Reply->deleteLater();
        TestManager->deleteLater();

        if (Reply->error() == QNetworkReply::NoError) {
            QMessageBox::information(this, QStringLiteral("Connection Test"),
                                     QStringLiteral("Connection successful."));
        } else {
            QMessageBox::warning(this, QStringLiteral("Connection Test"),
                                 QStringLiteral("Connection failed: %1").arg(Reply->errorString()));
        }
    });
}

void SymbolWidget::OnFilterChanged(const QString& Text)
{
    Q_UNUSED(Text);
    RefreshTable();
}

}
