#include "McpWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QHeaderView>
#include <QFont>
#include <QDateTime>

namespace Fidra {

McpWidget::McpWidget(QWidget* Parent)
    : QWidget(Parent)
    , ServerRef(nullptr)
    , ToolRegistryRef(nullptr)
    , StatusLabel(nullptr)
    , PortLabel(nullptr)
    , StartStopButton(nullptr)
    , PortSpinBox(nullptr)
    , StdioCheckBox(nullptr)
    , ClientList(nullptr)
    , RequestLogView(nullptr)
    , ToolTable(nullptr)
    , ClearLogButton(nullptr)
    , ClientCountLabel(nullptr)
    , RequestCountLabel(nullptr)
    , TotalRequests(0) {
    SetupUi();
}

McpWidget::~McpWidget() {
}

void McpWidget::SetupUi() {
    QVBoxLayout* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(6, 6, 6, 6);
    MainLayout->setSpacing(4);

    QGroupBox* ServerGroup = new QGroupBox(QStringLiteral("Server Control"), this);
    QVBoxLayout* ServerLayout = new QVBoxLayout(ServerGroup);

    QHBoxLayout* StatusRow = new QHBoxLayout();
    StatusLabel = new QLabel(QStringLiteral("Stopped"), this);
    StatusLabel->setStyleSheet(QStringLiteral("font-weight: bold; color: #e74c3c;"));
    StatusRow->addWidget(new QLabel(QStringLiteral("Status:"), this));
    StatusRow->addWidget(StatusLabel);
    StatusRow->addStretch();

    PortLabel = new QLabel(QStringLiteral("--"), this);
    StatusRow->addWidget(new QLabel(QStringLiteral("Active Port:"), this));
    StatusRow->addWidget(PortLabel);
    ServerLayout->addLayout(StatusRow);

    QHBoxLayout* ControlRow = new QHBoxLayout();
    ControlRow->addWidget(new QLabel(QStringLiteral("Port:"), this));
    PortSpinBox = new QSpinBox(this);
    PortSpinBox->setRange(1024, 65535);
    PortSpinBox->setValue(3333);
    ControlRow->addWidget(PortSpinBox);

    StartStopButton = new QPushButton(QStringLiteral("Start Server"), this);
    StartStopButton->setFixedWidth(120);
    ControlRow->addWidget(StartStopButton);

    StdioCheckBox = new QCheckBox(QStringLiteral("Enable stdio transport"), this);
    ControlRow->addWidget(StdioCheckBox);

    ControlRow->addStretch();
    ServerLayout->addLayout(ControlRow);

    MainLayout->addWidget(ServerGroup);

    connect(StartStopButton, &QPushButton::clicked, this, &McpWidget::OnStartStopClicked);
    connect(StdioCheckBox, &QCheckBox::toggled, this, &McpWidget::OnStdioToggled);

    QSplitter* Splitter = new QSplitter(Qt::Horizontal, this);

    QWidget* LeftPanel = new QWidget(Splitter);
    QVBoxLayout* LeftLayout = new QVBoxLayout(LeftPanel);
    LeftLayout->setContentsMargins(0, 0, 0, 0);

    QGroupBox* ClientGroup = new QGroupBox(QStringLiteral("Connected Clients"), LeftPanel);
    QVBoxLayout* ClientLayout = new QVBoxLayout(ClientGroup);
    ClientCountLabel = new QLabel(QStringLiteral("0 connected"), ClientGroup);
    ClientLayout->addWidget(ClientCountLabel);
    ClientList = new QListWidget(ClientGroup);
    ClientList->setFont(QFont(QStringLiteral("Consolas"), 9));
    ClientList->setMaximumHeight(120);
    ClientLayout->addWidget(ClientList);
    LeftLayout->addWidget(ClientGroup);

    QGroupBox* LogGroup = new QGroupBox(QStringLiteral("Request Log"), LeftPanel);
    QVBoxLayout* LogLayout = new QVBoxLayout(LogGroup);
    QHBoxLayout* LogControlRow = new QHBoxLayout();
    RequestCountLabel = new QLabel(QStringLiteral("0 requests"), LogGroup);
    LogControlRow->addWidget(RequestCountLabel);
    LogControlRow->addStretch();
    ClearLogButton = new QPushButton(QStringLiteral("Clear"), LogGroup);
    ClearLogButton->setFixedWidth(60);
    connect(ClearLogButton, &QPushButton::clicked, this, &McpWidget::OnClearLogClicked);
    LogControlRow->addWidget(ClearLogButton);
    LogLayout->addLayout(LogControlRow);

    RequestLogView = new QTextEdit(LogGroup);
    RequestLogView->setReadOnly(true);
    RequestLogView->setFont(QFont(QStringLiteral("Consolas"), 9));
    LogLayout->addWidget(RequestLogView);
    LeftLayout->addWidget(LogGroup);

    Splitter->addWidget(LeftPanel);

    QWidget* RightPanel = new QWidget(Splitter);
    QVBoxLayout* RightLayout = new QVBoxLayout(RightPanel);
    RightLayout->setContentsMargins(0, 0, 0, 0);

    QGroupBox* ToolGroup = new QGroupBox(QStringLiteral("Tool Registry"), RightPanel);
    QVBoxLayout* ToolLayout = new QVBoxLayout(ToolGroup);

    ToolTable = new QTableWidget(ToolGroup);
    ToolTable->setColumnCount(3);
    ToolTable->setHorizontalHeaderLabels({
        QStringLiteral("Tool Name"),
        QStringLiteral("Description"),
        QStringLiteral("Enabled")
    });
    ToolTable->horizontalHeader()->setStretchLastSection(false);
    ToolTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ToolTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ToolTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ToolTable->verticalHeader()->setVisible(false);
    ToolTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ToolTable->setSelectionMode(QAbstractItemView::SingleSelection);
    ToolTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ToolTable->setFont(QFont(QStringLiteral("Consolas"), 9));

    ToolLayout->addWidget(ToolTable);
    RightLayout->addWidget(ToolGroup);

    Splitter->addWidget(RightPanel);
    Splitter->setStretchFactor(0, 3);
    Splitter->setStretchFactor(1, 2);

    MainLayout->addWidget(Splitter, 1);
}

void McpWidget::SetServer(McpServer* Server) {
    if (ServerRef) {
        disconnect(ServerRef, nullptr, this, nullptr);
    }

    ServerRef = Server;

    if (ServerRef) {
        connect(ServerRef, &McpServer::TcpStarted, this, &McpWidget::OnServerStarted);
        connect(ServerRef, &McpServer::TcpStopped, this, &McpWidget::OnServerStopped);
        connect(ServerRef, &McpServer::ClientConnected, this, &McpWidget::OnClientConnected);
        connect(ServerRef, &McpServer::ClientDisconnected, this, &McpWidget::OnClientDisconnected);
        connect(ServerRef, &McpServer::RequestReceived, this, &McpWidget::OnRequestReceived);
        connect(ServerRef, &McpServer::ResponseSent, this, &McpWidget::OnResponseSent);
        connect(ServerRef, &McpServer::LogMessage, this, &McpWidget::OnLogMessage);
    }

    UpdateServerStatus();
}

void McpWidget::SetToolRegistry(McpToolRegistry* Registry) {
    if (ToolRegistryRef) {
        disconnect(ToolRegistryRef, nullptr, this, nullptr);
    }

    ToolRegistryRef = Registry;

    if (ToolRegistryRef) {
        connect(ToolRegistryRef, &McpToolRegistry::ToolRegistered, this, [this](const QString&) {
            RefreshToolTable();
        });
        connect(ToolRegistryRef, &McpToolRegistry::ToolEnabledChanged, this, &McpWidget::OnToolEnabledChanged);
    }

    RefreshToolTable();
}

void McpWidget::OnStartStopClicked() {
    if (!ServerRef) return;

    if (ServerRef->IsTcpRunning()) {
        ServerRef->StopTcp();
    } else {
        uint16_t Port = static_cast<uint16_t>(PortSpinBox->value());
        ServerRef->StartTcp(Port);
    }
}

void McpWidget::OnStdioToggled(bool Checked) {
    if (!ServerRef) return;

    if (Checked) {
        ServerRef->StartStdio();
    } else {
        ServerRef->StopStdio();
    }
}

void McpWidget::OnClearLogClicked() {
    RequestLogView->clear();
    TotalRequests = 0;
    RequestCountLabel->setText(QStringLiteral("0 requests"));
    if (ServerRef) {
        ServerRef->ClearRequestLog();
    }
}

void McpWidget::OnServerStarted(uint16_t Port) {
    UpdateServerStatus();
    PortLabel->setText(QString::number(Port));
}

void McpWidget::OnServerStopped() {
    UpdateServerStatus();
    PortLabel->setText(QStringLiteral("--"));
    ClientList->clear();
    ClientCountLabel->setText(QStringLiteral("0 connected"));
}

void McpWidget::OnClientConnected(const QString& Address) {
    ClientList->addItem(Address);
    RefreshClientList();
}

void McpWidget::OnClientDisconnected(const QString& Address) {
    QList<QListWidgetItem*> Items = ClientList->findItems(Address, Qt::MatchExactly);
    for (QListWidgetItem* Item : Items) {
        delete ClientList->takeItem(ClientList->row(Item));
    }
    RefreshClientList();
}

void McpWidget::OnRequestReceived(const QString& ClientAddress, const QString& Method) {
    ++TotalRequests;
    RequestCountLabel->setText(QString::number(TotalRequests) + QStringLiteral(" requests"));

    QString Timestamp = QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz"));
    QString LogLine = QStringLiteral("<span style='color:#3498db;'>[%1]</span> "
                                      "<span style='color:#2ecc71;'>%2</span> "
                                      "<b>%3</b>")
                          .arg(Timestamp, ClientAddress, Method);
    RequestLogView->append(LogLine);
}

void McpWidget::OnResponseSent(const QString& ClientAddress, const QString& Method, bool IsError) {
    QString Timestamp = QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz"));
    QString StatusColor = IsError ? QStringLiteral("#e74c3c") : QStringLiteral("#2ecc71");
    QString StatusText = IsError ? QStringLiteral("ERROR") : QStringLiteral("OK");

    QString LogLine = QStringLiteral("<span style='color:#3498db;'>[%1]</span> "
                                      "<span style='color:#95a5a6;'>%2</span> "
                                      "%3 -> <span style='color:%4;'>%5</span>")
                          .arg(Timestamp, ClientAddress, Method, StatusColor, StatusText);
    RequestLogView->append(LogLine);
}

void McpWidget::OnLogMessage(const QString& Message) {
    QString Timestamp = QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz"));
    QString LogLine = QStringLiteral("<span style='color:#3498db;'>[%1]</span> "
                                      "<span style='color:#f39c12;'>%2</span>")
                          .arg(Timestamp, Message);
    RequestLogView->append(LogLine);
}

void McpWidget::OnToolEnabledChanged(const QString& Name, bool Enabled) {
    Q_UNUSED(Name);
    Q_UNUSED(Enabled);
    RefreshToolTable();
}

void McpWidget::RefreshToolTable() {
    if (!ToolRegistryRef) return;

    QList<McpToolDefinition> AllTools = ToolRegistryRef->GetAllTools();

    ToolTable->setRowCount(AllTools.size());

    for (int I = 0; I < AllTools.size(); ++I) {
        const McpToolDefinition& Def = AllTools[I];

        QTableWidgetItem* NameItem = new QTableWidgetItem(Def.Name);
        NameItem->setFont(QFont(QStringLiteral("Consolas"), 9));
        ToolTable->setItem(I, 0, NameItem);

        QTableWidgetItem* DescItem = new QTableWidgetItem(Def.Description);
        ToolTable->setItem(I, 1, DescItem);

        QWidget* CheckContainer = new QWidget(ToolTable);
        QHBoxLayout* CheckLayout = new QHBoxLayout(CheckContainer);
        CheckLayout->setContentsMargins(0, 0, 0, 0);
        CheckLayout->setAlignment(Qt::AlignCenter);
        QCheckBox* EnabledCheck = new QCheckBox(CheckContainer);
        EnabledCheck->setChecked(Def.Enabled);
        CheckLayout->addWidget(EnabledCheck);
        ToolTable->setCellWidget(I, 2, CheckContainer);

        QString ToolName = Def.Name;
        connect(EnabledCheck, &QCheckBox::toggled, this, [this, ToolName](bool Checked) {
            if (ToolRegistryRef) {
                ToolRegistryRef->SetToolEnabled(ToolName, Checked);
            }
        });
    }
}

void McpWidget::RefreshClientList() {
    int Count = ClientList->count();
    ClientCountLabel->setText(QString::number(Count) + QStringLiteral(" connected"));
}

void McpWidget::UpdateServerStatus() {
    if (!ServerRef) {
        StatusLabel->setText(QStringLiteral("No Server"));
        StatusLabel->setStyleSheet(QStringLiteral("font-weight: bold; color: #95a5a6;"));
        StartStopButton->setText(QStringLiteral("Start Server"));
        StartStopButton->setEnabled(false);
        PortSpinBox->setEnabled(false);
        return;
    }

    StartStopButton->setEnabled(true);

    if (ServerRef->IsTcpRunning()) {
        StatusLabel->setText(QStringLiteral("Running"));
        StatusLabel->setStyleSheet(QStringLiteral("font-weight: bold; color: #2ecc71;"));
        StartStopButton->setText(QStringLiteral("Stop Server"));
        PortSpinBox->setEnabled(false);
    } else {
        StatusLabel->setText(QStringLiteral("Stopped"));
        StatusLabel->setStyleSheet(QStringLiteral("font-weight: bold; color: #e74c3c;"));
        StartStopButton->setText(QStringLiteral("Start Server"));
        PortSpinBox->setEnabled(true);
    }
}

}
