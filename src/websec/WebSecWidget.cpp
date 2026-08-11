#include "WebSecWidget.h"
#include "HttpProxy.h"
#include "RepeaterWidget.h"
#include "IntruderWidget.h"
#include "DecoderWidget.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QHeaderView>
#include <QFont>
#include <QUrl>
#include <QMenu>
#include <QAction>

namespace Fidra {

WebSecWidget::WebSecWidget(QWidget* Parent)
    : QWidget(Parent)
    , CoreRef(nullptr)
    , MainTabs(nullptr)
    , ProxyTab(nullptr)
    , Proxy(nullptr)
    , HistoryTable(nullptr)
    , RequestViewer(nullptr)
    , ResponseViewer(nullptr)
    , ProxyToggleButton(nullptr)
    , PortSpinBox(nullptr)
    , ProxyStatusLabel(nullptr)
    , Repeater(nullptr)
    , Intruder(nullptr)
    , Decoder(nullptr) {

    QVBoxLayout* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(0, 0, 0, 0);

    MainTabs = new QTabWidget(this);
    MainLayout->addWidget(MainTabs);

    SetupProxyTab();
    SetupRepeaterTab();
    SetupIntruderTab();
    SetupDecoderTab();
}

WebSecWidget::~WebSecWidget() {
    StopProxy();
}

void WebSecWidget::SetCore(ICore* Core) {
    CoreRef = Core;
}

void WebSecWidget::StopProxy() {
    if (Proxy && Proxy->IsRunning()) {
        Proxy->StopProxy();
        ProxyToggleButton->setText(QStringLiteral("Start Proxy"));
        ProxyStatusLabel->setText(QStringLiteral("Stopped"));
        ProxyStatusLabel->setStyleSheet(QStringLiteral("color: #f44336;"));
    }
}

void WebSecWidget::ToggleProxy() {
    OnProxyToggle();
}

void WebSecWidget::AddRepeaterTab() {
    if (Repeater) {
        Repeater->AddEmptyTab();
        MainTabs->setCurrentIndex(1);
    }
}

void WebSecWidget::SetupProxyTab() {
    ProxyTab = new QWidget(this);
    QVBoxLayout* Layout = new QVBoxLayout(ProxyTab);
    Layout->setContentsMargins(4, 4, 4, 4);
    Layout->setSpacing(4);

    QHBoxLayout* ControlLayout = new QHBoxLayout();

    ProxyToggleButton = new QPushButton(QStringLiteral("Start Proxy"), this);
    ProxyToggleButton->setFixedWidth(120);
    ProxyToggleButton->setStyleSheet(QStringLiteral("QPushButton { background-color: #4caf50; color: white; font-weight: bold; padding: 6px; border-radius: 3px; } QPushButton:hover { background-color: #66bb6a; }"));

    QLabel* PortLabel = new QLabel(QStringLiteral("Port:"), this);
    PortSpinBox = new QSpinBox(this);
    PortSpinBox->setRange(1, 65535);
    PortSpinBox->setValue(8080);
    PortSpinBox->setFixedWidth(80);

    ProxyStatusLabel = new QLabel(QStringLiteral("Stopped"), this);
    ProxyStatusLabel->setStyleSheet(QStringLiteral("color: #f44336; font-weight: bold;"));

    QPushButton* ClearButton = new QPushButton(QStringLiteral("Clear History"), this);

    ControlLayout->addWidget(ProxyToggleButton);
    ControlLayout->addSpacing(8);
    ControlLayout->addWidget(PortLabel);
    ControlLayout->addWidget(PortSpinBox);
    ControlLayout->addSpacing(16);
    ControlLayout->addWidget(ProxyStatusLabel);
    ControlLayout->addStretch();
    ControlLayout->addWidget(ClearButton);
    Layout->addLayout(ControlLayout);

    QSplitter* MainSplitter = new QSplitter(Qt::Vertical, this);

    HistoryTable = new QTableWidget(this);
    HistoryTable->setColumnCount(7);
    HistoryTable->setHorizontalHeaderLabels({
        QStringLiteral("#"),
        QStringLiteral("Method"),
        QStringLiteral("URL"),
        QStringLiteral("Status"),
        QStringLiteral("Length"),
        QStringLiteral("Time (ms)"),
        QStringLiteral("Content-Type")
    });
    HistoryTable->horizontalHeader()->setStretchLastSection(true);
    HistoryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    HistoryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    HistoryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    HistoryTable->setAlternatingRowColors(true);
    HistoryTable->verticalHeader()->setVisible(false);
    HistoryTable->setColumnWidth(0, 50);
    HistoryTable->setColumnWidth(1, 70);
    HistoryTable->setColumnWidth(2, 400);
    HistoryTable->setColumnWidth(3, 60);
    HistoryTable->setColumnWidth(4, 80);
    HistoryTable->setColumnWidth(5, 80);

    HistoryTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(HistoryTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& Pos) {
        int Row = HistoryTable->rowAt(Pos.y());
        if (Row < 0 || Row >= DisplayedHistory.size()) return;

        QMenu ContextMenu(this);
        QAction* SendRepeater = ContextMenu.addAction(QStringLiteral("Send to Repeater"));
        QAction* SendIntruder = ContextMenu.addAction(QStringLiteral("Send to Intruder"));

        QAction* Selected = ContextMenu.exec(HistoryTable->viewport()->mapToGlobal(Pos));
        if (Selected == SendRepeater) {
            OnSendToRepeater();
        } else if (Selected == SendIntruder) {
            OnSendToIntruder();
        }
    });

    MainSplitter->addWidget(HistoryTable);

    QSplitter* DetailSplitter = new QSplitter(Qt::Horizontal, this);

    QFont MonoFont(QStringLiteral("Consolas"), 10);

    RequestViewer = new QPlainTextEdit(this);
    RequestViewer->setFont(MonoFont);
    RequestViewer->setReadOnly(true);
    RequestViewer->setPlaceholderText(QStringLiteral("Select a request to view details..."));

    ResponseViewer = new QPlainTextEdit(this);
    ResponseViewer->setFont(MonoFont);
    ResponseViewer->setReadOnly(true);
    ResponseViewer->setPlaceholderText(QStringLiteral("Response will appear here..."));

    DetailSplitter->addWidget(RequestViewer);
    DetailSplitter->addWidget(ResponseViewer);
    DetailSplitter->setStretchFactor(0, 1);
    DetailSplitter->setStretchFactor(1, 1);

    MainSplitter->addWidget(DetailSplitter);
    MainSplitter->setStretchFactor(0, 2);
    MainSplitter->setStretchFactor(1, 1);

    Layout->addWidget(MainSplitter, 1);

    Proxy = new HttpProxy(this);
    connect(Proxy, &HttpProxy::RequestCaptured, this, &WebSecWidget::OnRequestCaptured);
    connect(ProxyToggleButton, &QPushButton::clicked, this, &WebSecWidget::OnProxyToggle);
    connect(HistoryTable, &QTableWidget::itemSelectionChanged, this, &WebSecWidget::OnHistoryItemSelected);
    connect(ClearButton, &QPushButton::clicked, this, &WebSecWidget::OnClearHistory);

    MainTabs->addTab(ProxyTab, QStringLiteral("Proxy"));
}

void WebSecWidget::SetupRepeaterTab() {
    Repeater = new RepeaterWidget(this);
    MainTabs->addTab(Repeater, QStringLiteral("Repeater"));
}

void WebSecWidget::SetupIntruderTab() {
    Intruder = new IntruderWidget(this);
    MainTabs->addTab(Intruder, QStringLiteral("Intruder"));
}

void WebSecWidget::SetupDecoderTab() {
    Decoder = new DecoderWidget(this);
    MainTabs->addTab(Decoder, QStringLiteral("Decoder"));
}

void WebSecWidget::OnProxyToggle() {
    if (Proxy->IsRunning()) {
        StopProxy();
    } else {
        quint16 Port = static_cast<quint16>(PortSpinBox->value());
        if (Proxy->StartProxy(Port)) {
            ProxyToggleButton->setText(QStringLiteral("Stop Proxy"));
            ProxyToggleButton->setStyleSheet(QStringLiteral("QPushButton { background-color: #f44336; color: white; font-weight: bold; padding: 6px; border-radius: 3px; } QPushButton:hover { background-color: #e53935; }"));
            ProxyStatusLabel->setText(QStringLiteral("Listening on port %1").arg(Port));
            ProxyStatusLabel->setStyleSheet(QStringLiteral("color: #4caf50; font-weight: bold;"));
            PortSpinBox->setEnabled(false);
        } else {
            ProxyStatusLabel->setText(QStringLiteral("Failed to start"));
            ProxyStatusLabel->setStyleSheet(QStringLiteral("color: #f44336; font-weight: bold;"));
        }
    }
}

void WebSecWidget::OnRequestCaptured(const HttpRequest& Request) {
    DisplayedHistory.append(Request);
    UpdateHistoryTable(Request);
}

void WebSecWidget::OnHistoryItemSelected() {
    int Row = HistoryTable->currentRow();
    if (Row < 0 || Row >= DisplayedHistory.size()) {
        RequestViewer->clear();
        ResponseViewer->clear();
        return;
    }

    const HttpRequest& Req = DisplayedHistory[Row];

    QString ReqText;
    QUrl ParsedUrl(Req.Url);
    QString Path = ParsedUrl.path();
    if (Path.isEmpty()) Path = "/";
    if (ParsedUrl.hasQuery()) {
        Path += "?" + ParsedUrl.query();
    }

    ReqText += Req.Method + " " + Path + " HTTP/1.1\r\n";
    for (auto It = Req.Headers.constBegin(); It != Req.Headers.constEnd(); ++It) {
        ReqText += It.key() + ": " + It.value() + "\r\n";
    }
    ReqText += "\r\n";
    if (!Req.Body.isEmpty()) {
        ReqText += QString::fromUtf8(Req.Body);
    }
    RequestViewer->setPlainText(ReqText);

    QString RespText;
    RespText += QStringLiteral("HTTP/1.1 %1\r\n").arg(Req.StatusCode);
    for (auto It = Req.ResponseHeaders.constBegin(); It != Req.ResponseHeaders.constEnd(); ++It) {
        RespText += It.key() + ": " + It.value() + "\r\n";
    }
    RespText += "\r\n";
    RespText += QString::fromUtf8(Req.ResponseBody);
    ResponseViewer->setPlainText(RespText);
}

void WebSecWidget::OnSendToRepeater() {
    int Row = HistoryTable->currentRow();
    if (Row < 0 || Row >= DisplayedHistory.size()) return;

    if (Repeater) {
        Repeater->AddTab(DisplayedHistory[Row]);
        MainTabs->setCurrentIndex(1);
    }
}

void WebSecWidget::OnSendToIntruder() {
    int Row = HistoryTable->currentRow();
    if (Row < 0 || Row >= DisplayedHistory.size()) return;

    if (Intruder) {
        Intruder->SetRequest(DisplayedHistory[Row]);
        MainTabs->setCurrentIndex(2);
    }
}

void WebSecWidget::OnClearHistory() {
    DisplayedHistory.clear();
    HistoryTable->setRowCount(0);
    RequestViewer->clear();
    ResponseViewer->clear();
    Proxy->ClearHistory();
}

void WebSecWidget::UpdateHistoryTable(const HttpRequest& Request) {
    int Row = HistoryTable->rowCount();
    HistoryTable->insertRow(Row);

    HistoryTable->setItem(Row, 0, new QTableWidgetItem(QString::number(Row + 1)));

    QTableWidgetItem* MethodItem = new QTableWidgetItem(Request.Method);
    if (Request.Method == "GET") {
        MethodItem->setForeground(QColor(0x4c, 0xaf, 0x50));
    } else if (Request.Method == "POST") {
        MethodItem->setForeground(QColor(0xff, 0x98, 0x00));
    } else if (Request.Method == "PUT" || Request.Method == "PATCH") {
        MethodItem->setForeground(QColor(0x21, 0x96, 0xf3));
    } else if (Request.Method == "DELETE") {
        MethodItem->setForeground(QColor(0xf4, 0x43, 0x36));
    } else if (Request.Method == "CONNECT") {
        MethodItem->setForeground(QColor(0x9c, 0x27, 0xb0));
    }
    HistoryTable->setItem(Row, 1, MethodItem);

    QUrl ParsedUrl(Request.Url);
    QString DisplayUrl = ParsedUrl.host() + ParsedUrl.path();
    if (ParsedUrl.hasQuery()) {
        DisplayUrl += "?" + ParsedUrl.query();
    }
    HistoryTable->setItem(Row, 2, new QTableWidgetItem(DisplayUrl));

    QTableWidgetItem* StatusItem = new QTableWidgetItem(QString::number(Request.StatusCode));
    if (Request.StatusCode >= 200 && Request.StatusCode < 300) {
        StatusItem->setForeground(QColor(0x4c, 0xaf, 0x50));
    } else if (Request.StatusCode >= 300 && Request.StatusCode < 400) {
        StatusItem->setForeground(QColor(0xff, 0x98, 0x00));
    } else if (Request.StatusCode >= 400) {
        StatusItem->setForeground(QColor(0xf4, 0x43, 0x36));
    }
    HistoryTable->setItem(Row, 3, StatusItem);

    HistoryTable->setItem(Row, 4, new QTableWidgetItem(QString::number(Request.ResponseBody.size())));
    HistoryTable->setItem(Row, 5, new QTableWidgetItem(QString::number(Request.ElapsedMs)));

    QString ContentType = Request.ResponseHeaders.value("Content-Type", Request.ResponseHeaders.value("content-type", ""));
    HistoryTable->setItem(Row, 6, new QTableWidgetItem(ContentType));

    HistoryTable->scrollToBottom();
}

}
