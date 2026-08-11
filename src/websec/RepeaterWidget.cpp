#include "RepeaterWidget.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QFont>
#include <QUrl>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QElapsedTimer>
#include <QRegularExpression>
#include <QEventLoop>
#include <QToolBar>
#include <QAction>

namespace Fidra {

SingleRepeaterTab::SingleRepeaterTab(QWidget* Parent)
    : QWidget(Parent)
    , RequestEditor(nullptr)
    , ResponseViewer(nullptr)
    , SendButton(nullptr)
    , StatusLabel(nullptr)
    , TimeLabel(nullptr)
    , SizeLabel(nullptr)
    , NetworkManager(new QNetworkAccessManager(this)) {

    QVBoxLayout* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(4, 4, 4, 4);
    MainLayout->setSpacing(4);

    QHBoxLayout* ToolLayout = new QHBoxLayout();
    SendButton = new QPushButton(QStringLiteral("Send"), this);
    SendButton->setFixedWidth(80);
    SendButton->setStyleSheet(QStringLiteral("QPushButton { background-color: #e8530e; color: white; font-weight: bold; padding: 6px; border-radius: 3px; } QPushButton:hover { background-color: #ff6b2b; }"));

    StatusLabel = new QLabel(this);
    TimeLabel = new QLabel(this);
    SizeLabel = new QLabel(this);

    QFont MonoFont(QStringLiteral("Consolas"), 10);
    StatusLabel->setFont(MonoFont);
    TimeLabel->setFont(MonoFont);
    SizeLabel->setFont(MonoFont);

    ToolLayout->addWidget(SendButton);
    ToolLayout->addSpacing(16);
    ToolLayout->addWidget(StatusLabel);
    ToolLayout->addSpacing(8);
    ToolLayout->addWidget(TimeLabel);
    ToolLayout->addSpacing(8);
    ToolLayout->addWidget(SizeLabel);
    ToolLayout->addStretch();
    MainLayout->addLayout(ToolLayout);

    QSplitter* Splitter = new QSplitter(Qt::Horizontal, this);

    RequestEditor = new QPlainTextEdit(this);
    RequestEditor->setFont(MonoFont);
    RequestEditor->setPlaceholderText(QStringLiteral("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"));
    RequestEditor->setTabStopDistance(40);

    ResponseViewer = new QPlainTextEdit(this);
    ResponseViewer->setFont(MonoFont);
    ResponseViewer->setReadOnly(true);
    ResponseViewer->setPlaceholderText(QStringLiteral("Response will appear here..."));

    Splitter->addWidget(RequestEditor);
    Splitter->addWidget(ResponseViewer);
    Splitter->setStretchFactor(0, 1);
    Splitter->setStretchFactor(1, 1);

    MainLayout->addWidget(Splitter, 1);

    connect(SendButton, &QPushButton::clicked, this, &SingleRepeaterTab::OnSendClicked);
}

SingleRepeaterTab::~SingleRepeaterTab() {
}

void SingleRepeaterTab::SetRequest(const HttpRequest& Request) {
    QString Raw;
    QUrl ParsedUrl(Request.Url);
    QString Path = ParsedUrl.path();
    if (Path.isEmpty()) Path = "/";
    if (ParsedUrl.hasQuery()) {
        Path += "?" + ParsedUrl.query();
    }

    Raw += Request.Method + " " + Path + " HTTP/1.1\r\n";
    Raw += "Host: " + ParsedUrl.host();
    if (ParsedUrl.port(-1) != -1) {
        Raw += ":" + QString::number(ParsedUrl.port());
    }
    Raw += "\r\n";

    for (auto It = Request.Headers.constBegin(); It != Request.Headers.constEnd(); ++It) {
        if (It.key().compare("Host", Qt::CaseInsensitive) == 0) continue;
        Raw += It.key() + ": " + It.value() + "\r\n";
    }

    Raw += "\r\n";
    if (!Request.Body.isEmpty()) {
        Raw += QString::fromUtf8(Request.Body);
    }

    RequestEditor->setPlainText(Raw);
}

void SingleRepeaterTab::SetRawRequest(const QString& Raw) {
    RequestEditor->setPlainText(Raw);
}

void SingleRepeaterTab::OnSendClicked() {
    QString RawText = RequestEditor->toPlainText();
    if (RawText.trimmed().isEmpty()) return;

    SendButton->setEnabled(false);
    StatusLabel->setText(QStringLiteral("Sending..."));
    TimeLabel->clear();
    SizeLabel->clear();
    ResponseViewer->clear();

    HttpRequest Req = ParseRawRequest(RawText);

    QUrl Url(Req.Url);
    if (!Url.isValid() || Url.host().isEmpty()) {
        StatusLabel->setText(QStringLiteral("Invalid URL"));
        SendButton->setEnabled(true);
        return;
    }

    QNetworkRequest NetReq(Url);
    for (auto It = Req.Headers.constBegin(); It != Req.Headers.constEnd(); ++It) {
        NetReq.setRawHeader(It.key().toUtf8(), It.value().toUtf8());
    }

    QElapsedTimer Timer;
    Timer.start();

    QNetworkReply* Reply = nullptr;
    if (Req.Method == "GET") {
        Reply = NetworkManager->get(NetReq);
    } else if (Req.Method == "POST") {
        Reply = NetworkManager->post(NetReq, Req.Body);
    } else if (Req.Method == "PUT") {
        Reply = NetworkManager->put(NetReq, Req.Body);
    } else if (Req.Method == "DELETE") {
        Reply = NetworkManager->deleteResource(NetReq);
    } else if (Req.Method == "HEAD") {
        Reply = NetworkManager->head(NetReq);
    } else if (Req.Method == "PATCH") {
        Reply = NetworkManager->sendCustomRequest(NetReq, Req.Method.toUtf8(), Req.Body);
    } else {
        Reply = NetworkManager->sendCustomRequest(NetReq, Req.Method.toUtf8(), Req.Body);
    }

    if (!Reply) {
        StatusLabel->setText(QStringLiteral("Failed to send request"));
        SendButton->setEnabled(true);
        return;
    }

    connect(Reply, &QNetworkReply::finished, this, [this, Reply, Timer, Req]() mutable {
        qint64 Elapsed = Timer.elapsed();

        HttpRequest Result = Req;
        Result.ElapsedMs = Elapsed;
        Result.StatusCode = Reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        Result.ResponseBody = Reply->readAll();

        QList<QByteArray> RawHeaders = Reply->rawHeaderList();
        for (const QByteArray& Header : RawHeaders) {
            Result.ResponseHeaders[QString::fromUtf8(Header)] = QString::fromUtf8(Reply->rawHeader(Header));
        }

        StatusLabel->setText(QStringLiteral("HTTP %1").arg(Result.StatusCode));
        TimeLabel->setText(QStringLiteral("%1 ms").arg(Result.ElapsedMs));
        SizeLabel->setText(QStringLiteral("%1 bytes").arg(Result.ResponseBody.size()));

        if (Result.StatusCode >= 200 && Result.StatusCode < 300) {
            StatusLabel->setStyleSheet(QStringLiteral("color: #4caf50;"));
        } else if (Result.StatusCode >= 300 && Result.StatusCode < 400) {
            StatusLabel->setStyleSheet(QStringLiteral("color: #ff9800;"));
        } else if (Result.StatusCode >= 400) {
            StatusLabel->setStyleSheet(QStringLiteral("color: #f44336;"));
        } else {
            StatusLabel->setStyleSheet(QString());
        }

        ResponseViewer->setPlainText(FormatResponse(Result));

        TabHistory.append(Result);
        emit RequestSent(Result);

        SendButton->setEnabled(true);
        Reply->deleteLater();
    });
}

HttpRequest SingleRepeaterTab::ParseRawRequest(const QString& Raw) {
    HttpRequest Req;
    Req.StatusCode = 0;
    Req.ElapsedMs = 0;

    int HeaderEnd = Raw.indexOf("\r\n\r\n");
    if (HeaderEnd == -1) {
        HeaderEnd = Raw.indexOf("\n\n");
    }

    QString HeaderSection;
    QString BodySection;
    if (HeaderEnd != -1) {
        HeaderSection = Raw.left(HeaderEnd);
        int SkipLen = Raw.mid(HeaderEnd, 4) == "\r\n\r\n" ? 4 : 2;
        BodySection = Raw.mid(HeaderEnd + SkipLen);
    } else {
        HeaderSection = Raw;
    }

    QStringList Lines = HeaderSection.split(QRegularExpression("\\r?\\n"));
    if (Lines.isEmpty()) return Req;

    QStringList RequestLine = Lines[0].split(' ');
    if (RequestLine.size() >= 2) {
        Req.Method = RequestLine[0].toUpper();
    }

    QString Host;
    quint16 Port = 80;
    QString Scheme = QStringLiteral("http");

    for (int I = 1; I < Lines.size(); ++I) {
        int Colon = Lines[I].indexOf(':');
        if (Colon != -1) {
            QString Key = Lines[I].left(Colon).trimmed();
            QString Value = Lines[I].mid(Colon + 1).trimmed();
            Req.Headers[Key] = Value;

            if (Key.compare("Host", Qt::CaseInsensitive) == 0) {
                int PortColon = Value.lastIndexOf(':');
                if (PortColon != -1) {
                    Host = Value.left(PortColon);
                    Port = Value.mid(PortColon + 1).toUShort();
                } else {
                    Host = Value;
                }
            }
        }
    }

    QString Path = "/";
    if (RequestLine.size() >= 2) {
        Path = RequestLine[1];
    }

    if (Path.startsWith("http://") || Path.startsWith("https://")) {
        Req.Url = Path;
    } else {
        if (Port == 443) Scheme = QStringLiteral("https");
        Req.Url = Scheme + "://" + Host;
        if ((Scheme == "http" && Port != 80) || (Scheme == "https" && Port != 443)) {
            Req.Url += ":" + QString::number(Port);
        }
        Req.Url += Path;
    }

    Req.Body = BodySection.toUtf8();

    return Req;
}

QString SingleRepeaterTab::FormatResponse(const HttpRequest& Result) {
    QString Output;
    Output += QStringLiteral("HTTP/1.1 %1\r\n").arg(Result.StatusCode);

    for (auto It = Result.ResponseHeaders.constBegin(); It != Result.ResponseHeaders.constEnd(); ++It) {
        Output += It.key() + ": " + It.value() + "\r\n";
    }

    Output += "\r\n";
    Output += QString::fromUtf8(Result.ResponseBody);
    return Output;
}

RepeaterWidget::RepeaterWidget(QWidget* Parent)
    : QWidget(Parent)
    , TabBar(nullptr)
    , TabCounter(0) {

    QVBoxLayout* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(0, 0, 0, 0);

    QToolBar* Toolbar = new QToolBar(this);
    QAction* NewTabAction = Toolbar->addAction(QStringLiteral("+ New Tab"));
    connect(NewTabAction, &QAction::triggered, this, &RepeaterWidget::AddEmptyTab);
    MainLayout->addWidget(Toolbar);

    TabBar = new QTabWidget(this);
    TabBar->setTabsClosable(true);
    TabBar->setMovable(true);
    connect(TabBar, &QTabWidget::tabCloseRequested, this, [this](int Index) {
        if (TabBar->count() > 1) {
            QWidget* W = TabBar->widget(Index);
            TabBar->removeTab(Index);
            W->deleteLater();
        }
    });

    MainLayout->addWidget(TabBar, 1);

    AddEmptyTab();
}

RepeaterWidget::~RepeaterWidget() {
}

void RepeaterWidget::AddTab(const HttpRequest& Request) {
    ++TabCounter;
    SingleRepeaterTab* Tab = new SingleRepeaterTab(this);
    Tab->SetRequest(Request);

    QUrl ParsedUrl(Request.Url);
    QString Title = QStringLiteral("%1 %2").arg(Request.Method, ParsedUrl.host());
    TabBar->addTab(Tab, Title);
    TabBar->setCurrentWidget(Tab);
}

void RepeaterWidget::AddEmptyTab() {
    ++TabCounter;
    SingleRepeaterTab* Tab = new SingleRepeaterTab(this);
    TabBar->addTab(Tab, QStringLiteral("Repeater %1").arg(TabCounter));
    TabBar->setCurrentWidget(Tab);
}

}
