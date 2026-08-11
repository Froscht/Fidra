#include "IntruderWidget.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QGroupBox>
#include <QHeaderView>
#include <QFileDialog>
#include <QFont>
#include <QUrl>
#include <QTcpSocket>
#include <QElapsedTimer>
#include <QTextCursor>
#include <QRegularExpression>

namespace Fidra {

AttackWorker::AttackWorker(QObject* Parent)
    : QObject(Parent)
    , Type(AttackType::Sniper)
    , Stopped(false) {
}

void AttackWorker::SetTemplate(const QString& Template) {
    RequestTemplate = Template;
}

void AttackWorker::SetPayloads(const QStringList& Payloads) {
    PayloadList = Payloads;
}

void AttackWorker::SetAttackType(AttackType InType) {
    Type = InType;
}

void AttackWorker::SetTargetUrl(const QString& Url) {
    TargetUrl = Url;
}

void AttackWorker::Stop() {
    Stopped = true;
}

void AttackWorker::Execute() {
    Stopped = false;
    QStringList InsertionPoints = FindInsertionPoints(RequestTemplate);

    if (InsertionPoints.isEmpty() || PayloadList.isEmpty()) {
        emit AttackFinished();
        return;
    }

    int TotalRequests = 0;
    if (Type == AttackType::Sniper) {
        TotalRequests = InsertionPoints.size() * PayloadList.size();
    } else {
        TotalRequests = PayloadList.size();
    }

    int CurrentRequest = 0;

    if (Type == AttackType::Sniper) {
        for (int Pos = 0; Pos < InsertionPoints.size() && !Stopped; ++Pos) {
            for (int P = 0; P < PayloadList.size() && !Stopped; ++P) {
                QString ModifiedRequest = SubstitutePayload(RequestTemplate, InsertionPoints, PayloadList[P], Pos);
                IntruderResult Result = SendRequest(ModifiedRequest, PayloadList[P], CurrentRequest);
                emit ResultReady(Result);
                ++CurrentRequest;
                emit ProgressUpdate(CurrentRequest, TotalRequests);
            }
        }
    } else {
        for (int P = 0; P < PayloadList.size() && !Stopped; ++P) {
            QString ModifiedRequest = RequestTemplate;
            for (const QString& Point : InsertionPoints) {
                ModifiedRequest.replace(QStringLiteral("\xC2\xA7") + Point + QStringLiteral("\xC2\xA7"), PayloadList[P]);
            }
            IntruderResult Result = SendRequest(ModifiedRequest, PayloadList[P], CurrentRequest);
            emit ResultReady(Result);
            ++CurrentRequest;
            emit ProgressUpdate(CurrentRequest, TotalRequests);
        }
    }

    emit AttackFinished();
}

QStringList AttackWorker::FindInsertionPoints(const QString& Template) {
    QStringList Points;
    QRegularExpression Regex(QStringLiteral("\xC2\xA7([^\xC2\xA7]+)\xC2\xA7"));
    QRegularExpressionMatchIterator It = Regex.globalMatch(Template);
    while (It.hasNext()) {
        QRegularExpressionMatch Match = It.next();
        QString Point = Match.captured(1);
        if (!Points.contains(Point)) {
            Points.append(Point);
        }
    }
    return Points;
}

QString AttackWorker::SubstitutePayload(const QString& Template, const QStringList& Points, const QString& Payload, int PositionIndex) {
    QString Result = Template;
    for (int I = 0; I < Points.size(); ++I) {
        QString Marker = QStringLiteral("\xC2\xA7") + Points[I] + QStringLiteral("\xC2\xA7");
        if (I == PositionIndex) {
            Result.replace(Marker, Payload);
        } else {
            Result.replace(Marker, Points[I]);
        }
    }
    return Result;
}

IntruderResult AttackWorker::SendRequest(const QString& RawRequest, const QString& Payload, int Index) {
    IntruderResult Result;
    Result.PayloadIndex = Index;
    Result.Payload = Payload;
    Result.StatusCode = 0;
    Result.ResponseLength = 0;
    Result.ResponseTime = 0;

    int HeaderEnd = RawRequest.indexOf("\r\n\r\n");
    if (HeaderEnd == -1) {
        HeaderEnd = RawRequest.indexOf("\n\n");
    }

    QString HeaderSection = HeaderEnd != -1 ? RawRequest.left(HeaderEnd) : RawRequest;
    QStringList Lines = HeaderSection.split(QRegularExpression("\\r?\\n"));

    if (Lines.isEmpty()) {
        Result.Error = QStringLiteral("Empty request");
        return Result;
    }

    QStringList RequestLineParts = Lines[0].split(' ');
    if (RequestLineParts.size() < 2) {
        Result.Error = QStringLiteral("Invalid request line");
        return Result;
    }

    QString Host;
    quint16 Port = 80;

    for (int I = 1; I < Lines.size(); ++I) {
        int Colon = Lines[I].indexOf(':');
        if (Colon != -1) {
            QString Key = Lines[I].left(Colon).trimmed();
            QString Value = Lines[I].mid(Colon + 1).trimmed();
            if (Key.compare("Host", Qt::CaseInsensitive) == 0) {
                int PortColon = Value.lastIndexOf(':');
                if (PortColon != -1) {
                    Host = Value.left(PortColon);
                    Port = Value.mid(PortColon + 1).toUShort();
                } else {
                    Host = Value;
                }
                break;
            }
        }
    }

    if (Host.isEmpty()) {
        Result.Error = QStringLiteral("No Host header found");
        return Result;
    }

    QTcpSocket Socket;
    Socket.connectToHost(Host, Port);
    if (!Socket.waitForConnected(10000)) {
        Result.Error = QStringLiteral("Connection failed: %1").arg(Socket.errorString());
        return Result;
    }

    QElapsedTimer Timer;
    Timer.start();

    QByteArray RequestData = RawRequest.toUtf8();
    if (!RequestData.contains("\r\n\r\n")) {
        RequestData.append("\r\n\r\n");
    }

    Socket.write(RequestData);
    Socket.flush();

    QByteArray ResponseData;
    while (Socket.waitForReadyRead(15000)) {
        ResponseData.append(Socket.readAll());
        if (ResponseData.contains("\r\n\r\n")) {
            int RespHeaderEnd = ResponseData.indexOf("\r\n\r\n");
            QString RespHeaders = QString::fromUtf8(ResponseData.left(RespHeaderEnd));

            int ContentLength = -1;
            bool Chunked = RespHeaders.contains("Transfer-Encoding: chunked", Qt::CaseInsensitive);

            for (const QString& Line : RespHeaders.split("\r\n")) {
                if (Line.startsWith("Content-Length:", Qt::CaseInsensitive)) {
                    ContentLength = Line.mid(15).trimmed().toInt();
                    break;
                }
            }

            if (ContentLength >= 0) {
                int BodyReceived = ResponseData.size() - (RespHeaderEnd + 4);
                while (BodyReceived < ContentLength) {
                    if (!Socket.waitForReadyRead(10000)) break;
                    ResponseData.append(Socket.readAll());
                    BodyReceived = ResponseData.size() - (RespHeaderEnd + 4);
                }
                break;
            } else if (Chunked) {
                while (!ResponseData.endsWith("\r\n0\r\n\r\n")) {
                    if (!Socket.waitForReadyRead(10000)) break;
                    ResponseData.append(Socket.readAll());
                }
                break;
            } else {
                while (Socket.waitForReadyRead(2000)) {
                    ResponseData.append(Socket.readAll());
                }
                break;
            }
        }
    }

    Result.ResponseTime = Timer.elapsed();
    Result.ResponseLength = ResponseData.size();

    int RespHeaderEnd = ResponseData.indexOf("\r\n\r\n");
    if (RespHeaderEnd != -1) {
        QString FirstLine = QString::fromUtf8(ResponseData.left(ResponseData.indexOf("\r\n")));
        QStringList StatusParts = FirstLine.split(' ');
        if (StatusParts.size() >= 2) {
            Result.StatusCode = StatusParts[1].toInt();
        }
        Result.ResponseLength = ResponseData.size() - (RespHeaderEnd + 4);
    }

    Socket.close();
    return Result;
}

IntruderWidget::IntruderWidget(QWidget* Parent)
    : QWidget(Parent)
    , TemplateEditor(nullptr)
    , ResultsTable(nullptr)
    , AttackTypeCombo(nullptr)
    , PayloadPresetCombo(nullptr)
    , PayloadEditor(nullptr)
    , StartButton(nullptr)
    , StopButton(nullptr)
    , LoadPayloadsButton(nullptr)
    , AddMarkersButton(nullptr)
    , ClearMarkersButton(nullptr)
    , ProgressIndicator(nullptr)
    , StatusLabel(nullptr)
    , WorkerThread(nullptr)
    , Worker(nullptr)
    , AttackRunning(false) {

    QFont MonoFont(QStringLiteral("Consolas"), 10);

    QVBoxLayout* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(4, 4, 4, 4);
    MainLayout->setSpacing(4);

    QSplitter* TopSplitter = new QSplitter(Qt::Horizontal, this);

    QWidget* LeftPanel = new QWidget(this);
    QVBoxLayout* LeftLayout = new QVBoxLayout(LeftPanel);
    LeftLayout->setContentsMargins(0, 0, 0, 0);

    QHBoxLayout* MarkerLayout = new QHBoxLayout();
    AddMarkersButton = new QPushButton(QStringLiteral("Add \xC2\xA7"), this);
    ClearMarkersButton = new QPushButton(QStringLiteral("Clear \xC2\xA7"), this);
    MarkerLayout->addWidget(AddMarkersButton);
    MarkerLayout->addWidget(ClearMarkersButton);
    MarkerLayout->addStretch();
    LeftLayout->addLayout(MarkerLayout);

    TemplateEditor = new QPlainTextEdit(this);
    TemplateEditor->setFont(MonoFont);
    TemplateEditor->setPlaceholderText(QStringLiteral("GET /path?param=\xC2\xA7value\xC2\xA7 HTTP/1.1\r\nHost: target.com\r\n\r\n"));
    LeftLayout->addWidget(TemplateEditor, 1);

    QWidget* RightPanel = new QWidget(this);
    QVBoxLayout* RightLayout = new QVBoxLayout(RightPanel);
    RightLayout->setContentsMargins(0, 0, 0, 0);

    QHBoxLayout* AttackLayout = new QHBoxLayout();
    QLabel* AttackLabel = new QLabel(QStringLiteral("Attack type:"), this);
    AttackTypeCombo = new QComboBox(this);
    AttackTypeCombo->addItem(QStringLiteral("Sniper"), static_cast<int>(AttackType::Sniper));
    AttackTypeCombo->addItem(QStringLiteral("Battering Ram"), static_cast<int>(AttackType::BatteringRam));
    AttackLayout->addWidget(AttackLabel);
    AttackLayout->addWidget(AttackTypeCombo);
    AttackLayout->addStretch();
    RightLayout->addLayout(AttackLayout);

    QHBoxLayout* PresetLayout = new QHBoxLayout();
    QLabel* PresetLabel = new QLabel(QStringLiteral("Preset:"), this);
    PayloadPresetCombo = new QComboBox(this);
    PayloadPresetCombo->addItem(QStringLiteral("Custom"));
    PayloadPresetCombo->addItem(QStringLiteral("Numbers 0-100"));
    PayloadPresetCombo->addItem(QStringLiteral("Numbers 0-255"));
    PayloadPresetCombo->addItem(QStringLiteral("Common Passwords"));
    PayloadPresetCombo->addItem(QStringLiteral("Common Directories"));
    PayloadPresetCombo->addItem(QStringLiteral("SQL Injection"));
    PayloadPresetCombo->addItem(QStringLiteral("XSS Payloads"));

    LoadPayloadsButton = new QPushButton(QStringLiteral("Load File"), this);
    PresetLayout->addWidget(PresetLabel);
    PresetLayout->addWidget(PayloadPresetCombo);
    PresetLayout->addWidget(LoadPayloadsButton);
    PresetLayout->addStretch();
    RightLayout->addLayout(PresetLayout);

    PayloadEditor = new QPlainTextEdit(this);
    PayloadEditor->setFont(MonoFont);
    PayloadEditor->setPlaceholderText(QStringLiteral("One payload per line..."));
    RightLayout->addWidget(PayloadEditor, 1);

    TopSplitter->addWidget(LeftPanel);
    TopSplitter->addWidget(RightPanel);
    TopSplitter->setStretchFactor(0, 2);
    TopSplitter->setStretchFactor(1, 1);
    MainLayout->addWidget(TopSplitter, 1);

    QHBoxLayout* ControlLayout = new QHBoxLayout();
    StartButton = new QPushButton(QStringLiteral("Start Attack"), this);
    StartButton->setStyleSheet(QStringLiteral("QPushButton { background-color: #e8530e; color: white; font-weight: bold; padding: 6px 16px; border-radius: 3px; } QPushButton:hover { background-color: #ff6b2b; }"));
    StopButton = new QPushButton(QStringLiteral("Stop"), this);
    StopButton->setEnabled(false);
    ProgressIndicator = new QProgressBar(this);
    ProgressIndicator->setMinimum(0);
    ProgressIndicator->setMaximum(100);
    ProgressIndicator->setValue(0);
    StatusLabel = new QLabel(this);
    StatusLabel->setFont(MonoFont);

    ControlLayout->addWidget(StartButton);
    ControlLayout->addWidget(StopButton);
    ControlLayout->addWidget(ProgressIndicator, 1);
    ControlLayout->addWidget(StatusLabel);
    MainLayout->addLayout(ControlLayout);

    ResultsTable = new QTableWidget(this);
    ResultsTable->setColumnCount(5);
    ResultsTable->setHorizontalHeaderLabels({
        QStringLiteral("#"),
        QStringLiteral("Payload"),
        QStringLiteral("Status"),
        QStringLiteral("Length"),
        QStringLiteral("Time (ms)")
    });
    ResultsTable->horizontalHeader()->setStretchLastSection(true);
    ResultsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    ResultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ResultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ResultsTable->setAlternatingRowColors(true);
    ResultsTable->verticalHeader()->setVisible(false);
    ResultsTable->setColumnWidth(0, 60);
    ResultsTable->setColumnWidth(1, 250);
    ResultsTable->setColumnWidth(2, 80);
    ResultsTable->setColumnWidth(3, 100);
    ResultsTable->setColumnWidth(4, 100);
    MainLayout->addWidget(ResultsTable, 1);

    connect(StartButton, &QPushButton::clicked, this, &IntruderWidget::OnStartAttack);
    connect(StopButton, &QPushButton::clicked, this, &IntruderWidget::OnStopAttack);
    connect(LoadPayloadsButton, &QPushButton::clicked, this, &IntruderWidget::OnLoadPayloads);
    connect(AddMarkersButton, &QPushButton::clicked, this, &IntruderWidget::OnAddMarkers);
    connect(ClearMarkersButton, &QPushButton::clicked, this, &IntruderWidget::OnClearMarkers);

    connect(PayloadPresetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int Index) {
        PopulateBuiltinPayloads();
    });
}

IntruderWidget::~IntruderWidget() {
    if (AttackRunning) {
        OnStopAttack();
    }
}

void IntruderWidget::SetRequest(const HttpRequest& Request) {
    TemplateEditor->setPlainText(RequestToRaw(Request));
}

void IntruderWidget::OnStartAttack() {
    if (AttackRunning) return;

    QString Template = TemplateEditor->toPlainText();
    if (Template.trimmed().isEmpty()) return;

    QString PayloadText = PayloadEditor->toPlainText();
    QStringList Payloads = PayloadText.split('\n', Qt::SkipEmptyParts);
    if (Payloads.isEmpty()) return;

    ResultsTable->setRowCount(0);
    ProgressIndicator->setValue(0);
    AttackRunning = true;
    StartButton->setEnabled(false);
    StopButton->setEnabled(true);
    StatusLabel->setText(QStringLiteral("Running..."));

    WorkerThread = new QThread();
    Worker = new AttackWorker();
    Worker->SetTemplate(Template);
    Worker->SetPayloads(Payloads);
    Worker->SetAttackType(static_cast<AttackType>(AttackTypeCombo->currentData().toInt()));
    Worker->moveToThread(WorkerThread);

    connect(WorkerThread, &QThread::started, Worker, &AttackWorker::Execute);
    connect(Worker, &AttackWorker::ResultReady, this, &IntruderWidget::OnResultReady, Qt::QueuedConnection);
    connect(Worker, &AttackWorker::ProgressUpdate, this, &IntruderWidget::OnProgressUpdate, Qt::QueuedConnection);
    connect(Worker, &AttackWorker::AttackFinished, this, &IntruderWidget::OnAttackFinished, Qt::QueuedConnection);
    connect(Worker, &AttackWorker::AttackFinished, WorkerThread, &QThread::quit);
    connect(WorkerThread, &QThread::finished, Worker, &QObject::deleteLater);
    connect(WorkerThread, &QThread::finished, WorkerThread, &QObject::deleteLater);

    WorkerThread->start();
}

void IntruderWidget::OnStopAttack() {
    if (Worker) {
        Worker->Stop();
    }
    StatusLabel->setText(QStringLiteral("Stopping..."));
}

void IntruderWidget::OnResultReady(const IntruderResult& Result) {
    int Row = ResultsTable->rowCount();
    ResultsTable->insertRow(Row);

    ResultsTable->setItem(Row, 0, new QTableWidgetItem(QString::number(Result.PayloadIndex)));
    ResultsTable->setItem(Row, 1, new QTableWidgetItem(Result.Payload));

    QTableWidgetItem* StatusItem = new QTableWidgetItem(QString::number(Result.StatusCode));
    if (Result.StatusCode >= 200 && Result.StatusCode < 300) {
        StatusItem->setForeground(QColor(0x4c, 0xaf, 0x50));
    } else if (Result.StatusCode >= 400) {
        StatusItem->setForeground(QColor(0xf4, 0x43, 0x36));
    } else if (Result.StatusCode >= 300) {
        StatusItem->setForeground(QColor(0xff, 0x98, 0x00));
    }
    ResultsTable->setItem(Row, 2, StatusItem);

    ResultsTable->setItem(Row, 3, new QTableWidgetItem(QString::number(Result.ResponseLength)));
    ResultsTable->setItem(Row, 4, new QTableWidgetItem(QString::number(Result.ResponseTime)));

    ResultsTable->scrollToBottom();
}

void IntruderWidget::OnProgressUpdate(int Current, int Total) {
    if (Total > 0) {
        ProgressIndicator->setMaximum(Total);
        ProgressIndicator->setValue(Current);
        StatusLabel->setText(QStringLiteral("%1 / %2").arg(Current).arg(Total));
    }
}

void IntruderWidget::OnAttackFinished() {
    AttackRunning = false;
    StartButton->setEnabled(true);
    StopButton->setEnabled(false);
    StatusLabel->setText(QStringLiteral("Finished - %1 results").arg(ResultsTable->rowCount()));
    WorkerThread = nullptr;
    Worker = nullptr;
}

void IntruderWidget::OnLoadPayloads() {
    QString FilePath = QFileDialog::getOpenFileName(this, QStringLiteral("Load Payload File"), QString(), QStringLiteral("Text Files (*.txt);;All Files (*)"));
    if (FilePath.isEmpty()) return;

    QFile File(FilePath);
    if (File.open(QIODevice::ReadOnly | QIODevice::Text)) {
        PayloadEditor->setPlainText(QString::fromUtf8(File.readAll()));
        PayloadPresetCombo->setCurrentIndex(0);
        File.close();
    }
}

void IntruderWidget::OnAddMarkers() {
    QTextCursor Cursor = TemplateEditor->textCursor();
    if (Cursor.hasSelection()) {
        QString Selected = Cursor.selectedText();
        Cursor.insertText(QStringLiteral("\xC2\xA7") + Selected + QStringLiteral("\xC2\xA7"));
    } else {
        Cursor.insertText(QStringLiteral("\xC2\xA7\xC2\xA7"));
        Cursor.movePosition(QTextCursor::Left, QTextCursor::MoveAnchor, 1);
        TemplateEditor->setTextCursor(Cursor);
    }
}

void IntruderWidget::OnClearMarkers() {
    QString Text = TemplateEditor->toPlainText();
    Text.remove(QStringLiteral("\xC2\xA7"));
    TemplateEditor->setPlainText(Text);
}

void IntruderWidget::PopulateBuiltinPayloads() {
    int Index = PayloadPresetCombo->currentIndex();
    if (Index == 0) return;

    QStringList Payloads;

    if (Index == 1) {
        for (int I = 0; I <= 100; ++I) {
            Payloads.append(QString::number(I));
        }
    } else if (Index == 2) {
        for (int I = 0; I <= 255; ++I) {
            Payloads.append(QString::number(I));
        }
    } else if (Index == 3) {
        Payloads = {
            "password", "123456", "12345678", "qwerty", "abc123",
            "monkey", "1234567", "letmein", "trustno1", "dragon",
            "baseball", "iloveyou", "master", "sunshine", "ashley",
            "bailey", "shadow", "123123", "654321", "superman",
            "qazwsx", "michael", "football", "password1", "password123",
            "batman", "login", "admin", "welcome", "hello",
            "charlie", "donald", "password2", "qwerty123", "admin123",
            "root", "toor", "pass", "test", "guest",
            "access", "love", "god", "time", "money",
            "12345", "1234", "123", "1", "0"
        };
    } else if (Index == 4) {
        Payloads = {
            "admin", "administrator", "login", "wp-admin", "wp-login.php",
            "dashboard", "console", "config", "configuration", "backup",
            "backups", "db", "database", "api", "v1",
            "v2", "test", "testing", "dev", "development",
            "staging", "prod", "production", "internal", "private",
            "secret", "hidden", "debug", "info", "status",
            "health", "metrics", "monitor", "logs", "log",
            "tmp", "temp", "upload", "uploads", "files",
            "static", "assets", "media", "images", "css",
            "js", "scripts", "cgi-bin", "bin", "server-status",
            ".env", ".git", ".htaccess", "robots.txt", "sitemap.xml",
            "phpinfo.php", "wp-config.php", "config.php", "web.config",
            ".svn", ".hg", "CVS"
        };
    } else if (Index == 5) {
        Payloads = {
            "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
            "\" OR \"1\"=\"1\"", "\" OR \"1\"=\"1\" --",
            "1' OR '1'='1", "1 OR 1=1", "1' OR '1'='1'--",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1; DROP TABLE users--", "1'; DROP TABLE users--",
            "admin'--", "admin' #", "admin'/*",
            "' OR 1=1#", "' OR 1=1--", "' OR 1=1/*",
            "') OR ('1'='1", "') OR ('1'='1'--",
            "1 AND 1=1", "1 AND 1=2", "1' AND '1'='1", "1' AND '1'='2",
            "SLEEP(5)#", "' OR SLEEP(5)#", "1; WAITFOR DELAY '0:0:5'--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "1 UNION SELECT @@version--"
        };
    } else if (Index == 6) {
        Payloads = {
            "<script>alert(1)</script>",
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=\"javascript:alert(1)\">",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<img src=\"x\" onerror=\"alert(1)\">",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            "<a href=\"javascript:alert(1)\">click</a>",
            "<math><mtext><table><mglyph><svg><mtext><textarea><path id=\"</textarea><img onerror=alert(1) src=1>\">",
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "<svg/onload=alert(1)>"
        };
    }

    PayloadEditor->setPlainText(Payloads.join('\n'));
}

QString IntruderWidget::RequestToRaw(const HttpRequest& Request) {
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

    return Raw;
}

}
