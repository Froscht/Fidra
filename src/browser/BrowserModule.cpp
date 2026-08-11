#include "BrowserModule.h"
#include "BrowserWidget.h"
#include "BrowserProfile.h"
#include "JsInjector.h"
#include "RequestInterceptor.h"

#include <QMenu>
#include <QMenuBar>
#include <QToolBar>
#include <QAction>
#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QComboBox>
#include <QLabel>

namespace Fidra {

BrowserModule::BrowserModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , MainBrowser(nullptr)
    , ActiveProfile(nullptr)
    , Injector(nullptr)
    , Interceptor(nullptr) {
}

BrowserModule::~BrowserModule() {
}

QString BrowserModule::Name() const {
    return QStringLiteral("Browser");
}

QString BrowserModule::Description() const {
    return QStringLiteral("Anti-detect browser with fingerprint spoofing");
}

QIcon BrowserModule::Icon() const {
    return QIcon::fromTheme(QStringLiteral("applications-internet"));
}

int BrowserModule::Priority() const {
    return 700;
}

QWidget* BrowserModule::CreateMainWidget(QWidget* Parent) {
    ActiveProfile = new BrowserProfile(QStringLiteral("FidraDefault"), this);
    Interceptor = new RequestInterceptor(this);
    Injector = new JsInjector(ActiveProfile->Profile(), this);

    Interceptor->AddBlockRule(QStringLiteral("*googlesyndication.com*"));
    Interceptor->AddBlockRule(QStringLiteral("*doubleclick.net*"));
    Interceptor->AddBlockRule(QStringLiteral("*google-analytics.com*"));
    Interceptor->AddBlockRule(QStringLiteral("*googletagmanager.com*"));
    Interceptor->AddBlockRule(QStringLiteral("*facebook.com/tr*"));
    Interceptor->AddBlockRule(QStringLiteral("*connect.facebook.net*"));

    Injector->InjectAllHooks();

    MainBrowser = new BrowserWidget(Parent);
    MainBrowser->SetProfile(ActiveProfile);
    MainBrowser->SetInterceptor(Interceptor);
    MainBrowser->SetInjector(Injector);

    return MainBrowser;
}

QList<QPair<QString, QWidget*>> BrowserModule::CreateDockWidgets(QWidget* Parent) {
    Q_UNUSED(Parent);
    return {};
}

void BrowserModule::Initialize(ICore* Core) {
    CoreRef = Core;

    if (MainBrowser) {
        MainBrowser->SetCore(Core);
    }

    if (Interceptor && CoreRef) {
        connect(Interceptor, &RequestInterceptor::RequestLogged, this, [this](const QString& Method, const QUrl& Url, const QString& ResourceType) {
            CoreRef->Log(QStringLiteral("[HTTP] %1 %2 [%3]").arg(Method, Url.toString(), ResourceType), LogLevel::Debug);
        });

        connect(Interceptor, &RequestInterceptor::RequestBlocked, this, [this](const QUrl& Url, const QString& Rule) {
            CoreRef->Log(QStringLiteral("[BLOCKED] %1 (rule: %2)").arg(Url.toString(), Rule), LogLevel::Info);
        });
    }
}

void BrowserModule::Shutdown() {
    CoreRef = nullptr;
}

void BrowserModule::ContributeToMenu(QMenuBar* MenuBar) {
    QMenu* BrowserMenu = MenuBar->addMenu(QStringLiteral("Browser"));

    QAction* NewTabAction = BrowserMenu->addAction(QStringLiteral("New Tab"));
    NewTabAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+T")));
    connect(NewTabAction, &QAction::triggered, this, [this]() {
        if (MainBrowser) {
            MainBrowser->NewTab();
        }
    });

    QAction* CloseTabAction = BrowserMenu->addAction(QStringLiteral("Close Tab"));
    CloseTabAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+W")));
    connect(CloseTabAction, &QAction::triggered, this, [this]() {
        if (MainBrowser) {
            MainBrowser->CloseCurrentTab();
        }
    });

    BrowserMenu->addSeparator();

    QAction* NavigateAction = BrowserMenu->addAction(QStringLiteral("Navigate to URL..."));
    NavigateAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+L")));
    connect(NavigateAction, &QAction::triggered, this, [this]() {
        if (MainBrowser) {
            MainBrowser->FocusUrlBar();
        }
    });

    BrowserMenu->addSeparator();

    QMenu* FingerprintMenu = BrowserMenu->addMenu(QStringLiteral("Fingerprint"));

    QAction* RandomFpAction = FingerprintMenu->addAction(QStringLiteral("Randomize Fingerprint"));
    connect(RandomFpAction, &QAction::triggered, this, [this]() {
        if (ActiveProfile) {
            FingerprintConfig Config = BrowserProfile::GenerateRandomFingerprint();
            ActiveProfile->SetFingerprint(Config);
            if (CoreRef) {
                CoreRef->Log(QStringLiteral("[Browser] Fingerprint randomized - UA: %1").arg(Config.UserAgent), LogLevel::Info);
            }
        }
    });

    QAction* SaveProfileAction = FingerprintMenu->addAction(QStringLiteral("Save Profile..."));
    connect(SaveProfileAction, &QAction::triggered, this, [this]() {
        if (!ActiveProfile) return;
        QString FilePath = QFileDialog::getSaveFileName(
            MainBrowser, QStringLiteral("Save Browser Profile"),
            QString(), QStringLiteral("JSON Files (*.json)"));
        if (!FilePath.isEmpty()) {
            ActiveProfile->SaveToFile(FilePath);
            if (CoreRef) {
                CoreRef->Log(QStringLiteral("[Browser] Profile saved to %1").arg(FilePath), LogLevel::Info);
            }
        }
    });

    QAction* LoadProfileAction = FingerprintMenu->addAction(QStringLiteral("Load Profile..."));
    connect(LoadProfileAction, &QAction::triggered, this, [this]() {
        if (!ActiveProfile) return;
        QString FilePath = QFileDialog::getOpenFileName(
            MainBrowser, QStringLiteral("Load Browser Profile"),
            QString(), QStringLiteral("JSON Files (*.json)"));
        if (!FilePath.isEmpty()) {
            if (ActiveProfile->LoadFromFile(FilePath)) {
                if (CoreRef) {
                    CoreRef->Log(QStringLiteral("[Browser] Profile loaded from %1").arg(FilePath), LogLevel::Info);
                }
            }
        }
    });

    BrowserMenu->addSeparator();

    QMenu* InterceptorMenu = BrowserMenu->addMenu(QStringLiteral("Request Interceptor"));

    QAction* ToggleLoggingAction = InterceptorMenu->addAction(QStringLiteral("Toggle Request Logging"));
    ToggleLoggingAction->setCheckable(true);
    ToggleLoggingAction->setChecked(true);
    connect(ToggleLoggingAction, &QAction::toggled, this, [this](bool Checked) {
        if (Interceptor) {
            Interceptor->SetLoggingEnabled(Checked);
        }
    });

    QAction* ToggleBlockingAction = InterceptorMenu->addAction(QStringLiteral("Toggle Ad Blocking"));
    ToggleBlockingAction->setCheckable(true);
    ToggleBlockingAction->setChecked(true);
    connect(ToggleBlockingAction, &QAction::toggled, this, [this](bool Checked) {
        if (Interceptor) {
            Interceptor->SetBlockingEnabled(Checked);
        }
    });

    QAction* AddBlockRuleAction = InterceptorMenu->addAction(QStringLiteral("Add Block Rule..."));
    connect(AddBlockRuleAction, &QAction::triggered, this, [this]() {
        if (!Interceptor) return;
        bool Ok = false;
        QString Pattern = QInputDialog::getText(
            MainBrowser, QStringLiteral("Add Block Rule"),
            QStringLiteral("URL Pattern (wildcard):"),
            QLineEdit::Normal, QStringLiteral("*example.com*"), &Ok);
        if (Ok && !Pattern.isEmpty()) {
            Interceptor->AddBlockRule(Pattern);
            if (CoreRef) {
                CoreRef->Log(QStringLiteral("[Browser] Added block rule: %1").arg(Pattern), LogLevel::Info);
            }
        }
    });

    QAction* AddHeaderAction = InterceptorMenu->addAction(QStringLiteral("Add Header Override..."));
    connect(AddHeaderAction, &QAction::triggered, this, [this]() {
        if (!Interceptor) return;
        bool Ok = false;
        QString HeaderName = QInputDialog::getText(
            MainBrowser, QStringLiteral("Add Header Override"),
            QStringLiteral("Header Name:"), QLineEdit::Normal,
            QStringLiteral("X-Custom-Header"), &Ok);
        if (!Ok || HeaderName.isEmpty()) return;

        QString HeaderValue = QInputDialog::getText(
            MainBrowser, QStringLiteral("Add Header Override"),
            QStringLiteral("Header Value:"), QLineEdit::Normal,
            QString(), &Ok);
        if (Ok) {
            Interceptor->AddHeaderOverride(HeaderName, HeaderValue);
            if (CoreRef) {
                CoreRef->Log(QStringLiteral("[Browser] Header override: %1 = %2").arg(HeaderName, HeaderValue), LogLevel::Info);
            }
        }
    });

    BrowserMenu->addSeparator();

    QAction* ScriptEditorAction = BrowserMenu->addAction(QStringLiteral("User Scripts..."));
    connect(ScriptEditorAction, &QAction::triggered, this, [this]() {
        if (Injector) {
            Injector->ShowScriptEditor(MainBrowser);
        }
    });
}

void BrowserModule::ContributeToToolBar(QToolBar* ToolBar) {
    ToolBar->addSeparator();

    QAction* NewTabToolAction = ToolBar->addAction(QStringLiteral("New Tab"));
    connect(NewTabToolAction, &QAction::triggered, this, [this]() {
        if (MainBrowser) {
            MainBrowser->NewTab();
        }
    });

    QAction* RandomFpToolAction = ToolBar->addAction(QStringLiteral("Random FP"));
    RandomFpToolAction->setToolTip(QStringLiteral("Randomize browser fingerprint"));
    connect(RandomFpToolAction, &QAction::triggered, this, [this]() {
        if (ActiveProfile) {
            FingerprintConfig Config = BrowserProfile::GenerateRandomFingerprint();
            ActiveProfile->SetFingerprint(Config);
            if (CoreRef) {
                CoreRef->Log(QStringLiteral("[Browser] Fingerprint randomized"), LogLevel::Info);
            }
        }
    });

    QLabel* RequestCountLabel = new QLabel(QStringLiteral("Requests: 0"), ToolBar);
    ToolBar->addWidget(RequestCountLabel);

    if (Interceptor) {
        connect(Interceptor, &RequestInterceptor::RequestLogged, this, [RequestCountLabel, this](const QString&, const QUrl&, const QString&) {
            if (Interceptor) {
                RequestCountLabel->setText(QStringLiteral("Requests: %1 (Blocked: %2)")
                    .arg(Interceptor->TotalRequestCount())
                    .arg(Interceptor->BlockedRequestCount()));
            }
        });
    }
}

QList<QPair<QString, QKeySequence>> BrowserModule::GetShortcuts() {
    QList<QPair<QString, QKeySequence>> Shortcuts;
    Shortcuts.append({QStringLiteral("New Tab"), QKeySequence(QStringLiteral("Ctrl+T"))});
    Shortcuts.append({QStringLiteral("Close Tab"), QKeySequence(QStringLiteral("Ctrl+W"))});
    Shortcuts.append({QStringLiteral("Focus URL Bar"), QKeySequence(QStringLiteral("Ctrl+L"))});
    return Shortcuts;
}

}
