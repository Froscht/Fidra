#include "BrowserWidget.h"
#include "BrowserProfile.h"
#include "JsInjector.h"
#include "RequestInterceptor.h"

#include <fidra/ICore.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QToolBar>
#include <QShortcut>
#include <QKeySequence>
#include <QStyle>
#include <QApplication>
#include <QWebEngineProfile>
#include <QWebEngineHistory>
#include <QWebEnginePage>
#include <QWebEngineSettings>

namespace Fidra {

BrowserWidget::BrowserWidget(QWidget* Parent)
    : QWidget(Parent)
    , CoreRef(nullptr)
    , ActiveProfile(nullptr)
    , ActiveInterceptor(nullptr)
    , ActiveInjector(nullptr)
    , TabBar(nullptr)
    , NewTabButton(nullptr)
    , UrlEdit(nullptr)
    , LoadProgress(nullptr)
    , StatusLabel(nullptr)
    , BackAction(nullptr)
    , ForwardAction(nullptr)
    , ReloadAction(nullptr)
    , StopAction(nullptr) {
    SetupUi();
    SetupShortcuts();
}

BrowserWidget::~BrowserWidget() {
}

void BrowserWidget::SetCore(ICore* Core) {
    CoreRef = Core;
}

void BrowserWidget::SetProfile(BrowserProfile* Profile) {
    ActiveProfile = Profile;
}

void BrowserWidget::SetInterceptor(RequestInterceptor* Interceptor) {
    ActiveInterceptor = Interceptor;
}

void BrowserWidget::SetInjector(JsInjector* Injector) {
    ActiveInjector = Injector;
}

QWebEngineView* BrowserWidget::CurrentView() const {
    if (!TabBar || TabBar->currentIndex() < 0) {
        return nullptr;
    }
    return qobject_cast<QWebEngineView*>(TabBar->currentWidget());
}

int BrowserWidget::TabCount() const {
    return TabBar ? TabBar->count() : 0;
}

void BrowserWidget::NewTab(const QUrl& Url) {
    QWebEngineView* View = new QWebEngineView(TabBar);

    if (ActiveProfile) {
        QWebEnginePage* Page = new QWebEnginePage(ActiveProfile->Profile(), View);
        View->setPage(Page);
    }

    if (ActiveInterceptor && View->page() && View->page()->profile()) {
        View->page()->profile()->setUrlRequestInterceptor(ActiveInterceptor);
    }

    QWebEngineSettings* Settings = View->page()->settings();
    Settings->setAttribute(QWebEngineSettings::JavascriptEnabled, true);
    Settings->setAttribute(QWebEngineSettings::LocalStorageEnabled, true);
    Settings->setAttribute(QWebEngineSettings::PluginsEnabled, true);
    Settings->setAttribute(QWebEngineSettings::FullScreenSupportEnabled, true);
    Settings->setAttribute(QWebEngineSettings::WebGLEnabled, true);
    Settings->setAttribute(QWebEngineSettings::Accelerated2dCanvasEnabled, true);
    Settings->setAttribute(QWebEngineSettings::ScrollAnimatorEnabled, true);

    int Index = TabBar->addTab(View, QStringLiteral("New Tab"));
    TabBar->setCurrentIndex(Index);

    ConnectView(View);

    View->load(Url);
}

void BrowserWidget::CloseTab(int Index) {
    if (TabBar->count() <= 1) {
        return;
    }

    QWebEngineView* View = qobject_cast<QWebEngineView*>(TabBar->widget(Index));
    if (View) {
        DisconnectView(View);
        TabBar->removeTab(Index);
        View->deleteLater();
    }
}

void BrowserWidget::CloseCurrentTab() {
    CloseTab(TabBar->currentIndex());
}

void BrowserWidget::NavigateToUrl(const QString& Url) {
    QWebEngineView* View = CurrentView();
    if (!View) return;

    QString ProcessedUrl = Url.trimmed();
    if (!ProcessedUrl.contains(QStringLiteral("://")) && !ProcessedUrl.startsWith(QStringLiteral("about:"))) {
        if (ProcessedUrl.contains(QStringLiteral(".")) && !ProcessedUrl.contains(QStringLiteral(" "))) {
            ProcessedUrl = QStringLiteral("https://") + ProcessedUrl;
        } else {
            ProcessedUrl = QStringLiteral("https://www.google.com/search?q=") + QUrl::toPercentEncoding(ProcessedUrl);
        }
    }

    View->load(QUrl(ProcessedUrl));
}

void BrowserWidget::FocusUrlBar() {
    if (UrlEdit) {
        UrlEdit->setFocus();
        UrlEdit->selectAll();
    }
}

void BrowserWidget::OnTabChanged(int Index) {
    if (Index < 0) return;

    QWebEngineView* View = qobject_cast<QWebEngineView*>(TabBar->widget(Index));
    if (!View) return;

    UrlEdit->setText(View->url().toString());
    BackAction->setEnabled(View->history()->canGoBack());
    ForwardAction->setEnabled(View->history()->canGoForward());

    emit TitleChanged(View->title());
    emit UrlChanged(View->url());
}

void BrowserWidget::OnTabCloseRequested(int Index) {
    CloseTab(Index);
}

void BrowserWidget::OnUrlEditReturnPressed() {
    NavigateToUrl(UrlEdit->text());
}

void BrowserWidget::OnNavigateBack() {
    QWebEngineView* View = CurrentView();
    if (View) {
        View->back();
    }
}

void BrowserWidget::OnNavigateForward() {
    QWebEngineView* View = CurrentView();
    if (View) {
        View->forward();
    }
}

void BrowserWidget::OnReload() {
    QWebEngineView* View = CurrentView();
    if (View) {
        View->reload();
    }
}

void BrowserWidget::OnStop() {
    QWebEngineView* View = CurrentView();
    if (View) {
        View->stop();
    }
}

void BrowserWidget::OnLoadStarted() {
    LoadProgress->setVisible(true);
    LoadProgress->setValue(0);
    ReloadAction->setVisible(false);
    StopAction->setVisible(true);
}

void BrowserWidget::OnLoadProgress(int Progress) {
    LoadProgress->setValue(Progress);
}

void BrowserWidget::OnLoadFinished(bool Ok) {
    Q_UNUSED(Ok);
    LoadProgress->setVisible(false);
    ReloadAction->setVisible(true);
    StopAction->setVisible(false);

    QWebEngineView* View = CurrentView();
    if (View) {
        BackAction->setEnabled(View->history()->canGoBack());
        ForwardAction->setEnabled(View->history()->canGoForward());
    }
}

void BrowserWidget::OnLinkHovered(const QString& Url) {
    StatusLabel->setText(Url);
}

void BrowserWidget::OnPageTitleChanged(const QString& Title) {
    QWebEngineView* View = qobject_cast<QWebEngineView*>(sender());
    if (!View) return;

    if (Title.startsWith(QStringLiteral("FIDRA_CONSOLE:")) ||
        Title.startsWith(QStringLiteral("FIDRA_XHR:")) ||
        Title.startsWith(QStringLiteral("FIDRA_FETCH:")) ||
        Title.startsWith(QStringLiteral("FIDRA_WS:"))) {

        if (CoreRef && Title.startsWith(QStringLiteral("FIDRA_CONSOLE:"))) {
            QString Payload = Title.mid(14);
            int ColonPos = Payload.indexOf(QStringLiteral(":"));
            if (ColonPos > 0) {
                QString Level = Payload.left(ColonPos);
                QString Message = Payload.mid(ColonPos + 1);
                LogLevel Lvl = LogLevel::Info;
                if (Level == QStringLiteral("error")) Lvl = LogLevel::Error;
                else if (Level == QStringLiteral("warn")) Lvl = LogLevel::Warning;
                else if (Level == QStringLiteral("debug")) Lvl = LogLevel::Debug;
                CoreRef->Log(QStringLiteral("[JS:%1] %2").arg(Level, Message), Lvl);
            }
        }

        if (CoreRef && Title.startsWith(QStringLiteral("FIDRA_XHR:"))) {
            CoreRef->Log(QStringLiteral("[XHR] %1").arg(Title.mid(9)), LogLevel::Debug);
        }

        if (CoreRef && Title.startsWith(QStringLiteral("FIDRA_FETCH:"))) {
            CoreRef->Log(QStringLiteral("[Fetch] %1").arg(Title.mid(11)), LogLevel::Debug);
        }

        if (CoreRef && Title.startsWith(QStringLiteral("FIDRA_WS:"))) {
            CoreRef->Log(QStringLiteral("[WS] %1").arg(Title.mid(8)), LogLevel::Debug);
        }

        return;
    }

    int Index = TabBar->indexOf(View);
    if (Index >= 0) {
        QString DisplayTitle = Title;
        if (DisplayTitle.length() > 30) {
            DisplayTitle = DisplayTitle.left(27) + QStringLiteral("...");
        }
        TabBar->setTabText(Index, DisplayTitle);
        TabBar->setTabToolTip(Index, Title);
    }

    if (View == CurrentView()) {
        emit TitleChanged(Title);
    }
}

void BrowserWidget::OnPageUrlChanged(const QUrl& Url) {
    QWebEngineView* View = qobject_cast<QWebEngineView*>(sender());
    if (!View) return;

    if (View == CurrentView()) {
        UrlEdit->setText(Url.toString());
        emit UrlChanged(Url);
    }
}

void BrowserWidget::SetupUi() {
    QVBoxLayout* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(0, 0, 0, 0);
    MainLayout->setSpacing(0);

    QToolBar* NavBar = new QToolBar(this);
    NavBar->setMovable(false);
    NavBar->setIconSize(QSize(16, 16));

    BackAction = NavBar->addAction(QApplication::style()->standardIcon(QStyle::SP_ArrowBack), QStringLiteral("Back"));
    connect(BackAction, &QAction::triggered, this, &BrowserWidget::OnNavigateBack);
    BackAction->setEnabled(false);

    ForwardAction = NavBar->addAction(QApplication::style()->standardIcon(QStyle::SP_ArrowForward), QStringLiteral("Forward"));
    connect(ForwardAction, &QAction::triggered, this, &BrowserWidget::OnNavigateForward);
    ForwardAction->setEnabled(false);

    ReloadAction = NavBar->addAction(QApplication::style()->standardIcon(QStyle::SP_BrowserReload), QStringLiteral("Reload"));
    connect(ReloadAction, &QAction::triggered, this, &BrowserWidget::OnReload);

    StopAction = NavBar->addAction(QApplication::style()->standardIcon(QStyle::SP_BrowserStop), QStringLiteral("Stop"));
    connect(StopAction, &QAction::triggered, this, &BrowserWidget::OnStop);
    StopAction->setVisible(false);

    UrlEdit = new QLineEdit(this);
    UrlEdit->setPlaceholderText(QStringLiteral("Enter URL or search..."));
    UrlEdit->setFont(QFont(QStringLiteral("Consolas"), 10));
    connect(UrlEdit, &QLineEdit::returnPressed, this, &BrowserWidget::OnUrlEditReturnPressed);
    NavBar->addWidget(UrlEdit);

    QAction* GoAction = NavBar->addAction(QApplication::style()->standardIcon(QStyle::SP_MediaPlay), QStringLiteral("Go"));
    connect(GoAction, &QAction::triggered, this, &BrowserWidget::OnUrlEditReturnPressed);

    MainLayout->addWidget(NavBar);

    LoadProgress = new QProgressBar(this);
    LoadProgress->setMaximumHeight(3);
    LoadProgress->setTextVisible(false);
    LoadProgress->setRange(0, 100);
    LoadProgress->setVisible(false);
    MainLayout->addWidget(LoadProgress);

    TabBar = new QTabWidget(this);
    TabBar->setTabsClosable(true);
    TabBar->setMovable(true);
    TabBar->setDocumentMode(true);
    TabBar->setElideMode(Qt::ElideRight);

    NewTabButton = new QToolButton(TabBar);
    NewTabButton->setText(QStringLiteral("+"));
    NewTabButton->setAutoRaise(true);
    TabBar->setCornerWidget(NewTabButton, Qt::TopRightCorner);

    connect(NewTabButton, &QToolButton::clicked, this, [this]() {
        NewTab();
    });

    connect(TabBar, &QTabWidget::currentChanged, this, &BrowserWidget::OnTabChanged);
    connect(TabBar, &QTabWidget::tabCloseRequested, this, &BrowserWidget::OnTabCloseRequested);

    MainLayout->addWidget(TabBar, 1);

    StatusLabel = new QLabel(this);
    StatusLabel->setMaximumHeight(20);
    StatusLabel->setContentsMargins(4, 0, 4, 0);
    StatusLabel->setFont(QFont(QStringLiteral("Consolas"), 8));
    MainLayout->addWidget(StatusLabel);

    NewTab(QUrl(QStringLiteral("about:blank")));
}

void BrowserWidget::SetupShortcuts() {
    QShortcut* NewTabShortcut = new QShortcut(QKeySequence(QStringLiteral("Ctrl+T")), this);
    connect(NewTabShortcut, &QShortcut::activated, this, [this]() { NewTab(); });

    QShortcut* CloseTabShortcut = new QShortcut(QKeySequence(QStringLiteral("Ctrl+W")), this);
    connect(CloseTabShortcut, &QShortcut::activated, this, &BrowserWidget::CloseCurrentTab);

    QShortcut* FocusUrlShortcut = new QShortcut(QKeySequence(QStringLiteral("Ctrl+L")), this);
    connect(FocusUrlShortcut, &QShortcut::activated, this, &BrowserWidget::FocusUrlBar);

    QShortcut* ReloadShortcut = new QShortcut(QKeySequence(QStringLiteral("F5")), this);
    connect(ReloadShortcut, &QShortcut::activated, this, &BrowserWidget::OnReload);

    QShortcut* BackShortcut = new QShortcut(QKeySequence(QStringLiteral("Alt+Left")), this);
    connect(BackShortcut, &QShortcut::activated, this, &BrowserWidget::OnNavigateBack);

    QShortcut* ForwardShortcut = new QShortcut(QKeySequence(QStringLiteral("Alt+Right")), this);
    connect(ForwardShortcut, &QShortcut::activated, this, &BrowserWidget::OnNavigateForward);
}

void BrowserWidget::ConnectView(QWebEngineView* View) {
    connect(View, &QWebEngineView::loadStarted, this, &BrowserWidget::OnLoadStarted);
    connect(View, &QWebEngineView::loadProgress, this, &BrowserWidget::OnLoadProgress);
    connect(View, &QWebEngineView::loadFinished, this, &BrowserWidget::OnLoadFinished);
    connect(View, &QWebEngineView::titleChanged, this, &BrowserWidget::OnPageTitleChanged);
    connect(View, &QWebEngineView::urlChanged, this, &BrowserWidget::OnPageUrlChanged);

    connect(View->page(), &QWebEnginePage::linkHovered, this, &BrowserWidget::OnLinkHovered);
}

void BrowserWidget::DisconnectView(QWebEngineView* View) {
    View->disconnect(this);
    if (View->page()) {
        View->page()->disconnect(this);
    }
}

}
