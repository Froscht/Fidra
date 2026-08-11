#pragma once

#include <QWidget>
#include <QTabWidget>
#include <QLineEdit>
#include <QProgressBar>
#include <QLabel>
#include <QToolButton>
#include <QWebEngineView>
#include <QWebEnginePage>
#include <QAction>

namespace Fidra {

class BrowserProfile;
class JsInjector;
class RequestInterceptor;
class ICore;

class BrowserWidget : public QWidget {
    Q_OBJECT

public:
    explicit BrowserWidget(QWidget* Parent = nullptr);
    ~BrowserWidget() override;

    void SetCore(ICore* Core);
    void SetProfile(BrowserProfile* Profile);
    void SetInterceptor(RequestInterceptor* Interceptor);
    void SetInjector(JsInjector* Injector);

    QWebEngineView* CurrentView() const;
    int TabCount() const;

public slots:
    void NewTab(const QUrl& Url = QUrl(QStringLiteral("about:blank")));
    void CloseTab(int Index);
    void CloseCurrentTab();
    void NavigateToUrl(const QString& Url);
    void FocusUrlBar();

signals:
    void TitleChanged(const QString& Title);
    void UrlChanged(const QUrl& Url);

private slots:
    void OnTabChanged(int Index);
    void OnTabCloseRequested(int Index);
    void OnUrlEditReturnPressed();
    void OnNavigateBack();
    void OnNavigateForward();
    void OnReload();
    void OnStop();
    void OnLoadStarted();
    void OnLoadProgress(int Progress);
    void OnLoadFinished(bool Ok);
    void OnLinkHovered(const QString& Url);
    void OnPageTitleChanged(const QString& Title);
    void OnPageUrlChanged(const QUrl& Url);

private:
    void SetupUi();
    void SetupShortcuts();
    void ConnectView(QWebEngineView* View);
    void DisconnectView(QWebEngineView* View);

    ICore* CoreRef;
    BrowserProfile* ActiveProfile;
    RequestInterceptor* ActiveInterceptor;
    JsInjector* ActiveInjector;

    QTabWidget* TabBar;
    QToolButton* NewTabButton;
    QLineEdit* UrlEdit;
    QProgressBar* LoadProgress;
    QLabel* StatusLabel;

    QAction* BackAction;
    QAction* ForwardAction;
    QAction* ReloadAction;
    QAction* StopAction;
};

}
