#pragma once

#include <fidra/IModule.h>

namespace Fidra {

class BrowserWidget;
class BrowserProfile;
class JsInjector;
class RequestInterceptor;

class BrowserModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit BrowserModule(QObject* Parent = nullptr);
    ~BrowserModule() override;

    QString Name() const override;
    QString Description() const override;
    QIcon Icon() const override;
    int Priority() const override;

    QWidget* CreateMainWidget(QWidget* Parent) override;
    QList<QPair<QString, QWidget*>> CreateDockWidgets(QWidget* Parent) override;

    void Initialize(ICore* Core) override;
    void Shutdown() override;

    void ContributeToMenu(QMenuBar* MenuBar) override;
    void ContributeToToolBar(QToolBar* ToolBar) override;

    QList<QPair<QString, QKeySequence>> GetShortcuts() override;

private:
    ICore* CoreRef;
    BrowserWidget* MainBrowser;
    BrowserProfile* ActiveProfile;
    JsInjector* Injector;
    RequestInterceptor* Interceptor;
};

}
