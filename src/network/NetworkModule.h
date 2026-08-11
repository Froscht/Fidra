#pragma once

#include <fidra/IModule.h>

namespace Fidra {

class NetworkWidget;

class NetworkModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit NetworkModule(QObject* Parent = nullptr);
    ~NetworkModule() override;

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

private:
    ICore* CoreRef;
    NetworkWidget* MainWidget;
};

}
