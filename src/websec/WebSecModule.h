#pragma once

#include <fidra/IModule.h>

namespace Fidra {

class WebSecWidget;

class WebSecModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit WebSecModule(QObject* Parent = nullptr);
    ~WebSecModule() override;

    QString Name() const override;
    QString Description() const override;
    QIcon Icon() const override;
    int Priority() const override;

    QWidget* CreateMainWidget(QWidget* Parent) override;

    void Initialize(ICore* Core) override;
    void Shutdown() override;

    void ContributeToMenu(QMenuBar* MenuBar) override;

private:
    ICore* CoreRef;
    WebSecWidget* MainWidget;
};

}
