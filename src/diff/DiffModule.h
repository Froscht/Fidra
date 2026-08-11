#pragma once

#include <fidra/IModule.h>

namespace Fidra {

class DiffWidget;

class DiffModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit DiffModule(QObject* Parent = nullptr);
    ~DiffModule() override;

    QString Name() const override;
    QString Description() const override;
    QIcon Icon() const override;
    int Priority() const override;

    QWidget* CreateMainWidget(QWidget* Parent) override;
    QList<QPair<QString, QWidget*>> CreateDockWidgets(QWidget* Parent) override;

    void Initialize(ICore* Core) override;
    void Shutdown() override;

private:
    ICore* CoreRef;
    DiffWidget* MainWidget;
};

}
