#pragma once

#include <fidra/IModule.h>
#include <QObject>

namespace Fidra {

class PluginManager;
class PluginWidget;

class PluginModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit PluginModule(QObject* Parent = nullptr);
    ~PluginModule() override;

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
    PluginWidget* MainWidget;
};

}
