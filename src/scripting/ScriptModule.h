#pragma once

#include <fidra/IModule.h>

namespace Fidra {

class ScriptWidget;

class ScriptModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit ScriptModule(QObject* Parent = nullptr);
    ~ScriptModule() override;

    QString Name() const override;
    QString Description() const override;
    QIcon Icon() const override;
    int Priority() const override;

    QWidget* CreateMainWidget(QWidget* Parent) override;
    QList<QPair<QString, QWidget*>> CreateDockWidgets(QWidget* Parent) override;

    void Initialize(ICore* Core) override;
    void Shutdown() override;

    void OnProcessAttached(const ProcessInfo& Info) override;
    void OnProcessDetached() override;
    void OnAnalysisComplete(AnalysisDatabase* Db, Address EntryPoint) override;

private:
    ICore* CoreRef;
    ScriptWidget* MainWidget;
};

}
