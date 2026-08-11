#pragma once

#include <fidra/IModule.h>

namespace Fidra {

class CallGraphWidget;

class CallGraphModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit CallGraphModule(QObject* Parent = nullptr);
    ~CallGraphModule() override;

    QString Name() const override;
    QString Description() const override;
    QIcon Icon() const override;
    int Priority() const override;

    QWidget* CreateMainWidget(QWidget* Parent) override;

    void Initialize(ICore* Core) override;
    void Shutdown() override;

    void OnAnalysisComplete(AnalysisDatabase* Db, Address EntryPoint) override;

private:
    ICore* CoreRef;
    CallGraphWidget* Widget;
};

}
