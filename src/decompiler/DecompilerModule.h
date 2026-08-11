#pragma once

#include <fidra/IModule.h>

namespace Fidra {

class DecompilerWidget;

class DecompilerModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit DecompilerModule(QObject* Parent = nullptr);
    ~DecompilerModule() override;

    QString Name() const override;
    QString Description() const override;
    QIcon Icon() const override;
    int Priority() const override;

    QWidget* CreateMainWidget(QWidget* Parent) override;
    QList<QPair<QString, QWidget*>> CreateDockWidgets(QWidget* Parent) override;

    void Initialize(ICore* Core) override;
    void Shutdown() override;

    void OnAnalysisComplete(AnalysisDatabase* Db, Address EntryPoint) override;

private:
    ICore* CoreRef;
    DecompilerWidget* MainWidget;
};

}
