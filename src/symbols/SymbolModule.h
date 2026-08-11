#pragma once

#include <fidra/IModule.h>
#include <QObject>

namespace Fidra {

class SymbolResolver;
class SymbolWidget;

class SymbolModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit SymbolModule(QObject* Parent = nullptr);
    ~SymbolModule() override;

    QString Name() const override;
    QString Description() const override;
    QIcon Icon() const override;
    int Priority() const override;

    QWidget* CreateMainWidget(QWidget* Parent) override;
    QList<QPair<QString, QWidget*>> CreateDockWidgets(QWidget* Parent) override;

    void Initialize(ICore* Core) override;
    void Shutdown() override;
    void OnAnalysisComplete(AnalysisDatabase* Db, Address EntryPoint) override;

    SymbolResolver* GetResolver() const;

private:
    ICore* CoreRef;
    SymbolResolver* Resolver;
    SymbolWidget* MainWidget;
};

}
