#pragma once

#include <fidra/IModule.h>

namespace Fidra {

class ScannerWidget;

class ScannerModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit ScannerModule(QObject* Parent = nullptr);
    ~ScannerModule() override;

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

private:
    ICore* CoreRef;
    ScannerWidget* MainWidget;
};

}
