#pragma once

#include <fidra/IModule.h>

namespace Fidra {

class StructEditorWidget;

class StructEditorModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit StructEditorModule(QObject* Parent = nullptr);
    ~StructEditorModule() override;

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
    StructEditorWidget* MainWidget;
};

}
