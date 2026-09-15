#pragma once

#include <fidra/IModule.h>
#include <QObject>
#include <QLabel>

namespace Fidra {

class EmulationModule : public QObject, public IModule {
    Q_OBJECT
public:
    explicit EmulationModule(QObject* Parent = nullptr);
    ~EmulationModule() override;

    QString Name() const override { return QStringLiteral("Emulation"); }
    QString Description() const override { return QStringLiteral("Unicorn-based dynamic emulation"); }
    QIcon Icon() const override;
    int Priority() const override { return 45; }

    QWidget* CreateMainWidget(QWidget* Parent) override;
    void Initialize(ICore* Core) override;
    void Shutdown() override;

private:
    ICore* CoreRef;
    QLabel* MainWidget;
};

}
