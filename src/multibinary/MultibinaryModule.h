#pragma once

#include <fidra/IModule.h>
#include <QObject>
#include <QLabel>

namespace Fidra {

class MultibinaryModule : public QObject, public IModule {
    Q_OBJECT
public:
    explicit MultibinaryModule(QObject* Parent = nullptr);
    ~MultibinaryModule() override;

    QString Name() const override { return QStringLiteral("Multibinary"); }
    QString Description() const override { return QStringLiteral("Cross-binary index and project (ported from AiDA)"); }
    QIcon Icon() const override;
    int Priority() const override { return 85; }

    QWidget* CreateMainWidget(QWidget* Parent) override;
    void Initialize(ICore* Core) override;
    void Shutdown() override;

private:
    ICore* CoreRef;
    QLabel* MainWidget;
};

}
