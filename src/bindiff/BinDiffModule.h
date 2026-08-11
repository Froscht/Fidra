#pragma once

#include <fidra/IModule.h>

namespace Fidra {

class BinDiffWidget;

class BinDiffModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit BinDiffModule(QObject* Parent = nullptr);
    ~BinDiffModule() override;

    QString Name() const override;
    QString Description() const override;
    QIcon Icon() const override;
    int Priority() const override;

    QWidget* CreateMainWidget(QWidget* Parent) override;

    void Initialize(ICore* Core) override;
    void Shutdown() override;

private:
    ICore* CoreRef;
    BinDiffWidget* Widget;
};

}
