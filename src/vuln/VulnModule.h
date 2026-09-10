#pragma once

#include <fidra/IModule.h>
#include <QObject>
#include <QLabel>

namespace Fidra {

class VulnModule : public QObject, public IModule {
    Q_OBJECT
public:
    explicit VulnModule(QObject* Parent = nullptr);
    ~VulnModule() override;

    QString Name() const override { return QStringLiteral("Vuln Chains"); }
    QString Description() const override { return QStringLiteral("Chain analysis and vulnerability discovery (ported from AiDA)"); }
    QIcon Icon() const override;
    int Priority() const override { return 90; }

    QWidget* CreateMainWidget(QWidget* Parent) override;
    void Initialize(ICore* Core) override;
    void Shutdown() override;
    void OnAnalysisComplete(AnalysisDatabase* Db, Address EntryPoint) override;

private:
    ICore* CoreRef;
    QLabel* MainWidget;
};

}
