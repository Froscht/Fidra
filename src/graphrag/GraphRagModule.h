#pragma once

#include <fidra/IModule.h>
#include <QString>
#include <QLabel>

namespace Fidra {

class GraphRagModule : public IModule {
public:
    ~GraphRagModule() override = default;

    QString Name() const override { return "GraphRag"; }
    QString Description() const override { return "AiDA-derived retrieval-augmented graph over analyzed functions."; }
    QIcon Icon() const override { return QIcon(); }
    int Priority() const override { return 700; }

    QWidget* CreateMainWidget(QWidget* Parent) override {
        auto* L = new QLabel("GraphRag module — port scaffold. UI TBD.", Parent);
        L->setWordWrap(true);
        return L;
    }

    void Initialize(ICore* Core) override { m_Core = Core; }
    void Shutdown() override { m_Core = nullptr; }

private:
    ICore* m_Core = nullptr;
};

}
