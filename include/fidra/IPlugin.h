#pragma once

#include "ICore.h"
#include <QString>
#include <QWidget>

namespace Fidra {

enum class PluginType {
    Analysis,
    UI,
    Import,
    Export,
    Custom
};

class IPlugin {
public:
    virtual ~IPlugin() = default;

    virtual QString Name() const = 0;
    virtual QString Description() const = 0;
    virtual QString Version() const = 0;
    virtual QString Author() const = 0;

    virtual PluginType Type() const { return PluginType::Custom; }

    virtual bool Initialize(ICore* Core) = 0;
    virtual void Shutdown() = 0;

    virtual QWidget* CreateWidget(QWidget* Parent) { Q_UNUSED(Parent); return nullptr; }
};

}

extern "C" {
    typedef Fidra::IPlugin* (*CreatePluginFunc)();
    typedef void (*DestroyPluginFunc)(Fidra::IPlugin*);
}

#define FIDRA_PLUGIN(ClassName) \
    extern "C" Fidra::IPlugin* CreatePlugin() { return new ClassName(); } \
    extern "C" void DestroyPlugin(Fidra::IPlugin* P) { delete P; }
