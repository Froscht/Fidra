#pragma once

#include "Types.h"
#include <QMainWindow>
#include <QSettings>
#include <functional>

namespace Fidra {

class IModule;
class AnalysisDatabase;

class ICore {
public:
    virtual ~ICore() = default;

    virtual QMainWindow* MainWindow() = 0;
    virtual void AddDockWidget(const QString& Title, QWidget* Widget, Qt::DockWidgetArea Area = Qt::BottomDockWidgetArea) = 0;
    virtual void RemoveDockWidget(QWidget* Widget) = 0;

    virtual void RegisterModule(IModule* Module) = 0;
    virtual IModule* GetModule(const QString& Name) = 0;
    virtual QList<IModule*> GetAllModules() = 0;

    virtual void Log(const QString& Message, LogLevel Level = LogLevel::Info) = 0;

    virtual QSettings* Settings() = 0;

    virtual ProcessInfo CurrentProcess() const = 0;
    virtual void AttachToProcess(uint32_t Pid) = 0;
    virtual void DetachFromProcess() = 0;
    virtual bool IsAttached() const = 0;

    virtual bool ReadMemory(Address Addr, void* Buffer, size_t Size) = 0;
    virtual bool WriteMemory(Address Addr, const void* Buffer, size_t Size) = 0;
    virtual QList<MemoryRegion> GetMemoryRegions() = 0;
    virtual QList<ProcessInfo> GetProcessList() = 0;

    using ProcessCallback = std::function<void(uint32_t Pid)>;
    virtual void OnProcessAttached(ProcessCallback Callback) = 0;
    virtual void OnProcessDetached(ProcessCallback Callback) = 0;

    using AddressCallback = std::function<void(Address Addr)>;
    virtual void NavigateToFunction(Address Addr) = 0;
    virtual void OnFunctionNavigated(AddressCallback Callback) = 0;

    using AnalysisCallback = std::function<void(AnalysisDatabase* Db)>;
    virtual void OnAnalysisStarted(AnalysisCallback Callback) = 0;
};

}
