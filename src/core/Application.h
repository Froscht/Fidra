#pragma once

#include <fidra/ICore.h>
#include <QMainWindow>
#include <QTabWidget>
#include <QDockWidget>
#include <QStatusBar>
#include <QLabel>
#include <QTextEdit>
#include <QSettings>
#include <QProgressBar>
#include <QMap>
#include "AnalysisProgressWidget.h"
#include <QList>
#include <functional>

namespace Fidra {

class LogWidget;
class AnalysisEngine;
class UndoManager;

class Application : public QMainWindow, public ICore {
    Q_OBJECT

public:
    explicit Application(QWidget* Parent = nullptr);
    ~Application() override;

    QMainWindow* MainWindow() override;
    void AddDockWidget(const QString& Title, QWidget* Widget, Qt::DockWidgetArea Area = Qt::BottomDockWidgetArea) override;
    void RemoveDockWidget(QWidget* Widget) override;

    void RegisterModule(IModule* Module) override;
    IModule* GetModule(const QString& Name) override;
    QList<IModule*> GetAllModules() override;

    void Log(const QString& Message, LogLevel Level) override;

    QSettings* Settings() override;

    ProcessInfo CurrentProcess() const override;
    void AttachToProcess(uint32_t Pid) override;
    void DetachFromProcess() override;
    bool IsAttached() const override;

    bool ReadMemory(Address Addr, void* Buffer, size_t Size) override;
    bool WriteMemory(Address Addr, const void* Buffer, size_t Size) override;
    QList<MemoryRegion> GetMemoryRegions() override;
    QList<ProcessInfo> GetProcessList() override;

    void OnProcessAttached(ProcessCallback Callback) override;
    void OnProcessDetached(ProcessCallback Callback) override;

    void NavigateToFunction(Address Addr) override;
    void OnFunctionNavigated(AddressCallback Callback) override;
    void OnAnalysisStarted(AnalysisCallback Callback) override;

    void InitializeModules();

    AnalysisEngine* GetAnalysisEngine() const { return Engine; }
    UndoManager* GetUndoManager() const { return Undo; }

    void OpenBinaryFile(const QString& FilePath);

signals:
    void ProcessAttachedSignal(uint32_t Pid);
    void ProcessDetachedSignal();
    void AnalysisComplete();

private:
    void SetupMenuBar();
    void SetupToolBar();
    void SetupStatusBar();
    void SetupCentralWidget();
    void SetupDockLayout();
    void ApplyTheme();
    void ShowAttachDialog();
    void UpdateWindowTitle();
    void OnAnalysisProgress(int Percentage, const QString& Message);
    void OnAnalysisFinished(bool Success);

    QTabWidget* ModuleTabs;
    LogWidget* LogOutput;
    QDockWidget* LogDock;
    QLabel* StatusProcessLabel;
    QLabel* StatusArchLabel;

    QSettings* AppSettings;
    QList<IModule*> Modules;
    QMap<QString, IModule*> ModuleMap;
    QMap<QWidget*, QDockWidget*> DockWidgets;

    ProcessInfo AttachedProcess;
    bool ProcessAttached;

    QList<ProcessCallback> AttachCallbacks;
    QList<ProcessCallback> DetachCallbacks;
    QList<AddressCallback> FunctionNavCallbacks;
    QList<AnalysisCallback> AnalysisStartCallbacks;

    AnalysisEngine* Engine;
    UndoManager* Undo;
    QProgressBar* AnalysisProgressBar;
    AnalysisProgressWidget* ProgressPanel;
    QAction* UndoAction;
    QAction* RedoAction;

#ifdef _WIN32
    void* ProcessHandle;
#elif defined(__linux__)
    int MemFd;
#endif
};

}
