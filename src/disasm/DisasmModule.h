#pragma once

#include <fidra/IModule.h>

namespace Fidra {

class DisasmWidget;
class HexWidget;
class FunctionList;
class CFGWidget;
class XrefWidget;
class ImportsExportsWidget;
class SegmentWidget;
class AnalysisDatabase;

class DisasmModule : public QObject, public IModule {
    Q_OBJECT

public:
    explicit DisasmModule(QObject* Parent = nullptr);
    ~DisasmModule() override;

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

    void ContributeToMenu(QMenuBar* MenuBar) override;
    void ContributeToToolBar(QToolBar* ToolBar) override;

    void OnAnalysisComplete(AnalysisDatabase* Db, Address EntryPoint) override;

private:
    ICore* CoreRef;
    DisasmWidget* MainDisasm;
    HexWidget* HexView;
    FunctionList* FuncList;
    CFGWidget* GraphView;
    XrefWidget* XrefView;
    ImportsExportsWidget* ImportsExportsView;
    SegmentWidget* SegmentView;
};

}
