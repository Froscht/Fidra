#include "DecompilerModule.h"
#include "DecompilerWidget.h"
#include "Lifter.h"
#include "Optimizer.h"
#include "CodeGenerator.h"
#include "../analysis/AnalysisDatabase.h"

#include <fidra/hexrays_shim.h>
#include <fidra/ida_shim.h>

#include <QStyle>
#include <QApplication>
#include <QTabWidget>

namespace Fidra {

DecompilerModule::DecompilerModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , MainWidget(nullptr)
{
}

DecompilerModule::~DecompilerModule() = default;

QString DecompilerModule::Name() const {
    return QStringLiteral("Decompiler");
}

QString DecompilerModule::Description() const {
    return QStringLiteral("Pseudo-C Decompiler");
}

QIcon DecompilerModule::Icon() const {
    return qApp->style()->standardIcon(QStyle::SP_FileDialogDetailedView);
}

int DecompilerModule::Priority() const {
    return 40;
}

QWidget* DecompilerModule::CreateMainWidget(QWidget* Parent) {
    MainWidget = new DecompilerWidget(Parent, CoreRef);
    return MainWidget;
}

QList<QPair<QString, QWidget*>> DecompilerModule::CreateDockWidgets(QWidget* Parent) {
    Q_UNUSED(Parent);
    return {};
}

void DecompilerModule::Initialize(ICore* Core) {
    CoreRef = Core;

    CoreRef->OnFunctionNavigated([this](Address Addr) {
        if (MainWidget) {
            MainWidget->NavigateToAddress(Addr);
            QWidget* Parent = MainWidget->parentWidget();
            while (Parent) {
                auto* Tabs = qobject_cast<QTabWidget*>(Parent);
                if (Tabs) {
                    Tabs->setCurrentWidget(MainWidget);
                    break;
                }
                Parent = Parent->parentWidget();
            }
        }
    });

    // Bridge Hexrays shim's decompile() to Fidra's own decompiler pipeline.
    // Vuln/multibinary chain code that calls decompile(func_t*) now gets real
    // pseudocode text back instead of nullptr.
    Fidra::HexraysShim::SetDecompiler([](ea_t Ea) -> std::string {
        auto* Db = Fidra::IdaShim::CurrentDb();
        if (!Db) return {};
        AnalyzedFunction Func = Db->GetFunctionContaining(static_cast<Address>(Ea));
        if (Func.Start == 0 && Func.End == 0) return {};
        Decomp::Lifter Lft;
        Decomp::IrFunction IrFunc = Lft.LiftFunction(Func, Db);
        Decomp::Optimizer Opt;
        IrFunc = Opt.Optimize(IrFunc);
        Decomp::CodeGenerator Gen;
        Decomp::DecompOutput Out = Gen.Generate(IrFunc, Db);
        return Out.PseudoC.toStdString();
    });

    CoreRef->Log(QStringLiteral("Decompiler module initialized (Hexrays bridge armed)"));
}

void DecompilerModule::Shutdown() {
    if (CoreRef)
        CoreRef->Log(QStringLiteral("Decompiler module shutdown"));
}

void DecompilerModule::OnAnalysisComplete(AnalysisDatabase* Db, Address EntryPoint) {
    if (MainWidget) {
        MainWidget->SetDatabase(Db);
        if (EntryPoint != 0)
            MainWidget->DecompileFunction(EntryPoint, Db);
    }
}

}
