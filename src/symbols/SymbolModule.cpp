#include "SymbolModule.h"
#include "SymbolResolver.h"
#include "SymbolWidget.h"
#include "../analysis/AnalysisDatabase.h"
#include <QStyle>
#include <QApplication>
#include <QFileInfo>
#include <QFile>

namespace Fidra {

SymbolModule::SymbolModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , Resolver(nullptr)
    , MainWidget(nullptr)
{
}

SymbolModule::~SymbolModule() = default;

QString SymbolModule::Name() const
{
    return QStringLiteral("Symbols");
}

QString SymbolModule::Description() const
{
    return QStringLiteral("Symbol resolution and management");
}

QIcon SymbolModule::Icon() const
{
    return qApp->style()->standardIcon(QStyle::SP_FileDialogInfoView);
}

int SymbolModule::Priority() const
{
    return 15;
}

QWidget* SymbolModule::CreateMainWidget(QWidget* Parent)
{
    MainWidget = new SymbolWidget(Parent, Resolver, CoreRef);
    return MainWidget;
}

QList<QPair<QString, QWidget*>> SymbolModule::CreateDockWidgets(QWidget* Parent)
{
    Q_UNUSED(Parent);
    return {};
}

void SymbolModule::Initialize(ICore* Core)
{
    CoreRef = Core;
    Resolver = new SymbolResolver(this);
    CoreRef->Log(QStringLiteral("Symbol module initialized"));
}

void SymbolModule::Shutdown()
{
    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Symbol module shutdown"));
    }
}

void SymbolModule::OnAnalysisComplete(AnalysisDatabase* Db, Address EntryPoint)
{
    Q_UNUSED(EntryPoint);

    if (!Resolver || !Db) return;

    BinaryInfo BinInfo = Db->GetBinaryInfo();

    if (!BinInfo.Exports.isEmpty()) {
        Resolver->LoadFromExports(BinInfo.Exports, BinInfo.ImageBase);
        if (CoreRef) {
            CoreRef->Log(QStringLiteral("Loaded %1 export symbols").arg(BinInfo.Exports.size()));
        }
    }

    if (!BinInfo.Imports.isEmpty()) {
        Resolver->LoadFromImports(BinInfo.Imports);
        if (CoreRef) {
            CoreRef->Log(QStringLiteral("Loaded %1 import symbols").arg(BinInfo.Imports.size()));
        }
    }

    if (!BinInfo.FilePath.isEmpty()) {
        QFileInfo FileInfo(BinInfo.FilePath);
        if (FileInfo.exists()) {
            QFile TestFile(BinInfo.FilePath);
            if (TestFile.open(QIODevice::ReadOnly)) {
                char Magic[4] = {};
                TestFile.read(Magic, 4);
                TestFile.close();
                if (Magic[0] == 0x7f && Magic[1] == 'E' && Magic[2] == 'L' && Magic[3] == 'F') {
                    Resolver->LoadFromDwarf(BinInfo.FilePath);
                    if (CoreRef) {
                        CoreRef->Log(QStringLiteral("Attempted DWARF symbol loading from: %1").arg(BinInfo.FilePath));
                    }
                }
            }
        }
    }

    QList<SymbolInfo> AllSymbols = Resolver->GetAllSymbols();
    for (const SymbolInfo& Sym : AllSymbols) {
        if (!Sym.Name.isEmpty() && Sym.Addr != 0) {
            Db->SetName(Sym.Addr, Sym.Name);
        }
    }

    if (CoreRef) {
        CoreRef->Log(QStringLiteral("Applied %1 symbols to analysis database").arg(AllSymbols.size()));
    }

    if (MainWidget) {
        MainWidget->SetDatabase(Db);
        MainWidget->RefreshTable();
    }
}

SymbolResolver* SymbolModule::GetResolver() const
{
    return Resolver;
}

}
