#include "DisasmModule.h"
#include "DisasmWidget.h"
#include "HexWidget.h"
#include "FunctionList.h"
#include "CFGWidget.h"
#include "XrefWidget.h"
#include "ImportsExportsWidget.h"
#include "SegmentWidget.h"
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"

#include <QLineEdit>
#include <QMenu>
#include <QMenuBar>
#include <QToolBar>
#include <QAction>
#include <QInputDialog>
#include <QHBoxLayout>
#include <QLabel>

namespace Fidra {

DisasmModule::DisasmModule(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
    , MainDisasm(nullptr)
    , HexView(nullptr)
    , FuncList(nullptr)
    , GraphView(nullptr)
    , XrefView(nullptr)
    , ImportsExportsView(nullptr)
    , SegmentView(nullptr) {
}

DisasmModule::~DisasmModule() {
}

QString DisasmModule::Name() const {
    return QStringLiteral("Disassembler");
}

QString DisasmModule::Description() const {
    return QStringLiteral("Interactive disassembler with hex view");
}

QIcon DisasmModule::Icon() const {
    return QIcon::fromTheme(QStringLiteral("utilities-terminal"));
}

int DisasmModule::Priority() const {
    return 100;
}

QWidget* DisasmModule::CreateMainWidget(QWidget* Parent) {
    MainDisasm = new DisasmWidget(Parent);
    return MainDisasm;
}

QList<QPair<QString, QWidget*>> DisasmModule::CreateDockWidgets(QWidget* Parent) {
    HexView = new HexWidget(Parent);
    FuncList = new FunctionList(Parent);
    GraphView = new CFGWidget(Parent);
    XrefView = new XrefWidget(Parent);
    ImportsExportsView = new ImportsExportsWidget(Parent);
    SegmentView = new SegmentWidget(Parent);

    QList<QPair<QString, QWidget*>> Docks;
    Docks.append({QStringLiteral("Hex View"), HexView});
    Docks.append({QStringLiteral("Functions"), FuncList});
    Docks.append({QStringLiteral("CFG Graph"), GraphView});
    Docks.append({QStringLiteral("Cross References"), XrefView});
    Docks.append({QStringLiteral("Imports / Exports"), ImportsExportsView});
    Docks.append({QStringLiteral("Segments"), SegmentView});
    return Docks;
}

void DisasmModule::Initialize(ICore* Core) {
    CoreRef = Core;
}

void DisasmModule::PostInitialize(ICore* Core) {
    if (MainDisasm) {
        MainDisasm->SetCore(Core);
    }
    if (HexView) {
        HexView->SetCore(Core);
    }
    if (FuncList) {
        FuncList->SetCore(Core);
    }

    if (FuncList && MainDisasm) {
        connect(FuncList, &FunctionList::FunctionSelected, MainDisasm, &DisasmWidget::NavigateTo);
    }

    if (FuncList && CoreRef) {
        connect(FuncList, &FunctionList::FunctionSelected, [this](Address Addr) {
            CoreRef->NavigateToFunction(Addr);
        });
    }

    if (GraphView && MainDisasm) {
        connect(GraphView, &CFGWidget::AddressDoubleClicked, MainDisasm, &DisasmWidget::NavigateTo);
    }

    if (XrefView && MainDisasm) {
        connect(XrefView, &XrefWidget::NavigateToAddress, MainDisasm, &DisasmWidget::NavigateTo);
    }

    if (ImportsExportsView && MainDisasm) {
        connect(ImportsExportsView, &ImportsExportsWidget::NavigateToAddress, MainDisasm, &DisasmWidget::NavigateTo);
    }

    if (SegmentView && MainDisasm) {
        connect(SegmentView, &SegmentWidget::NavigateToAddress, MainDisasm, &DisasmWidget::NavigateTo);
    }

    CoreRef->OnAnalysisStarted([this](AnalysisDatabase* Db) {
        if (FuncList) {
            FuncList->ConnectToDatabase(Db);
        }
    });
}

void DisasmModule::Shutdown() {
    CoreRef = nullptr;
}

void DisasmModule::OnProcessAttached(const ProcessInfo& Info) {
    if (MainDisasm) {
        MainDisasm->OnProcessAttached(Info);
    }
    if (HexView) {
        HexView->OnProcessAttached(Info);
    }
    if (FuncList) {
        FuncList->OnProcessAttached(Info);
    }
}

void DisasmModule::OnProcessDetached() {
    if (MainDisasm) {
        MainDisasm->OnProcessDetached();
    }
    if (HexView) {
        HexView->OnProcessDetached();
    }
    if (FuncList) {
        FuncList->OnProcessDetached();
    }
}

void DisasmModule::ContributeToMenu(QMenuBar* MenuBar) {
    QMenu* DisasmMenu = MenuBar->addMenu(QStringLiteral("Disassembler"));

    QAction* GoToAddressAction = DisasmMenu->addAction(QStringLiteral("Go to Address"));
    GoToAddressAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+G")));
    connect(GoToAddressAction, &QAction::triggered, this, [this]() {
        if (MainDisasm) {
            bool Ok = false;
            QString Text = QInputDialog::getText(MainDisasm, "Go to Address", "Address (hex):", QLineEdit::Normal, "", &Ok);
            if (Ok && !Text.isEmpty()) {
                Address Addr = Text.toULongLong(&Ok, 16);
                if (!Ok && Text.startsWith("0x", Qt::CaseInsensitive))
                    Addr = Text.mid(2).toULongLong(&Ok, 16);
                if (Ok) MainDisasm->NavigateTo(Addr);
            }
        }
    });

    QAction* GoToEntryAction = DisasmMenu->addAction(QStringLiteral("Go to Entry Point"));
    GoToEntryAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+E")));
    connect(GoToEntryAction, &QAction::triggered, this, [this]() {
        if (MainDisasm && CoreRef && CoreRef->IsAttached()) {
            Address EntryPoint = CoreRef->CurrentProcess().BaseAddress;
            MainDisasm->NavigateTo(EntryPoint);
        }
    });

    DisasmMenu->addSeparator();

    QAction* BackAction = DisasmMenu->addAction(QStringLiteral("Navigate Back"));
    BackAction->setShortcut(QKeySequence(QStringLiteral("Alt+Left")));
    connect(BackAction, &QAction::triggered, this, [this]() {
        if (MainDisasm) {
            MainDisasm->GoBack();
        }
    });

    QAction* ForwardAction = DisasmMenu->addAction(QStringLiteral("Navigate Forward"));
    ForwardAction->setShortcut(QKeySequence(QStringLiteral("Alt+Right")));
    connect(ForwardAction, &QAction::triggered, this, [this]() {
        if (MainDisasm) {
            MainDisasm->GoForward();
        }
    });
}

void DisasmModule::ContributeToToolBar(QToolBar* ToolBar) {
    ToolBar->addSeparator();

    QLabel* AddressLabel = new QLabel(QStringLiteral("Address:"), ToolBar);
    ToolBar->addWidget(AddressLabel);

    QLineEdit* AddressInput = new QLineEdit(ToolBar);
    AddressInput->setPlaceholderText(QStringLiteral("0x00000000"));
    AddressInput->setFixedWidth(180);
    AddressInput->setFont(QFont(QStringLiteral("Consolas"), 10));
    ToolBar->addWidget(AddressInput);

    QAction* GoAction = ToolBar->addAction(QStringLiteral("Go"));
    connect(GoAction, &QAction::triggered, this, [this, AddressInput]() {
        if (!MainDisasm) return;
        QString Text = AddressInput->text().trimmed();
        bool Ok = false;
        Address Addr = Text.toULongLong(&Ok, 16);
        if (!Ok && Text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
            Addr = Text.mid(2).toULongLong(&Ok, 16);
        }
        if (Ok) {
            MainDisasm->NavigateTo(Addr);
        }
    });

    connect(AddressInput, &QLineEdit::returnPressed, GoAction, &QAction::trigger);
}

void DisasmModule::OnAnalysisComplete(AnalysisDatabase* Db, Address EntryPoint) {
    if (!Db) return;

    if (MainDisasm) {
        MainDisasm->SetAnalysisDatabase(Db);
        if (EntryPoint != 0) {
            MainDisasm->NavigateTo(EntryPoint);
        }
    }

    if (FuncList) {
        FuncList->LoadFromAnalysisDatabase(Db);
    }

    if (ImportsExportsView) {
        ImportsExportsView->LoadFromDatabase(Db);
    }

    if (SegmentView) {
        SegmentView->LoadFromDatabase(Db);
    }
}

}
