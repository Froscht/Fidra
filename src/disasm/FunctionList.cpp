#include "FunctionList.h"
#include "Disassembler.h"
#include <fidra/ICore.h>
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <QVBoxLayout>
#include <QHeaderView>
#include <algorithm>

namespace Fidra {

FunctionList::FunctionList(QWidget* Parent)
    : QWidget(Parent)
    , CorePtr(nullptr)
{
    auto* Layout = new QVBoxLayout(this);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(2);

    FilterInput = new QLineEdit(this);
    FilterInput->setPlaceholderText("Filter functions...");
    Layout->addWidget(FilterInput);

    TreeWidget = new QTreeWidget(this);
    TreeWidget->setHeaderLabels({"Name", "Address", "Size", "End Address"});
    TreeWidget->setAlternatingRowColors(true);
    TreeWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    TreeWidget->setRootIsDecorated(false);
    TreeWidget->setSortingEnabled(true);
    TreeWidget->header()->setStretchLastSection(true);
    TreeWidget->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    TreeWidget->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    TreeWidget->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    Layout->addWidget(TreeWidget);

    connect(FilterInput, &QLineEdit::textChanged, this, &FunctionList::OnFilterChanged);
    connect(TreeWidget, &QTreeWidget::itemDoubleClicked, this, &FunctionList::OnItemDoubleClicked);
}

FunctionList::~FunctionList() = default;

void FunctionList::SetCore(ICore* Core) {
    CorePtr = Core;
}

void FunctionList::OnProcessAttached(const ProcessInfo& Info) {
    if (!CorePtr || !CorePtr->IsAttached())
        return;

    constexpr size_t ReadSize = 65536;
    QByteArray Buffer(ReadSize, '\0');

    if (CorePtr->ReadMemory(Info.BaseAddress, Buffer.data(), ReadSize)) {
        DetectFunctions(Buffer, Info.BaseAddress);
        PopulateList();
    }
}

void FunctionList::OnProcessDetached() {
    Functions.clear();
    TreeWidget->clear();
}

void FunctionList::AnalyzeFunctions(Address StartAddr, size_t Size) {
    if (!CorePtr || !CorePtr->IsAttached())
        return;

    QByteArray Buffer(static_cast<qsizetype>(Size), '\0');
    if (CorePtr->ReadMemory(StartAddr, Buffer.data(), Size)) {
        DetectFunctions(Buffer, StartAddr);
        PopulateList();
    }
}

void FunctionList::DetectFunctions(const QByteArray& Data, Address BaseAddr) {
    Functions.clear();

    Disassembler Disasm;
    Architecture Arch = CorePtr ? CorePtr->CurrentProcess().Arch : Architecture::X64;
    Disasm.SetArchitecture(Arch);

    QList<DisasmInstruction> Instructions = Disasm.Disassemble(Data, BaseAddr);

    QSet<Address> SeenAddresses;

    for (const auto& Insn : Instructions) {
        if (Insn.Mnemonic.toLower() == "call") {
            QString Ops = Insn.Operands.trimmed();
            bool Ok = false;
            Address Target = 0;

            if (Ops.startsWith("0x") || Ops.startsWith("0X")) {
                Target = Ops.mid(2).toULongLong(&Ok, 16);
            } else {
                Target = Ops.toULongLong(&Ok, 16);
                if (!Ok) {
                    Target = Ops.toULongLong(&Ok, 10);
                }
            }

            if (Ok && Target != 0 && !SeenAddresses.contains(Target)) {
                SeenAddresses.insert(Target);
                FunctionEntry Entry;
                Entry.StartAddress = Target;
                Entry.EndAddress = 0;
                Entry.Name = QString("sub_%1").arg(Target, 0, 16);
                Entry.Size = 0;
                Functions.append(Entry);
            }
        }
    }

    for (int I = 0; I < Instructions.size() - 1; ++I) {
        const auto& Curr = Instructions[I];
        const auto& Next = Instructions[I + 1];

        bool IsPrologue = false;

        if (Curr.Mnemonic.toLower() == "push" && Next.Mnemonic.toLower() == "mov") {
            QString CurrOps = Curr.Operands.toLower().trimmed();
            QString NextOps = Next.Operands.toLower().trimmed();

            if ((CurrOps == "rbp" && NextOps == "rbp, rsp") ||
                (CurrOps == "ebp" && NextOps == "ebp, esp")) {
                IsPrologue = true;
            }
        }

        if (IsPrologue && !SeenAddresses.contains(Curr.Location)) {
            SeenAddresses.insert(Curr.Location);
            FunctionEntry Entry;
            Entry.StartAddress = Curr.Location;
            Entry.EndAddress = 0;
            Entry.Name = QString("sub_%1").arg(Curr.Location, 0, 16);
            Entry.Size = 0;
            Functions.append(Entry);
        }
    }

    std::sort(Functions.begin(), Functions.end(),
        [](const FunctionEntry& A, const FunctionEntry& B) {
            return A.StartAddress < B.StartAddress;
        });

    for (int I = 0; I < Functions.size() - 1; ++I) {
        Functions[I].Size = static_cast<size_t>(Functions[I + 1].StartAddress - Functions[I].StartAddress);
        Functions[I].EndAddress = Functions[I].StartAddress + Functions[I].Size - 1;
    }
}

void FunctionList::PopulateList() {
    TreeWidget->clear();

    for (const auto& Func : Functions) {
        auto* Item = new QTreeWidgetItem();
        Item->setText(0, Func.Name);
        Item->setText(1, QString("0x%1").arg(Func.StartAddress, 16, 16, QChar('0')));
        Item->setText(2, Func.Size > 0 ? QString::number(Func.Size) : "?");
        Item->setText(3, Func.EndAddress > 0 ? QString("0x%1").arg(Func.EndAddress, 16, 16, QChar('0')) : "?");
        Item->setData(0, Qt::UserRole, QVariant::fromValue(Func.StartAddress));
        TreeWidget->addTopLevelItem(Item);
    }
}

void FunctionList::OnItemDoubleClicked(QTreeWidgetItem* Item, int Column) {
    Q_UNUSED(Column);
    if (!Item)
        return;

    Address Addr = Item->data(0, Qt::UserRole).toULongLong();
    emit FunctionSelected(Addr);
}

void FunctionList::LoadFromAnalysisDatabase(AnalysisDatabase* Db) {
    if (!Db) return;

    Functions.clear();

    QList<AnalyzedFunction> AllFuncs = Db->GetAllFunctions();

    for (const auto& Af : AllFuncs) {
        FunctionEntry Entry;
        Entry.StartAddress = Af.Start;
        Entry.EndAddress = Af.End;
        Entry.Name = Af.Name;
        Entry.Size = Af.Size;
        Functions.append(Entry);
    }

    std::sort(Functions.begin(), Functions.end(),
        [](const FunctionEntry& A, const FunctionEntry& B) {
            return A.StartAddress < B.StartAddress;
        });

    PopulateList();
}

void FunctionList::OnFilterChanged(const QString& Text) {
    for (int I = 0; I < TreeWidget->topLevelItemCount(); ++I) {
        QTreeWidgetItem* Item = TreeWidget->topLevelItem(I);
        bool Matches = Text.isEmpty() ||
            Item->text(0).contains(Text, Qt::CaseInsensitive) ||
            Item->text(1).contains(Text, Qt::CaseInsensitive);
        Item->setHidden(!Matches);
    }
}

}
