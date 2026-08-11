#include "FunctionList.h"
#include "Disassembler.h"
#include <fidra/ICore.h>
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <QVBoxLayout>
#include <QHeaderView>
#include <algorithm>

namespace Fidra {

FunctionTableModel::FunctionTableModel(QObject* Parent)
    : QAbstractTableModel(Parent)
{
}

int FunctionTableModel::rowCount(const QModelIndex& Parent) const {
    if (Parent.isValid()) return 0;
    return static_cast<int>(Functions.size());
}

int FunctionTableModel::columnCount(const QModelIndex& Parent) const {
    if (Parent.isValid()) return 0;
    return ColCount;
}

QVariant FunctionTableModel::data(const QModelIndex& Index, int Role) const {
    if (!Index.isValid() || Index.row() >= Functions.size())
        return {};

    const auto& Func = Functions[Index.row()];

    if (Role == Qt::DisplayRole) {
        switch (Index.column()) {
        case ColName:
            return Func.Name;
        case ColAddress:
            return QString("0x%1").arg(Func.StartAddress, 16, 16, QChar('0'));
        case ColSize:
            return Func.Size > 0 ? QString::number(Func.Size) : QStringLiteral("?");
        case ColEndAddress:
            return Func.EndAddress > 0 ? QString("0x%1").arg(Func.EndAddress, 16, 16, QChar('0')) : QStringLiteral("?");
        }
    } else if (Role == Qt::UserRole) {
        return QVariant::fromValue(Func.StartAddress);
    }

    return {};
}

QVariant FunctionTableModel::headerData(int Section, Qt::Orientation Orientation, int Role) const {
    if (Orientation != Qt::Horizontal || Role != Qt::DisplayRole)
        return {};

    switch (Section) {
    case ColName: return QStringLiteral("Name");
    case ColAddress: return QStringLiteral("Address");
    case ColSize: return QStringLiteral("Size");
    case ColEndAddress: return QStringLiteral("End Address");
    }
    return {};
}

void FunctionTableModel::SetFunctions(QList<FunctionEntry>&& Funcs) {
    beginResetModel();
    Functions = std::move(Funcs);
    endResetModel();
}

void FunctionTableModel::AppendFunctions(const QList<FunctionEntry>& Funcs) {
    if (Funcs.isEmpty()) return;
    int First = Functions.size();
    beginInsertRows(QModelIndex(), First, First + Funcs.size() - 1);
    Functions.append(Funcs);
    endInsertRows();
}

void FunctionTableModel::Clear() {
    beginResetModel();
    Functions.clear();
    endResetModel();
}

Address FunctionTableModel::AddressAt(int Row) const {
    if (Row < 0 || Row >= Functions.size())
        return 0;
    return Functions[Row].StartAddress;
}

FunctionList::FunctionList(QWidget* Parent)
    : QWidget(Parent)
    , CorePtr(nullptr)
    , LiveDb(nullptr)
    , BatchTimer(nullptr)
    , LastKnownCount(0)
{
    auto* Layout = new QVBoxLayout(this);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(2);

    FilterInput = new QLineEdit(this);
    FilterInput->setPlaceholderText("Filter functions...");
    Layout->addWidget(FilterInput);

    Model = new FunctionTableModel(this);

    ProxyModel = new QSortFilterProxyModel(this);
    ProxyModel->setSourceModel(Model);
    ProxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    ProxyModel->setFilterKeyColumn(-1);

    TreeView = new QTreeView(this);
    TreeView->setModel(ProxyModel);
    TreeView->setAlternatingRowColors(true);
    TreeView->setSelectionMode(QAbstractItemView::SingleSelection);
    TreeView->setRootIsDecorated(false);
    TreeView->setSortingEnabled(true);
    TreeView->header()->setStretchLastSection(true);
    TreeView->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    TreeView->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    TreeView->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    TreeView->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    TreeView->setUniformRowHeights(true);
    Layout->addWidget(TreeView);

    connect(FilterInput, &QLineEdit::textChanged, this, &FunctionList::OnFilterChanged);
    connect(TreeView, &QTreeView::doubleClicked, this, &FunctionList::OnItemDoubleClicked);
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

        std::sort(Functions.begin(), Functions.end(),
            [](const FunctionEntry& A, const FunctionEntry& B) {
                return A.StartAddress < B.StartAddress;
            });

        for (int I = 0; I < Functions.size() - 1; ++I) {
            Functions[I].Size = static_cast<size_t>(Functions[I + 1].StartAddress - Functions[I].StartAddress);
            Functions[I].EndAddress = Functions[I].StartAddress + Functions[I].Size - 1;
        }

        Model->SetFunctions(std::move(Functions));
        Functions.clear();
    }
}

void FunctionList::OnProcessDetached() {
    Functions.clear();
    Model->Clear();
}

void FunctionList::AnalyzeFunctions(Address StartAddr, size_t Size) {
    if (!CorePtr || !CorePtr->IsAttached())
        return;

    QByteArray Buffer(static_cast<qsizetype>(Size), '\0');
    if (CorePtr->ReadMemory(StartAddr, Buffer.data(), Size)) {
        DetectFunctions(Buffer, StartAddr);

        std::sort(Functions.begin(), Functions.end(),
            [](const FunctionEntry& A, const FunctionEntry& B) {
                return A.StartAddress < B.StartAddress;
            });

        for (int I = 0; I < Functions.size() - 1; ++I) {
            Functions[I].Size = static_cast<size_t>(Functions[I + 1].StartAddress - Functions[I].StartAddress);
            Functions[I].EndAddress = Functions[I].StartAddress + Functions[I].Size - 1;
        }

        Model->SetFunctions(std::move(Functions));
        Functions.clear();
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
}

void FunctionList::OnItemDoubleClicked(const QModelIndex& Index) {
    if (!Index.isValid())
        return;

    QModelIndex SourceIndex = ProxyModel->mapToSource(Index);
    Address Addr = Model->AddressAt(SourceIndex.row());
    if (Addr != 0)
        emit FunctionSelected(Addr);
}

void FunctionList::LoadFromAnalysisDatabase(AnalysisDatabase* Db) {
    if (!Db) return;

    QList<AnalyzedFunction> AllFuncs = Db->GetAllFunctions();

    QList<FunctionEntry> Entries;
    Entries.reserve(AllFuncs.size());

    for (const auto& Af : AllFuncs) {
        FunctionEntry Entry;
        Entry.StartAddress = Af.Start;
        Entry.EndAddress = Af.End;
        Entry.Name = Af.Name;
        Entry.Size = Af.Size;
        Entries.append(Entry);
    }

    std::sort(Entries.begin(), Entries.end(),
        [](const FunctionEntry& A, const FunctionEntry& B) {
            return A.StartAddress < B.StartAddress;
        });

    Model->SetFunctions(std::move(Entries));
}

void FunctionList::ConnectToDatabase(AnalysisDatabase* Db) {
    if (LiveDb) {
        disconnect(LiveDb, nullptr, this, nullptr);
    }
    LiveDb = Db;
    LastKnownCount = 0;
    PendingEntries.clear();

    if (!BatchTimer) {
        BatchTimer = new QTimer(this);
        BatchTimer->setSingleShot(true);
        connect(BatchTimer, &QTimer::timeout, this, &FunctionList::FlushPending);
    }

    if (LiveDb) {
        connect(LiveDb, &AnalysisDatabase::FunctionAdded, this, [this](Address, const QString&) {
            if (!BatchTimer->isActive()) {
                BatchTimer->start(500);
            }
        }, Qt::QueuedConnection);
    }
}

void FunctionList::FlushPending() {
    if (!LiveDb) return;

    int CurrentCount = LiveDb->FunctionCount();
    if (CurrentCount <= LastKnownCount) return;

    QList<AnalyzedFunction> AllFuncs = LiveDb->GetAllFunctions();

    QList<FunctionEntry> NewEntries;
    NewEntries.reserve(AllFuncs.size() - LastKnownCount);

    int Skip = LastKnownCount;
    for (const auto& Af : AllFuncs) {
        if (Skip > 0) { --Skip; continue; }
        FunctionEntry Entry;
        Entry.StartAddress = Af.Start;
        Entry.EndAddress = Af.End;
        Entry.Name = Af.Name;
        Entry.Size = Af.Size;
        NewEntries.append(Entry);
    }

    LastKnownCount = CurrentCount;

    if (!NewEntries.isEmpty()) {
        Model->AppendFunctions(NewEntries);
    }
}

void FunctionList::OnFilterChanged(const QString& Text) {
    ProxyModel->setFilterFixedString(Text);
}

}
