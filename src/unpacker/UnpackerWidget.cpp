#include "UnpackerWidget.h"
#include "IatRebuilder.h"
#include <fidra/ICore.h>
#include <QFile>
#include <QDateTime>
#include <QMap>
#include <QSet>

namespace Fidra {

UnpackerWidget::UnpackerWidget(QWidget* Parent)
    : QWidget(Parent)
    , CoreRef(nullptr)
    , TabWidget(nullptr)
    , ToolBar(nullptr)
    , HeadersTree(nullptr)
    , SectionsTable(nullptr)
    , ImportsTree(nullptr)
    , ExportsTable(nullptr)
    , ResourcesTree(nullptr)
    , TlsTree(nullptr)
    , RichTree(nullptr)
{
    SetupUi();
}

UnpackerWidget::~UnpackerWidget() = default;

void UnpackerWidget::SetCore(ICore* Core)
{
    CoreRef = Core;
}

void UnpackerWidget::SetupUi()
{
    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(0, 0, 0, 0);
    MainLayout->setSpacing(0);

    CreateToolBar();
    MainLayout->addWidget(ToolBar);

    TabWidget = new QTabWidget(this);

    HeadersTree = new QTreeWidget(this);
    HeadersTree->setHeaderLabels({"Field", "Value", "Description"});
    HeadersTree->setAlternatingRowColors(true);
    HeadersTree->header()->setStretchLastSection(true);
    HeadersTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    HeadersTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);

    SectionsTable = new QTableWidget(this);
    SectionsTable->setColumnCount(7);
    SectionsTable->setHorizontalHeaderLabels({"Name", "VirtualAddr", "VirtualSize", "RawSize", "RawOffset", "Characteristics", "Entropy"});
    SectionsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    SectionsTable->setAlternatingRowColors(true);
    SectionsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    SectionsTable->horizontalHeader()->setStretchLastSection(true);
    SectionsTable->verticalHeader()->setVisible(false);

    ImportsTree = new QTreeWidget(this);
    ImportsTree->setHeaderLabels({"Module / Function", "Hint", "Ordinal"});
    ImportsTree->setAlternatingRowColors(true);
    ImportsTree->header()->setStretchLastSection(true);
    ImportsTree->header()->setSectionResizeMode(0, QHeaderView::Stretch);

    ExportsTable = new QTableWidget(this);
    ExportsTable->setColumnCount(4);
    ExportsTable->setHorizontalHeaderLabels({"Ordinal", "Name", "Address", "Forwarder"});
    ExportsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ExportsTable->setAlternatingRowColors(true);
    ExportsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ExportsTable->horizontalHeader()->setStretchLastSection(true);
    ExportsTable->verticalHeader()->setVisible(false);

    ResourcesTree = new QTreeWidget(this);
    ResourcesTree->setHeaderLabels({"Name/ID", "Type", "Size", "Offset"});
    ResourcesTree->setAlternatingRowColors(true);
    ResourcesTree->header()->setStretchLastSection(true);

    TlsTree = new QTreeWidget(this);
    TlsTree->setHeaderLabels({"Index", "Callback Address"});
    TlsTree->setAlternatingRowColors(true);
    TlsTree->header()->setStretchLastSection(true);

    RichTree = new QTreeWidget(this);
    RichTree->setHeaderLabels({"ID", "Build ID", "Count"});
    RichTree->setAlternatingRowColors(true);
    RichTree->header()->setStretchLastSection(true);

    TabWidget->addTab(HeadersTree, "PE Headers");
    TabWidget->addTab(SectionsTable, "Sections");
    TabWidget->addTab(ImportsTree, "Imports");
    TabWidget->addTab(ExportsTable, "Exports");
    TabWidget->addTab(ResourcesTree, "Resources");
    TabWidget->addTab(TlsTree, "TLS");
    TabWidget->addTab(RichTree, "Rich Header");

    MainLayout->addWidget(TabWidget);
}

void UnpackerWidget::CreateToolBar()
{
    ToolBar = new QToolBar(this);
    ToolBar->setIconSize(QSize(16, 16));
    ToolBar->setMovable(false);

    auto* OpenAction = new QAction("Open File", this);
    OpenAction->setShortcut(QKeySequence::Open);
    connect(OpenAction, &QAction::triggered, this, &UnpackerWidget::OnOpenFile);
    ToolBar->addAction(OpenAction);

    ToolBar->addSeparator();

    auto* DumpAction = new QAction("Dump to File", this);
    connect(DumpAction, &QAction::triggered, this, &UnpackerWidget::OnDumpToFile);
    ToolBar->addAction(DumpAction);

    auto* RebuildAction = new QAction("Rebuild IAT", this);
    connect(RebuildAction, &QAction::triggered, this, &UnpackerWidget::OnRebuildIat);
    ToolBar->addAction(RebuildAction);
}

void UnpackerWidget::OnOpenFile()
{
    QString FilePath = QFileDialog::getOpenFileName(
        this,
        "Open PE File",
        QString(),
        "PE Files (*.exe *.dll *.sys *.drv);;All Files (*)"
    );

    if (!FilePath.isEmpty()) {
        LoadFile(FilePath);
    }
}

void UnpackerWidget::LoadFile(const QString& FilePath)
{
    Parser = std::make_unique<PeParser>();

    if (!Parser->ParseFile(FilePath)) {
        QMessageBox::warning(this, "Parse Error",
            QString("Failed to parse PE file:\n%1").arg(FilePath));
        Parser.reset();
        return;
    }

    CurrentFilePath = FilePath;
    Rebuilder = std::make_unique<IatRebuilder>(Parser.get());

    ClearAll();
    PopulateHeaders();
    PopulateSections();
    PopulateImports();
    PopulateExports();
    PopulateResources();
    PopulateTlsCallbacks();
    PopulateRichHeader();

    if (CoreRef) {
        CoreRef->Log(QString("Loaded PE: %1").arg(FilePath));
    }
}

void UnpackerWidget::LoadFromMemory(const QByteArray& Data, const QString& Name)
{
    Parser = std::make_unique<PeParser>();

    if (!Parser->ParseMemory(Data)) {
        QMessageBox::warning(this, "Parse Error",
            QString("Failed to parse PE from memory:\n%1").arg(Name));
        Parser.reset();
        return;
    }

    CurrentFilePath = Name;
    Rebuilder = std::make_unique<IatRebuilder>(Parser.get());

    ClearAll();
    PopulateHeaders();
    PopulateSections();
    PopulateImports();
    PopulateExports();
    PopulateResources();
    PopulateTlsCallbacks();
    PopulateRichHeader();

    if (CoreRef) {
        CoreRef->Log(QString("Loaded PE from memory: %1").arg(Name));
    }
}

void UnpackerWidget::ClearAll()
{
    HeadersTree->clear();
    SectionsTable->setRowCount(0);
    ImportsTree->clear();
    ExportsTable->setRowCount(0);
    ResourcesTree->clear();
    TlsTree->clear();
    RichTree->clear();
}

QString UnpackerWidget::FormatHex(uint64_t Value, int Width)
{
    return QString("0x%1").arg(Value, Width, 16, QChar('0')).toUpper().replace("0X", "0x");
}

void UnpackerWidget::AddHeaderField(QTreeWidgetItem* Parent, const QString& Field, const QString& Value, const QString& Desc)
{
    auto* Item = new QTreeWidgetItem(Parent);
    Item->setText(0, Field);
    Item->setText(1, Value);
    Item->setText(2, Desc);
}

void UnpackerWidget::PopulateHeaders()
{
    if (!Parser || !Parser->IsValid())
        return;

    const auto& DosHeader = Parser->GetDosHeader();
    auto* DosItem = new QTreeWidgetItem(HeadersTree);
    DosItem->setText(0, "DOS Header");
    DosItem->setExpanded(true);

    AddHeaderField(DosItem, "e_magic", FormatHex(DosHeader.Magic, 4), "MZ signature");
    AddHeaderField(DosItem, "e_cblp", QString::number(DosHeader.Cblp), "Bytes on last page");
    AddHeaderField(DosItem, "e_cp", QString::number(DosHeader.Cp), "Pages in file");
    AddHeaderField(DosItem, "e_crlc", QString::number(DosHeader.Crlc), "Relocations");
    AddHeaderField(DosItem, "e_cparhdr", QString::number(DosHeader.Cparhdr), "Size of header in paragraphs");
    AddHeaderField(DosItem, "e_minalloc", QString::number(DosHeader.Minalloc), "Minimum extra paragraphs");
    AddHeaderField(DosItem, "e_maxalloc", QString::number(DosHeader.Maxalloc), "Maximum extra paragraphs");
    AddHeaderField(DosItem, "e_ss", FormatHex(DosHeader.Ss, 4), "Initial SS");
    AddHeaderField(DosItem, "e_sp", FormatHex(DosHeader.Sp, 4), "Initial SP");
    AddHeaderField(DosItem, "e_csum", FormatHex(DosHeader.Csum, 4), "Checksum");
    AddHeaderField(DosItem, "e_ip", FormatHex(DosHeader.Ip, 4), "Initial IP");
    AddHeaderField(DosItem, "e_cs", FormatHex(DosHeader.Cs, 4), "Initial CS");
    AddHeaderField(DosItem, "e_lfarlc", FormatHex(DosHeader.Lfarlc, 4), "Relocation table offset");
    AddHeaderField(DosItem, "e_ovno", QString::number(DosHeader.Ovno), "Overlay number");
    AddHeaderField(DosItem, "e_oemid", FormatHex(DosHeader.Oemid, 4), "OEM identifier");
    AddHeaderField(DosItem, "e_oeminfo", FormatHex(DosHeader.Oeminfo, 4), "OEM information");
    AddHeaderField(DosItem, "e_lfanew", FormatHex(DosHeader.Lfanew, 8), "Offset to PE header");

    const auto& FileHeader = Parser->GetFileHeader();
    auto* FileItem = new QTreeWidgetItem(HeadersTree);
    FileItem->setText(0, "File Header");
    FileItem->setExpanded(true);

    QString MachineDesc;
    switch (FileHeader.Machine) {
    case 0x14C:  MachineDesc = "x86 (i386)"; break;
    case 0x8664: MachineDesc = "x64 (AMD64)"; break;
    case 0x1C0:  MachineDesc = "ARM"; break;
    case 0xAA64: MachineDesc = "ARM64"; break;
    default:     MachineDesc = "Unknown"; break;
    }

    AddHeaderField(FileItem, "Machine", FormatHex(FileHeader.Machine, 4), MachineDesc);
    AddHeaderField(FileItem, "NumberOfSections", QString::number(FileHeader.NumberOfSections), "");
    AddHeaderField(FileItem, "TimeDateStamp", FormatHex(FileHeader.TimeDateStamp, 8),
        QDateTime::fromSecsSinceEpoch(FileHeader.TimeDateStamp).toString("yyyy-MM-dd HH:mm:ss"));
    AddHeaderField(FileItem, "PointerToSymbolTable", FormatHex(FileHeader.PointerToSymbolTable, 8), "");
    AddHeaderField(FileItem, "NumberOfSymbols", QString::number(FileHeader.NumberOfSymbols), "");
    AddHeaderField(FileItem, "SizeOfOptionalHeader", QString::number(FileHeader.SizeOfOptionalHeader), "");

    QString CharDesc;
    if (FileHeader.Characteristics & 0x0002) CharDesc += "EXECUTABLE_IMAGE ";
    if (FileHeader.Characteristics & 0x0020) CharDesc += "LARGE_ADDRESS_AWARE ";
    if (FileHeader.Characteristics & 0x2000) CharDesc += "DLL ";
    if (FileHeader.Characteristics & 0x0100) CharDesc += "32BIT_MACHINE ";
    if (FileHeader.Characteristics & 0x0001) CharDesc += "RELOCS_STRIPPED ";
    AddHeaderField(FileItem, "Characteristics", FormatHex(FileHeader.Characteristics, 4), CharDesc.trimmed());

    const auto& OptHeader = Parser->GetOptionalHeader();
    auto* OptItem = new QTreeWidgetItem(HeadersTree);
    OptItem->setText(0, "Optional Header");
    OptItem->setExpanded(true);

    QString MagicDesc;
    switch (OptHeader.Magic) {
    case 0x10B: MagicDesc = "PE32"; break;
    case 0x20B: MagicDesc = "PE32+ (64-bit)"; break;
    default:    MagicDesc = "Unknown"; break;
    }

    AddHeaderField(OptItem, "Magic", FormatHex(OptHeader.Magic, 4), MagicDesc);
    AddHeaderField(OptItem, "MajorLinkerVersion", QString::number(OptHeader.MajorLinkerVersion), "");
    AddHeaderField(OptItem, "MinorLinkerVersion", QString::number(OptHeader.MinorLinkerVersion), "");
    AddHeaderField(OptItem, "SizeOfCode", FormatHex(OptHeader.SizeOfCode, 8), "");
    AddHeaderField(OptItem, "SizeOfInitializedData", FormatHex(OptHeader.SizeOfInitializedData, 8), "");
    AddHeaderField(OptItem, "SizeOfUninitializedData", FormatHex(OptHeader.SizeOfUninitializedData, 8), "");
    AddHeaderField(OptItem, "AddressOfEntryPoint", FormatHex(OptHeader.AddressOfEntryPoint, 8), "");
    AddHeaderField(OptItem, "BaseOfCode", FormatHex(OptHeader.BaseOfCode, 8), "");
    AddHeaderField(OptItem, "ImageBase", FormatHex(OptHeader.ImageBase, 16), "");
    AddHeaderField(OptItem, "SectionAlignment", FormatHex(OptHeader.SectionAlignment, 8), "");
    AddHeaderField(OptItem, "FileAlignment", FormatHex(OptHeader.FileAlignment, 8), "");
    AddHeaderField(OptItem, "MajorOSVersion", QString::number(OptHeader.MajorOperatingSystemVersion), "");
    AddHeaderField(OptItem, "MinorOSVersion", QString::number(OptHeader.MinorOperatingSystemVersion), "");
    AddHeaderField(OptItem, "MajorImageVersion", QString::number(OptHeader.MajorImageVersion), "");
    AddHeaderField(OptItem, "MinorImageVersion", QString::number(OptHeader.MinorImageVersion), "");
    AddHeaderField(OptItem, "MajorSubsystemVersion", QString::number(OptHeader.MajorSubsystemVersion), "");
    AddHeaderField(OptItem, "MinorSubsystemVersion", QString::number(OptHeader.MinorSubsystemVersion), "");
    AddHeaderField(OptItem, "Win32VersionValue", QString::number(OptHeader.Win32VersionValue), "");
    AddHeaderField(OptItem, "SizeOfImage", FormatHex(OptHeader.SizeOfImage, 8), "");
    AddHeaderField(OptItem, "SizeOfHeaders", FormatHex(OptHeader.SizeOfHeaders, 8), "");
    AddHeaderField(OptItem, "CheckSum", FormatHex(OptHeader.CheckSum, 8), "");

    QString SubsystemDesc;
    switch (OptHeader.Subsystem) {
    case 1:  SubsystemDesc = "NATIVE"; break;
    case 2:  SubsystemDesc = "WINDOWS_GUI"; break;
    case 3:  SubsystemDesc = "WINDOWS_CUI"; break;
    case 5:  SubsystemDesc = "OS2_CUI"; break;
    case 7:  SubsystemDesc = "POSIX_CUI"; break;
    case 9:  SubsystemDesc = "WINDOWS_CE_GUI"; break;
    case 10: SubsystemDesc = "EFI_APPLICATION"; break;
    case 11: SubsystemDesc = "EFI_BOOT_SERVICE_DRIVER"; break;
    case 12: SubsystemDesc = "EFI_RUNTIME_DRIVER"; break;
    case 13: SubsystemDesc = "EFI_ROM"; break;
    case 14: SubsystemDesc = "XBOX"; break;
    default: SubsystemDesc = "Unknown"; break;
    }
    AddHeaderField(OptItem, "Subsystem", FormatHex(OptHeader.Subsystem, 4), SubsystemDesc);

    QString DllCharDesc;
    if (OptHeader.DllCharacteristics & 0x0020) DllCharDesc += "HIGH_ENTROPY_VA ";
    if (OptHeader.DllCharacteristics & 0x0040) DllCharDesc += "DYNAMIC_BASE ";
    if (OptHeader.DllCharacteristics & 0x0080) DllCharDesc += "FORCE_INTEGRITY ";
    if (OptHeader.DllCharacteristics & 0x0100) DllCharDesc += "NX_COMPAT ";
    if (OptHeader.DllCharacteristics & 0x0200) DllCharDesc += "NO_ISOLATION ";
    if (OptHeader.DllCharacteristics & 0x0400) DllCharDesc += "NO_SEH ";
    if (OptHeader.DllCharacteristics & 0x0800) DllCharDesc += "NO_BIND ";
    if (OptHeader.DllCharacteristics & 0x1000) DllCharDesc += "APPCONTAINER ";
    if (OptHeader.DllCharacteristics & 0x2000) DllCharDesc += "WDM_DRIVER ";
    if (OptHeader.DllCharacteristics & 0x4000) DllCharDesc += "GUARD_CF ";
    if (OptHeader.DllCharacteristics & 0x8000) DllCharDesc += "TERMINAL_SERVER_AWARE ";
    AddHeaderField(OptItem, "DllCharacteristics", FormatHex(OptHeader.DllCharacteristics, 4), DllCharDesc.trimmed());

    AddHeaderField(OptItem, "SizeOfStackReserve", FormatHex(OptHeader.SizeOfStackReserve, 16), "");
    AddHeaderField(OptItem, "SizeOfStackCommit", FormatHex(OptHeader.SizeOfStackCommit, 16), "");
    AddHeaderField(OptItem, "SizeOfHeapReserve", FormatHex(OptHeader.SizeOfHeapReserve, 16), "");
    AddHeaderField(OptItem, "SizeOfHeapCommit", FormatHex(OptHeader.SizeOfHeapCommit, 16), "");
    AddHeaderField(OptItem, "LoaderFlags", FormatHex(OptHeader.LoaderFlags, 8), "");
    AddHeaderField(OptItem, "NumberOfRvaAndSizes", QString::number(OptHeader.NumberOfRvaAndSizes), "");

    const auto& DataDirs = OptHeader.DataDirectories;
    if (!DataDirs.isEmpty()) {
        auto* DataDirItem = new QTreeWidgetItem(OptItem);
        DataDirItem->setText(0, "Data Directories");

        static const QStringList DirNames = {
            "Export", "Import", "Resource", "Exception",
            "Certificate", "Base Relocation", "Debug", "Architecture",
            "Global Ptr", "TLS", "Load Config", "Bound Import",
            "IAT", "Delay Import", "CLR Runtime", "Reserved"
        };

        for (int I = 0; I < DataDirs.size(); ++I) {
            QString DirName = (I < DirNames.size()) ? DirNames[I] : QString("Directory %1").arg(I);
            auto* DirItem = new QTreeWidgetItem(DataDirItem);
            DirItem->setText(0, DirName);
            DirItem->setText(1, QString("RVA: %1  Size: %2")
                .arg(FormatHex(DataDirs[I].Rva, 8))
                .arg(FormatHex(DataDirs[I].Size, 8)));
        }
    }
}

void UnpackerWidget::PopulateSections()
{
    if (!Parser || !Parser->IsValid())
        return;

    const auto& Sections = Parser->GetSections();
    SectionsTable->setRowCount(Sections.size());

    for (int I = 0; I < Sections.size(); ++I) {
        const auto& Sec = Sections[I];

        SectionsTable->setItem(I, 0, new QTableWidgetItem(Sec.Name));
        SectionsTable->setItem(I, 1, new QTableWidgetItem(FormatHex(Sec.VirtualAddress, 8)));
        SectionsTable->setItem(I, 2, new QTableWidgetItem(FormatHex(Sec.VirtualSize, 8)));
        SectionsTable->setItem(I, 3, new QTableWidgetItem(FormatHex(Sec.RawSize, 8)));
        SectionsTable->setItem(I, 4, new QTableWidgetItem(FormatHex(Sec.RawOffset, 8)));

        QString CharStr;
        if (Sec.Characteristics & 0x00000020) CharStr += "CODE ";
        if (Sec.Characteristics & 0x00000040) CharStr += "INIT_DATA ";
        if (Sec.Characteristics & 0x00000080) CharStr += "UNINIT_DATA ";
        if (Sec.Characteristics & 0x20000000) CharStr += "EXEC ";
        if (Sec.Characteristics & 0x40000000) CharStr += "READ ";
        if (Sec.Characteristics & 0x80000000) CharStr += "WRITE ";
        auto* CharItem = new QTableWidgetItem(FormatHex(Sec.Characteristics, 8) + " " + CharStr.trimmed());
        SectionsTable->setItem(I, 5, CharItem);

        auto* EntropyItem = new QTableWidgetItem(QString::number(Sec.Entropy, 'f', 4));
        EntropyItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);

        if (Sec.Entropy > 7.0) {
            EntropyItem->setBackground(QColor(255, 180, 180));
        } else if (Sec.Entropy > 6.5) {
            EntropyItem->setBackground(QColor(255, 255, 180));
        }

        SectionsTable->setItem(I, 6, EntropyItem);
    }

    SectionsTable->resizeColumnsToContents();
}

void UnpackerWidget::PopulateImports()
{
    if (!Parser || !Parser->IsValid())
        return;

    const auto& Imports = Parser->GetImports();

    for (const auto& Dll : Imports) {
        auto* DllItem = new QTreeWidgetItem(ImportsTree);
        DllItem->setText(0, QString("%1 (%2 functions)").arg(Dll.DllName).arg(Dll.Functions.size()));
        DllItem->setExpanded(false);

        for (const auto& Func : Dll.Functions) {
            auto* FuncItem = new QTreeWidgetItem(DllItem);

            if (Func.Name.isEmpty()) {
                FuncItem->setText(0, QString("Ordinal #%1").arg(Func.Ordinal));
            } else {
                FuncItem->setText(0, Func.Name);
            }

            FuncItem->setText(1, QString::number(Func.Hint));
            FuncItem->setText(2, QString::number(Func.Ordinal));
        }
    }
}

void UnpackerWidget::PopulateExports()
{
    if (!Parser || !Parser->IsValid())
        return;

    const auto& Exports = Parser->GetExports();
    ExportsTable->setRowCount(Exports.size());

    for (int I = 0; I < Exports.size(); ++I) {
        const auto& Exp = Exports[I];

        auto* OrdItem = new QTableWidgetItem(QString::number(Exp.Ordinal));
        OrdItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        ExportsTable->setItem(I, 0, OrdItem);

        ExportsTable->setItem(I, 1, new QTableWidgetItem(Exp.Name));
        ExportsTable->setItem(I, 2, new QTableWidgetItem(FormatHex(Exp.Address, 8)));
        ExportsTable->setItem(I, 3, new QTableWidgetItem(Exp.ForwarderName));
    }

    ExportsTable->resizeColumnsToContents();
}

void UnpackerWidget::PopulateResources()
{
    if (!Parser || !Parser->IsValid())
        return;

    const auto& Resources = Parser->GetResources();
    QMap<int, QTreeWidgetItem*> DepthMap;

    for (const auto& Entry : Resources) {
        QTreeWidgetItem* Item;

        if (Entry.Depth == 0) {
            Item = new QTreeWidgetItem(ResourcesTree);
        } else {
            auto It = DepthMap.find(Entry.Depth - 1);
            if (It != DepthMap.end()) {
                Item = new QTreeWidgetItem(It.value());
            } else {
                Item = new QTreeWidgetItem(ResourcesTree);
            }
        }

        if (!Entry.Name.isEmpty()) {
            Item->setText(0, Entry.Name);
        } else {
            Item->setText(0, QString("#%1").arg(Entry.Id));
        }

        Item->setText(1, Entry.Type);
        Item->setText(2, Entry.Size > 0 ? QString::number(Entry.Size) : "");
        Item->setText(3, Entry.Offset > 0 ? FormatHex(Entry.Offset, 8) : "");

        DepthMap[Entry.Depth] = Item;
    }
}

void UnpackerWidget::PopulateTlsCallbacks()
{
    if (!Parser || !Parser->IsValid())
        return;

    const auto& Callbacks = Parser->GetTlsCallbacks();

    for (int I = 0; I < Callbacks.size(); ++I) {
        auto* Item = new QTreeWidgetItem(TlsTree);
        Item->setText(0, QString::number(I));
        Item->setText(1, FormatHex(Callbacks[I].Address, 16));
    }
}

void UnpackerWidget::PopulateRichHeader()
{
    if (!Parser || !Parser->IsValid())
        return;

    const auto& RichEntries = Parser->GetRichHeader();

    for (const auto& Entry : RichEntries) {
        auto* Item = new QTreeWidgetItem(RichTree);
        Item->setText(0, FormatHex(Entry.Id, 4));
        Item->setText(1, FormatHex(Entry.BuildId, 4));
        Item->setText(2, QString::number(Entry.Count));
    }
}

void UnpackerWidget::OnDumpToFile()
{
    if (!Parser || !Parser->IsValid()) {
        QMessageBox::information(this, "Dump", "No PE file loaded to dump.");
        return;
    }

    QString SavePath = QFileDialog::getSaveFileName(
        this,
        "Save Dumped PE",
        CurrentFilePath + ".dump",
        "PE Files (*.exe *.dll *.sys);;All Files (*)"
    );

    if (SavePath.isEmpty())
        return;

    const QByteArray& RawData = Parser->GetRawData();

    QFile OutFile(SavePath);
    if (!OutFile.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, "Dump Error",
            QString("Failed to write file:\n%1").arg(OutFile.errorString()));
        return;
    }

    OutFile.write(RawData);
    OutFile.close();

    if (CoreRef) {
        CoreRef->Log(QString("Dumped PE to: %1 (%2 bytes)").arg(SavePath).arg(RawData.size()));
    }

    QMessageBox::information(this, "Dump Complete",
        QString("PE dumped successfully.\nSize: %1 bytes").arg(RawData.size()));
}

void UnpackerWidget::OnRebuildIat()
{
    if (!Parser || !Parser->IsValid()) {
        QMessageBox::information(this, "Rebuild IAT", "No PE file loaded.");
        return;
    }

    if (!CoreRef || !CoreRef->IsAttached()) {
        QMessageBox::warning(this, "Rebuild IAT",
            "A process must be attached to rebuild the IAT.\n"
            "The IAT rebuilder scans process memory to resolve API addresses.");
        return;
    }

    if (!Rebuilder) {
        Rebuilder = std::make_unique<IatRebuilder>(Parser.get());
    }

    Rebuilder->SetCore(CoreRef);

    uint64_t BaseAddress = Parser->GetOptionalHeader().ImageBase;
    IatFixupResult Result = Rebuilder->ScanAndRebuild(BaseAddress);

    if (Result.Success) {
        ClearAll();
        PopulateHeaders();
        PopulateSections();
        PopulateImports();
        PopulateExports();
        PopulateResources();
        PopulateTlsCallbacks();
        PopulateRichHeader();

        QSet<QString> UniqueModules;
        for (const auto& Imp : Result.Imports) {
            if (!Imp.ModuleName.isEmpty())
                UniqueModules.insert(Imp.ModuleName);
        }
        int ModuleCount = UniqueModules.size();

        if (CoreRef) {
            CoreRef->Log(QString("IAT rebuilt: %1 imports resolved across %2 modules")
                .arg(Result.ResolvedEntries).arg(ModuleCount));
        }

        QMessageBox::information(this, "Rebuild IAT",
            QString("IAT reconstruction complete.\n"
                    "Resolved: %1 imports\n"
                    "Modules: %2\n"
                    "Unresolved: %3")
                .arg(Result.ResolvedEntries)
                .arg(ModuleCount)
                .arg(Result.FailedEntries));
    } else {
        QMessageBox::warning(this, "Rebuild IAT",
            QString("IAT reconstruction failed:\n%1").arg(Result.ErrorMessage));
    }
}

}
