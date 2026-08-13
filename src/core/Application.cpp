#include "Application.h"
#include "UndoManager.h"
#include "LogWidget.h"
#include "Theme.h"
#include <fidra/IModule.h>
#include "../analysis/AnalysisEngine.h"
#include "../analysis/AnalysisTypes.h"
#include <QApplication>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QFileDialog>
#include <QMessageBox>
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QHeaderView>
#include <QPushButton>
#include <QLineEdit>
#include <QTimer>
#include <QCloseEvent>
#include <QRegularExpression>
#include <algorithm>

#ifdef _WIN32
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")
#elif defined(__linux__)
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <elf.h>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <QFileInfo>
#endif

namespace Fidra {

Application::Application(QWidget* Parent)
    : QMainWindow(Parent)
    , ModuleTabs(nullptr)
    , LogOutput(nullptr)
    , LogDock(nullptr)
    , StatusProcessLabel(nullptr)
    , StatusArchLabel(nullptr)
    , AppSettings(new QSettings("Fidra", "Fidra", this))
    , ProcessAttached(false)
    , Engine(new AnalysisEngine(this))
    , Undo(new UndoManager(this))
    , AnalysisProgressBar(nullptr)
    , ProgressPanel(nullptr)
    , UndoAction(nullptr)
    , RedoAction(nullptr)
#ifdef _WIN32
    , ProcessHandle(nullptr)
#elif defined(__linux__)
    , MemFd(-1)
#endif
{
    setWindowTitle("Fidra");
    resize(1600, 900);
    setMinimumSize(1200, 700);

    AttachedProcess.Pid = 0;
    AttachedProcess.BaseAddress = 0;
    AttachedProcess.Arch = Architecture::Unknown;

    ApplyTheme();
    SetupMenuBar();
    SetupToolBar();
    SetupCentralWidget();
    SetupStatusBar();

    connect(Engine, &AnalysisEngine::ProgressChanged, this, [this](AnalysisProgress P) {
        OnAnalysisProgress(P.Percentage, P.StatusMessage);
        if (ProgressPanel) ProgressPanel->OnProgress(P);
    });
    connect(Engine, &AnalysisEngine::AnalysisFinished, this, &Application::OnAnalysisFinished);
    connect(Engine, &AnalysisEngine::LogMessage, this, [this](const QString& Msg) {
        Log(Msg, LogLevel::Info);
    });

    QByteArray SavedGeometry = AppSettings->value("geometry").toByteArray();
    if (!SavedGeometry.isEmpty()) {
        restoreGeometry(SavedGeometry);
    }
}

Application::~Application() {
    AppSettings->setValue("geometry", saveGeometry());
    AppSettings->setValue("windowState", saveState());

    for (auto* Module : Modules) {
        Module->Shutdown();
        delete Module;
    }

    DetachFromProcess();
}

QMainWindow* Application::MainWindow() {
    return this;
}

void Application::AddDockWidget(const QString& Title, QWidget* Widget, Qt::DockWidgetArea Area) {
    static const QHash<QString, Qt::DockWidgetArea> DockAreas = {
        {"Functions", Qt::LeftDockWidgetArea},
        {"Imports / Exports", Qt::LeftDockWidgetArea},
        {"Segments", Qt::LeftDockWidgetArea},
        {"Hex View", Qt::RightDockWidgetArea},
    };
    static const QSet<QString> HiddenByDefault = {
        "Registers", "Call Stack", "Breakpoints",
        "CFG Graph", "Cross References"
    };

    Qt::DockWidgetArea FinalArea = DockAreas.value(Title, Area);

    auto* Dock = new QDockWidget(Title, this);
    Dock->setWidget(Widget);
    Dock->setObjectName(Title);
    Dock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable | QDockWidget::DockWidgetClosable);
    QMainWindow::addDockWidget(FinalArea, Dock);
    DockWidgets[Widget] = Dock;

    if (HiddenByDefault.contains(Title)) {
        Dock->hide();
    }
}

void Application::RemoveDockWidget(QWidget* Widget) {
    if (DockWidgets.contains(Widget)) {
        auto* Dock = DockWidgets[Widget];
        QMainWindow::removeDockWidget(Dock);
        DockWidgets.remove(Widget);
        delete Dock;
    }
}

void Application::RegisterModule(IModule* Module) {
    Modules.append(Module);
    ModuleMap[Module->Name()] = Module;
}

IModule* Application::GetModule(const QString& Name) {
    return ModuleMap.value(Name, nullptr);
}

QList<IModule*> Application::GetAllModules() {
    return Modules;
}

void Application::Log(const QString& Message, LogLevel Level) {
    if (LogOutput) {
        LogOutput->AppendMessage(Message, Level);
    }
}

QSettings* Application::Settings() {
    return AppSettings;
}

ProcessInfo Application::CurrentProcess() const {
    return AttachedProcess;
}

void Application::AttachToProcess(uint32_t Pid) {
#ifdef _WIN32
    if (ProcessAttached) {
        DetachFromProcess();
    }

    ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
    if (!ProcessHandle) {
        Log(QString("Failed to attach to PID %1: Error %2").arg(Pid).arg(GetLastError()), LogLevel::Error);
        return;
    }

    AttachedProcess.Pid = Pid;

    char ExePath[MAX_PATH];
    DWORD PathSize = MAX_PATH;
    if (QueryFullProcessImageNameA(ProcessHandle, 0, ExePath, &PathSize)) {
        AttachedProcess.Path = QString::fromLocal8Bit(ExePath);
        AttachedProcess.Name = AttachedProcess.Path.section('\\', -1);
    }

    BOOL IsWow64 = FALSE;
    IsWow64Process(ProcessHandle, &IsWow64);
    AttachedProcess.Arch = IsWow64 ? Architecture::X86 : Architecture::X64;

    HMODULE BaseModule;
    DWORD Needed;
    if (EnumProcessModules(ProcessHandle, &BaseModule, sizeof(BaseModule), &Needed)) {
        AttachedProcess.BaseAddress = reinterpret_cast<Address>(BaseModule);
    }

    ProcessAttached = true;
    UpdateWindowTitle();
    Log(QString("Attached to %1 (PID: %2, Base: 0x%3)")
        .arg(AttachedProcess.Name)
        .arg(Pid)
        .arg(AttachedProcess.BaseAddress, 0, 16), LogLevel::Info);

    for (auto& Callback : AttachCallbacks) {
        Callback(Pid);
    }

    for (auto* Module : Modules) {
        Module->OnProcessAttached(AttachedProcess);
    }

    emit ProcessAttachedSignal(Pid);
#elif defined(__linux__)
    if (ProcessAttached) {
        DetachFromProcess();
    }

    QString MemPath = QString("/proc/%1/mem").arg(Pid);
    MemFd = ::open(MemPath.toUtf8().constData(), O_RDONLY);
    if (MemFd < 0) {
        Log(QString("Failed to open %1: %2").arg(MemPath, QString::fromUtf8(strerror(errno))), LogLevel::Error);
        return;
    }

    AttachedProcess.Pid = Pid;

    QFile CommFile(QString("/proc/%1/comm").arg(Pid));
    if (CommFile.open(QIODevice::ReadOnly)) {
        AttachedProcess.Name = QString::fromUtf8(CommFile.readAll()).trimmed();
        CommFile.close();
    }

    char LinkBuf[4096];
    QString ExeLink = QString("/proc/%1/exe").arg(Pid);
    ssize_t LinkLen = readlink(ExeLink.toUtf8().constData(), LinkBuf, sizeof(LinkBuf) - 1);
    if (LinkLen > 0) {
        LinkBuf[LinkLen] = '\0';
        AttachedProcess.Path = QString::fromUtf8(LinkBuf);
        if (AttachedProcess.Name.isEmpty()) {
            AttachedProcess.Name = QFileInfo(AttachedProcess.Path).fileName();
        }
    }

    AttachedProcess.Arch = Architecture::X64;
    QFile MapsFile(QString("/proc/%1/maps").arg(Pid));
    if (MapsFile.open(QIODevice::ReadOnly)) {
        QString FirstLine = QString::fromUtf8(MapsFile.readLine());
        MapsFile.close();
        if (!FirstLine.isEmpty()) {
            QString AddrPart = FirstLine.section('-', 0, 0);
            if (AddrPart.length() <= 8) {
                AttachedProcess.Arch = Architecture::X86;
            }
        }
    }

    AttachedProcess.BaseAddress = 0;
    QFile MapsFile2(QString("/proc/%1/maps").arg(Pid));
    if (MapsFile2.open(QIODevice::ReadOnly)) {
        while (!MapsFile2.atEnd()) {
            QString Line = QString::fromUtf8(MapsFile2.readLine()).trimmed();
            if (Line.contains(AttachedProcess.Name) || Line.contains(".exe") || Line.contains(".so")) {
                QString AddrRange = Line.section(' ', 0, 0);
                QString StartStr = AddrRange.section('-', 0, 0);
                bool Ok = false;
                Address StartAddr = StartStr.toULongLong(&Ok, 16);
                if (Ok && StartAddr > 0) {
                    uint8_t ElfMagic[4];
                    if (pread(MemFd, ElfMagic, 4, StartAddr) == 4) {
                        if (ElfMagic[0] == 0x7F && ElfMagic[1] == 'E' && ElfMagic[2] == 'L' && ElfMagic[3] == 'F') {
                            AttachedProcess.BaseAddress = StartAddr;
                            break;
                        }
                        if (ElfMagic[0] == 'M' && ElfMagic[1] == 'Z') {
                            AttachedProcess.BaseAddress = StartAddr;
                            break;
                        }
                    }
                }
            }
        }
        MapsFile2.close();
    }

    ProcessAttached = true;
    UpdateWindowTitle();
    Log(QString("Attached to %1 (PID: %2, Base: 0x%3)")
        .arg(AttachedProcess.Name)
        .arg(Pid)
        .arg(AttachedProcess.BaseAddress, 0, 16), LogLevel::Info);

    for (auto& Callback : AttachCallbacks) {
        Callback(Pid);
    }

    for (auto* Module : Modules) {
        Module->OnProcessAttached(AttachedProcess);
    }

    emit ProcessAttachedSignal(Pid);
#else
    Q_UNUSED(Pid);
    Log("Process attachment not supported on this platform", LogLevel::Error);
#endif
}

void Application::DetachFromProcess() {
    if (!ProcessAttached) return;

    for (auto* Module : Modules) {
        Module->OnProcessDetached();
    }

    for (auto& Callback : DetachCallbacks) {
        Callback(AttachedProcess.Pid);
    }

#ifdef _WIN32
    if (ProcessHandle) {
        CloseHandle(ProcessHandle);
        ProcessHandle = nullptr;
    }
#elif defined(__linux__)
    if (MemFd >= 0) {
        ::close(MemFd);
        MemFd = -1;
    }
#endif

    uint32_t OldPid = AttachedProcess.Pid;
    AttachedProcess = ProcessInfo{};
    AttachedProcess.Arch = Architecture::Unknown;
    ProcessAttached = false;
    UpdateWindowTitle();
    Log(QString("Detached from PID %1").arg(OldPid), LogLevel::Info);

    emit ProcessDetachedSignal();
}

bool Application::IsAttached() const {
    return ProcessAttached;
}

bool Application::ReadMemory(Address Addr, void* Buffer, size_t Size) {
#ifdef _WIN32
    if (!ProcessHandle) return false;
    SIZE_T BytesRead = 0;
    return ::ReadProcessMemory(ProcessHandle, reinterpret_cast<LPCVOID>(Addr), Buffer, Size, &BytesRead) && BytesRead == Size;
#elif defined(__linux__)
    if (MemFd < 0) return false;
    ssize_t BytesRead = pread(MemFd, Buffer, Size, static_cast<off_t>(Addr));
    return BytesRead == static_cast<ssize_t>(Size);
#else
    Q_UNUSED(Addr); Q_UNUSED(Buffer); Q_UNUSED(Size);
    return false;
#endif
}

bool Application::WriteMemory(Address Addr, const void* Buffer, size_t Size) {
#ifdef _WIN32
    if (!ProcessHandle) return false;
    SIZE_T BytesWritten = 0;
    return ::WriteProcessMemory(ProcessHandle, reinterpret_cast<LPVOID>(Addr), Buffer, Size, &BytesWritten) && BytesWritten == Size;
#elif defined(__linux__)
    if (!ProcessAttached) return false;
    QString MemPath = QString("/proc/%1/mem").arg(AttachedProcess.Pid);
    int WriteFd = ::open(MemPath.toUtf8().constData(), O_WRONLY);
    if (WriteFd < 0) return false;
    ssize_t BytesWritten = pwrite(WriteFd, Buffer, Size, static_cast<off_t>(Addr));
    ::close(WriteFd);
    return BytesWritten == static_cast<ssize_t>(Size);
#else
    Q_UNUSED(Addr); Q_UNUSED(Buffer); Q_UNUSED(Size);
    return false;
#endif
}

QList<MemoryRegion> Application::GetMemoryRegions() {
    QList<MemoryRegion> Regions;
#ifdef _WIN32
    if (!ProcessHandle) return Regions;

    MEMORY_BASIC_INFORMATION Mbi;
    Address CurrentAddress = 0;

    while (VirtualQueryEx(ProcessHandle, reinterpret_cast<LPCVOID>(CurrentAddress), &Mbi, sizeof(Mbi))) {
        if (Mbi.State == MEM_COMMIT && !(Mbi.Protect & PAGE_NOACCESS) && !(Mbi.Protect & PAGE_GUARD)) {
            MemoryRegion Region;
            Region.Base = reinterpret_cast<Address>(Mbi.BaseAddress);
            Region.Size = Mbi.RegionSize;
            Region.Protection = Mbi.Protect;

            char ModuleName[MAX_PATH] = {};
            if (GetMappedFileNameA(ProcessHandle, Mbi.BaseAddress, ModuleName, MAX_PATH)) {
                Region.ModuleName = QString::fromLocal8Bit(ModuleName).section('\\', -1);
            }

            Regions.append(Region);
        }
        CurrentAddress = reinterpret_cast<Address>(Mbi.BaseAddress) + Mbi.RegionSize;
        if (CurrentAddress == 0) break;
    }
#elif defined(__linux__)
    if (!ProcessAttached) return Regions;

    QFile MapsFile(QString("/proc/%1/maps").arg(AttachedProcess.Pid));
    if (!MapsFile.open(QIODevice::ReadOnly)) return Regions;

    while (!MapsFile.atEnd()) {
        QString Line = QString::fromUtf8(MapsFile.readLine()).trimmed();
        if (Line.isEmpty()) continue;

        QStringList Parts = Line.split(QRegularExpression("\\s+"));
        if (Parts.size() < 2) continue;

        QString AddrRange = Parts[0];
        QString Perms = Parts[1];

        if (!Perms.contains('r')) continue;

        QStringList Addrs = AddrRange.split('-');
        if (Addrs.size() != 2) continue;

        bool OkLo = false, OkHi = false;
        Address Lo = Addrs[0].toULongLong(&OkLo, 16);
        Address Hi = Addrs[1].toULongLong(&OkHi, 16);
        if (!OkLo || !OkHi || Hi <= Lo) continue;

        MemoryRegion Region;
        Region.Base = Lo;
        Region.Size = Hi - Lo;

        uint32_t Prot = 0;
        if (Perms.contains('r')) Prot |= 1;
        if (Perms.contains('w')) Prot |= 2;
        if (Perms.contains('x')) Prot |= 4;
        Region.Protection = Prot;

        if (Parts.size() >= 6) {
            QString PathStr = Parts.last();
            if (!PathStr.startsWith('[')) {
                Region.ModuleName = QFileInfo(PathStr).fileName();
            }
        }

        Regions.append(Region);
    }
    MapsFile.close();
#endif
    return Regions;
}

QList<ProcessInfo> Application::GetProcessList() {
    QList<ProcessInfo> Processes;
#ifdef _WIN32
    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE) return Processes;

    PROCESSENTRY32W Pe;
    Pe.dwSize = sizeof(Pe);

    if (Process32FirstW(Snapshot, &Pe)) {
        do {
            ProcessInfo Info;
            Info.Pid = Pe.th32ProcessID;
            Info.Name = QString::fromWCharArray(Pe.szExeFile);
            Info.Arch = Architecture::Unknown;
            Info.BaseAddress = 0;

            HANDLE TempHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Info.Pid);
            if (TempHandle) {
                WCHAR ExePath[MAX_PATH];
                DWORD PathSize = MAX_PATH;
                if (QueryFullProcessImageNameW(TempHandle, 0, ExePath, &PathSize)) {
                    Info.Path = QString::fromWCharArray(ExePath);
                }
                BOOL IsWow64 = FALSE;
                IsWow64Process(TempHandle, &IsWow64);
                Info.Arch = IsWow64 ? Architecture::X86 : Architecture::X64;
                CloseHandle(TempHandle);
            }

            Processes.append(Info);
        } while (Process32NextW(Snapshot, &Pe));
    }

    CloseHandle(Snapshot);
#elif defined(__linux__)
    QDir ProcDir("/proc");
    QStringList Entries = ProcDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);

    for (const QString& Entry : Entries) {
        bool IsNumeric = false;
        uint32_t Pid = Entry.toUInt(&IsNumeric);
        if (!IsNumeric || Pid == 0) continue;

        ProcessInfo Info;
        Info.Pid = Pid;
        Info.Arch = Architecture::Unknown;
        Info.BaseAddress = 0;

        QFile CommFile(QString("/proc/%1/comm").arg(Pid));
        if (CommFile.open(QIODevice::ReadOnly)) {
            Info.Name = QString::fromUtf8(CommFile.readAll()).trimmed();
            CommFile.close();
        }

        if (Info.Name.isEmpty()) continue;

        char LinkBuf[4096];
        QString ExeLink = QString("/proc/%1/exe").arg(Pid);
        ssize_t LinkLen = readlink(ExeLink.toUtf8().constData(), LinkBuf, sizeof(LinkBuf) - 1);
        if (LinkLen > 0) {
            LinkBuf[LinkLen] = '\0';
            Info.Path = QString::fromUtf8(LinkBuf);
        }

        QFile MapsFile(QString("/proc/%1/maps").arg(Pid));
        if (MapsFile.open(QIODevice::ReadOnly)) {
            QString FirstLine = QString::fromUtf8(MapsFile.readLine());
            MapsFile.close();
            if (!FirstLine.isEmpty()) {
                QString AddrPart = FirstLine.section('-', 0, 0);
                Info.Arch = (AddrPart.length() > 8) ? Architecture::X64 : Architecture::X86;
            }
        }

        Processes.append(Info);
    }
#endif
    return Processes;
}

void Application::OnProcessAttached(ProcessCallback Callback) {
    AttachCallbacks.append(std::move(Callback));
}

void Application::OnProcessDetached(ProcessCallback Callback) {
    DetachCallbacks.append(std::move(Callback));
}

void Application::NavigateToFunction(Address Addr) {
    for (auto& Cb : FunctionNavCallbacks) {
        Cb(Addr);
    }
}

void Application::OnFunctionNavigated(AddressCallback Callback) {
    FunctionNavCallbacks.append(std::move(Callback));
}

void Application::OnAnalysisStarted(AnalysisCallback Callback) {
    AnalysisStartCallbacks.append(std::move(Callback));
}

void Application::InitializeModules() {
    std::sort(Modules.begin(), Modules.end(), [](IModule* A, IModule* B) {
        return A->Priority() < B->Priority();
    });

    for (auto* Module : Modules) {
        Module->Initialize(this);
        auto* Widget = Module->CreateMainWidget(ModuleTabs);
        if (Widget) {
            ModuleTabs->addTab(Widget, Module->Icon(), Module->Name());
        }
        auto DockList = Module->CreateDockWidgets(this);
        for (auto& [DockTitle, DockWidget] : DockList) {
            AddDockWidget(DockTitle, DockWidget);
        }

        Module->ContributeToMenu(menuBar());

        auto* ToolBar = findChild<QToolBar*>("mainToolBar");
        if (ToolBar) {
            Module->ContributeToToolBar(ToolBar);
        }
    }

    for (auto* Module : Modules) {
        Module->PostInitialize(this);
    }

    QByteArray SavedState = AppSettings->value("windowState").toByteArray();
    if (!SavedState.isEmpty()) {
        restoreState(SavedState);
    } else {
        SetupDockLayout();
    }

    Log(QString("Loaded %1 modules").arg(Modules.size()), LogLevel::Info);
}

void Application::SetupDockLayout() {
    setCorner(Qt::BottomLeftCorner, Qt::LeftDockWidgetArea);
    setCorner(Qt::BottomRightCorner, Qt::RightDockWidgetArea);

    QList<QDockWidget*> LeftGroup;
    QList<QDockWidget*> BottomGroup;

    for (auto It = DockWidgets.begin(); It != DockWidgets.end(); ++It) {
        QDockWidget* Dock = It.value();
        if (!Dock || !Dock->isVisible()) continue;

        Qt::DockWidgetArea Area = dockWidgetArea(Dock);
        if (Area == Qt::LeftDockWidgetArea) {
            LeftGroup.append(Dock);
        } else if (Area == Qt::BottomDockWidgetArea) {
            BottomGroup.append(Dock);
        }
    }

    for (int I = 1; I < LeftGroup.size(); ++I) {
        tabifyDockWidget(LeftGroup[0], LeftGroup[I]);
    }
    if (!LeftGroup.isEmpty()) LeftGroup[0]->raise();

    if (LogDock && LogDock->isVisible() && !BottomGroup.contains(LogDock)) {
        BottomGroup.prepend(LogDock);
    }
    for (int I = 1; I < BottomGroup.size(); ++I) {
        tabifyDockWidget(BottomGroup[0], BottomGroup[I]);
    }
    if (LogDock && LogDock->isVisible()) LogDock->raise();
}

void Application::SetupMenuBar() {
    auto* FileMenu = menuBar()->addMenu("&File");
    FileMenu->addAction("&Open File...", this, [this]() {
        auto Path = QFileDialog::getOpenFileName(this, "Open File", QString(),
            "All Supported (*.exe *.dll *.sys *.so *.dylib *.o *.elf *.bin);;"
            "Executables (*.exe *.dll *.sys);;"
            "ELF Files (*.so *.elf *.o);;"
            "Raw Binary (*.bin);;"
            "All Files (*)");
        if (!Path.isEmpty()) {
            OpenBinaryFile(Path);
        }
    }, QKeySequence::Open);

    FileMenu->addSeparator();

    FileMenu->addAction("Attach to &Process...", this, &Application::ShowAttachDialog, QKeySequence(Qt::CTRL | Qt::Key_P));
    FileMenu->addAction("&Detach", this, &Application::DetachFromProcess);

    FileMenu->addSeparator();
    FileMenu->addAction("E&xit", this, &QMainWindow::close, QKeySequence::Quit);

    auto* EditMenu = menuBar()->addMenu("&Edit");

    UndoAction = EditMenu->addAction("&Undo", this, [this]() { Undo->Undo(); }, QKeySequence(Qt::CTRL | Qt::Key_Z));
    UndoAction->setEnabled(false);

    RedoAction = EditMenu->addAction("&Redo", this, [this]() { Undo->Redo(); }, QKeySequence(Qt::CTRL | Qt::Key_Y));
    RedoAction->setEnabled(false);

    connect(Undo, &UndoManager::UndoRedoChanged, this, [this]() {
        UndoAction->setEnabled(Undo->CanUndo());
        RedoAction->setEnabled(Undo->CanRedo());
        UndoAction->setText(Undo->CanUndo() ? QString("&Undo %1").arg(Undo->UndoText()) : QString("&Undo"));
        RedoAction->setText(Undo->CanRedo() ? QString("&Redo %1").arg(Undo->RedoText()) : QString("&Redo"));
    });

    EditMenu->addSeparator();
    EditMenu->addAction("&Settings...", this, []() {});

    auto* ViewMenu = menuBar()->addMenu("&View");
    ViewMenu->addAction("Show &Log", this, [this]() {
        if (LogDock) LogDock->show();
    });
    ViewMenu->addAction("&Reset Layout", this, [this]() {
        AppSettings->remove("windowState");
        for (auto It = DockWidgets.begin(); It != DockWidgets.end(); ++It) {
            QDockWidget* Dock = It.value();
            QMainWindow::removeDockWidget(Dock);
        }
        if (LogDock) QMainWindow::removeDockWidget(LogDock);

        static const QHash<QString, Qt::DockWidgetArea> DockAreas = {
            {"Functions", Qt::LeftDockWidgetArea},
            {"Imports / Exports", Qt::LeftDockWidgetArea},
            {"Segments", Qt::LeftDockWidgetArea},
            {"Hex View", Qt::RightDockWidgetArea},
        };
        static const QSet<QString> HiddenByDefault = {
            "Registers", "Call Stack", "Breakpoints",
            "CFG Graph", "Cross References"
        };
        for (auto It = DockWidgets.begin(); It != DockWidgets.end(); ++It) {
            QDockWidget* Dock = It.value();
            Qt::DockWidgetArea Area = DockAreas.value(Dock->objectName(), Qt::BottomDockWidgetArea);
            QMainWindow::addDockWidget(Area, Dock);
            if (HiddenByDefault.contains(Dock->objectName())) {
                Dock->hide();
            } else {
                Dock->show();
            }
        }
        if (LogDock) {
            QMainWindow::addDockWidget(Qt::BottomDockWidgetArea, LogDock);
            LogDock->show();
        }
        SetupDockLayout();
    });

    menuBar()->addMenu("&Debug");
    menuBar()->addMenu("&Tools");
    menuBar()->addMenu("&Window");

    auto* HelpMenu = menuBar()->addMenu("&Help");
    HelpMenu->addAction("&About Fidra", this, [this]() {
        QMessageBox::about(this, "About Fidra",
            "<h2>Fidra</h2>"
            "<p>Version 1.0.0</p>"
            "<p>Advanced Interactive Disassembler & Analyzer</p>"
            "<p>Reverse engineering, debugging, memory analysis, network inspection, web security testing.</p>");
    });
}

void Application::SetupToolBar() {
    auto* ToolBar = new QToolBar("Main", this);
    ToolBar->setObjectName("mainToolBar");
    ToolBar->setMovable(false);
    ToolBar->setIconSize(QSize(20, 20));

    ToolBar->addAction(style()->standardIcon(QStyle::SP_DialogOpenButton), "Open", this, [this]() {
        auto Path = QFileDialog::getOpenFileName(this, "Open File", QString(),
            "All Supported (*.exe *.dll *.sys *.so *.dylib *.o *.elf *.bin);;"
            "All Files (*)");
        if (!Path.isEmpty()) {
            OpenBinaryFile(Path);
        }
    });

    ToolBar->addAction(style()->standardIcon(QStyle::SP_ComputerIcon), "Attach", this, &Application::ShowAttachDialog);

    ToolBar->addSeparator();

    addToolBar(ToolBar);
}

void Application::SetupStatusBar() {
    StatusProcessLabel = new QLabel("No process");
    StatusArchLabel = new QLabel("");

    statusBar()->addPermanentWidget(StatusProcessLabel);
    statusBar()->addPermanentWidget(StatusArchLabel);
    statusBar()->showMessage("Ready");
}

void Application::SetupCentralWidget() {
    auto* CentralWidget = new QWidget(this);
    auto* Layout = new QVBoxLayout(CentralWidget);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(0);

    ProgressPanel = new AnalysisProgressWidget(CentralWidget);
    ProgressPanel->hide();
    Layout->addWidget(ProgressPanel);

    ModuleTabs = new QTabWidget(CentralWidget);
    ModuleTabs->setTabPosition(QTabWidget::North);
    ModuleTabs->setDocumentMode(true);
    ModuleTabs->setMovable(true);
    Layout->addWidget(ModuleTabs);

    setCentralWidget(CentralWidget);

    LogOutput = new LogWidget(this);
    LogDock = new QDockWidget("Output", this);
    LogDock->setObjectName("logDock");
    LogDock->setWidget(LogOutput);
    LogDock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable | QDockWidget::DockWidgetClosable);
    QMainWindow::addDockWidget(Qt::BottomDockWidgetArea, LogDock);
}

void Application::ApplyTheme() {
    Theme::Apply(qApp);
}

void Application::ShowAttachDialog() {
    auto* Dialog = new QDialog(this);
    Dialog->setWindowTitle("Attach to Process");
    Dialog->resize(600, 500);
    Dialog->setModal(true);

    auto* Layout = new QVBoxLayout(Dialog);

    auto* FilterEdit = new QLineEdit(Dialog);
    FilterEdit->setPlaceholderText("Filter processes...");
    Layout->addWidget(FilterEdit);

    auto* Table = new QTableWidget(Dialog);
    Table->setColumnCount(4);
    Table->setHorizontalHeaderLabels({"PID", "Name", "Architecture", "Path"});
    Table->horizontalHeader()->setStretchLastSection(true);
    Table->setSelectionBehavior(QAbstractItemView::SelectRows);
    Table->setSelectionMode(QAbstractItemView::SingleSelection);
    Table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    Table->verticalHeader()->hide();
    Table->setSortingEnabled(true);
    Layout->addWidget(Table);

    auto ProcessList = GetProcessList();
    Table->setRowCount(ProcessList.size());
    for (int Row = 0; Row < ProcessList.size(); ++Row) {
        auto& Info = ProcessList[Row];
        Table->setItem(Row, 0, new QTableWidgetItem(QString::number(Info.Pid)));
        Table->setItem(Row, 1, new QTableWidgetItem(Info.Name));
        QString ArchStr = Info.Arch == Architecture::X86 ? "x86" : Info.Arch == Architecture::X64 ? "x64" : "?";
        Table->setItem(Row, 2, new QTableWidgetItem(ArchStr));
        Table->setItem(Row, 3, new QTableWidgetItem(Info.Path));
    }

    connect(FilterEdit, &QLineEdit::textChanged, [Table](const QString& Text) {
        for (int Row = 0; Row < Table->rowCount(); ++Row) {
            bool Visible = Text.isEmpty();
            for (int Col = 0; Col < Table->columnCount() && !Visible; ++Col) {
                auto* Item = Table->item(Row, Col);
                if (Item && Item->text().contains(Text, Qt::CaseInsensitive)) {
                    Visible = true;
                }
            }
            Table->setRowHidden(Row, !Visible);
        }
    });

    auto* ButtonLayout = new QHBoxLayout();
    auto* RefreshBtn = new QPushButton("Refresh", Dialog);
    auto* AttachBtn = new QPushButton("Attach", Dialog);
    auto* CancelBtn = new QPushButton("Cancel", Dialog);
    ButtonLayout->addWidget(RefreshBtn);
    ButtonLayout->addStretch();
    ButtonLayout->addWidget(AttachBtn);
    ButtonLayout->addWidget(CancelBtn);
    Layout->addLayout(ButtonLayout);

    connect(CancelBtn, &QPushButton::clicked, Dialog, &QDialog::reject);
    connect(AttachBtn, &QPushButton::clicked, [this, Table, Dialog]() {
        auto Selected = Table->selectedItems();
        if (!Selected.isEmpty()) {
            uint32_t Pid = Table->item(Selected.first()->row(), 0)->text().toUInt();
            AttachToProcess(Pid);
            Dialog->accept();
        }
    });
    connect(Table, &QTableWidget::doubleClicked, [this, Table, Dialog](const QModelIndex& Index) {
        uint32_t Pid = Table->item(Index.row(), 0)->text().toUInt();
        AttachToProcess(Pid);
        Dialog->accept();
    });
    connect(RefreshBtn, &QPushButton::clicked, [this, Table]() {
        auto NewList = GetProcessList();
        Table->setRowCount(NewList.size());
        for (int Row = 0; Row < NewList.size(); ++Row) {
            auto& Info = NewList[Row];
            Table->setItem(Row, 0, new QTableWidgetItem(QString::number(Info.Pid)));
            Table->setItem(Row, 1, new QTableWidgetItem(Info.Name));
            QString ArchStr = Info.Arch == Architecture::X86 ? "x86" : Info.Arch == Architecture::X64 ? "x64" : "?";
            Table->setItem(Row, 2, new QTableWidgetItem(ArchStr));
            Table->setItem(Row, 3, new QTableWidgetItem(Info.Path));
        }
    });

    Dialog->exec();
    delete Dialog;
}

void Application::UpdateWindowTitle() {
    if (ProcessAttached) {
        setWindowTitle(QString("Fidra - %1 (PID: %2)").arg(AttachedProcess.Name).arg(AttachedProcess.Pid));
    } else if (Engine && Engine->Database()) {
        BinaryInfo Info = Engine->Database()->GetBinaryInfo();
        if (!Info.FileName.isEmpty()) {
            setWindowTitle(QString("Fidra - %1").arg(Info.FileName));
        } else {
            setWindowTitle("Fidra");
        }
    } else {
        setWindowTitle("Fidra");
    }
}

void Application::OpenBinaryFile(const QString& FilePath) {
    if (Engine->IsAnalyzing()) {
        Engine->CancelAnalysis();
    }

    Log(QString("Loading: %1").arg(FilePath), LogLevel::Info);

    if (!AnalysisProgressBar) {
        AnalysisProgressBar = new QProgressBar(this);
        AnalysisProgressBar->setMaximumHeight(16);
        AnalysisProgressBar->setTextVisible(true);
        AnalysisProgressBar->setFormat("%v% - %m");
        statusBar()->addWidget(AnalysisProgressBar, 1);
    }
    AnalysisProgressBar->setValue(0);
    AnalysisProgressBar->show();

    ProgressPanel->Reset();
    ProgressPanel->show();

    if (!Engine->LoadFile(FilePath)) {
        Log("Failed to load file: " + FilePath, LogLevel::Error);
        AnalysisProgressBar->hide();
        return;
    }

    AnalysisDatabase* Db = Engine->Database();
    ProgressPanel->SetDatabase(Db);

    for (auto& Cb : AnalysisStartCallbacks) {
        Cb(Db);
    }

    UpdateWindowTitle();
}

void Application::OnAnalysisProgress(int Percentage, const QString& Message) {
    if (AnalysisProgressBar) {
        AnalysisProgressBar->setValue(Percentage);
        AnalysisProgressBar->setFormat(QString("%1 - %p%").arg(Message));
    }
    statusBar()->showMessage(Message);
}

void Application::OnAnalysisFinished(bool Success) {
    if (AnalysisProgressBar) {
        AnalysisProgressBar->hide();
    }
    if (ProgressPanel) {
        ProgressPanel->OnFinished(Success);
    }

    if (Success) {
        AnalysisDatabase* Db = Engine->Database();
        int FuncCount = Db->FunctionCount();
        int StrCount = Db->StringCount();
        int InstCount = Db->InstructionCount();
        int XrefCount = Db->XrefCount();

        Log(QString("Analysis complete: %1 functions, %2 instructions, %3 strings, %4 xrefs")
            .arg(FuncCount).arg(InstCount).arg(StrCount).arg(XrefCount), LogLevel::Info);

        statusBar()->showMessage(QString("Analysis complete - %1 functions found").arg(FuncCount));

        BinaryInfo BinInfo = Db->GetBinaryInfo();
        Address EntryPoint = BinInfo.EntryPoint;

        for (auto* Module : Modules) {
            Module->OnAnalysisComplete(Db, EntryPoint);
        }

        emit AnalysisComplete();
    } else {
        Log("Analysis failed or cancelled", LogLevel::Warning);
        statusBar()->showMessage("Analysis failed");
    }

    UpdateWindowTitle();
}

}
