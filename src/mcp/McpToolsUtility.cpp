#include "McpToolRegistry.h"
#include "McpSchemaBuilder.h"
#include <QSysInfo>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QProcess>
#include <QThread>
#include <QCoreApplication>
#include <QStorageInfo>
#include <unistd.h>

namespace Fidra {

void McpToolRegistry::RegisterUtilityTools() {

    RegisterTool(QStringLiteral("get_system_info"),
        QStringLiteral("Get comprehensive system information including OS, CPU, memory, and kernel version."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QJsonObject Result;
            Result[QStringLiteral("os")] = QSysInfo::prettyProductName();
            Result[QStringLiteral("kernel_type")] = QSysInfo::kernelType();
            Result[QStringLiteral("kernel_version")] = QSysInfo::kernelVersion();
            Result[QStringLiteral("product_type")] = QSysInfo::productType();
            Result[QStringLiteral("product_version")] = QSysInfo::productVersion();
            Result[QStringLiteral("build_abi")] = QSysInfo::buildAbi();
            Result[QStringLiteral("cpu_architecture")] = QSysInfo::currentCpuArchitecture();
            Result[QStringLiteral("build_cpu_architecture")] = QSysInfo::buildCpuArchitecture();
            Result[QStringLiteral("machine_hostname")] = QSysInfo::machineHostName();
            Result[QStringLiteral("byte_order")] = (QSysInfo::ByteOrder == QSysInfo::LittleEndian)
                ? QStringLiteral("little-endian") : QStringLiteral("big-endian");
            Result[QStringLiteral("qt_version")] = QString::fromLatin1(qVersion());
            Result[QStringLiteral("logical_cpu_count")] = QThread::idealThreadCount();
            QFile MemInfo(QStringLiteral("/proc/meminfo"));
            if (MemInfo.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QByteArray Content = MemInfo.readAll();
                MemInfo.close();
                QStringList Lines = QString::fromUtf8(Content).split(QChar('\n'));
                for (const QString& Line : Lines) {
                    if (Line.startsWith(QStringLiteral("MemTotal:"))) {
                        QStringList Parts = Line.split(QChar(' '), Qt::SkipEmptyParts);
                        if (Parts.size() >= 2) {
                            Result[QStringLiteral("total_memory_kb")] = Parts[1].toLongLong();
                            Result[QStringLiteral("total_memory_mb")] = Parts[1].toLongLong() / 1024;
                            Result[QStringLiteral("total_memory_gb")] = Parts[1].toLongLong() / (1024 * 1024);
                        }
                    } else if (Line.startsWith(QStringLiteral("MemAvailable:"))) {
                        QStringList Parts = Line.split(QChar(' '), Qt::SkipEmptyParts);
                        if (Parts.size() >= 2) {
                            Result[QStringLiteral("available_memory_kb")] = Parts[1].toLongLong();
                            Result[QStringLiteral("available_memory_mb")] = Parts[1].toLongLong() / 1024;
                        }
                    }
                }
            }
            return Result;
        });

    RegisterTool(QStringLiteral("get_os_version"),
        QStringLiteral("Get detailed OS version and distribution information."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QJsonObject Result;
            Result[QStringLiteral("pretty_name")] = QSysInfo::prettyProductName();
            Result[QStringLiteral("kernel_type")] = QSysInfo::kernelType();
            Result[QStringLiteral("kernel_version")] = QSysInfo::kernelVersion();
            Result[QStringLiteral("product_type")] = QSysInfo::productType();
            Result[QStringLiteral("product_version")] = QSysInfo::productVersion();
            QFile OsRelease(QStringLiteral("/etc/os-release"));
            if (OsRelease.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QByteArray Content = OsRelease.readAll();
                OsRelease.close();
                QStringList Lines = QString::fromUtf8(Content).split(QChar('\n'));
                QJsonObject OsInfo;
                for (const QString& Line : Lines) {
                    int Eq = Line.indexOf(QChar('='));
                    if (Eq > 0) {
                        QString Key = Line.left(Eq).trimmed().toLower();
                        QString Val = Line.mid(Eq + 1).trimmed();
                        if (Val.startsWith(QChar('"')) && Val.endsWith(QChar('"'))) {
                            Val = Val.mid(1, Val.size() - 2);
                        }
                        OsInfo[Key] = Val;
                    }
                }
                Result[QStringLiteral("os_release")] = OsInfo;
            }
            QFile Version(QStringLiteral("/proc/version"));
            if (Version.open(QIODevice::ReadOnly | QIODevice::Text)) {
                Result[QStringLiteral("proc_version")] = QString::fromUtf8(Version.readAll()).trimmed();
                Version.close();
            }
            return Result;
        });

    RegisterTool(QStringLiteral("get_cpu_info"),
        QStringLiteral("Get detailed CPU information from /proc/cpuinfo including model name, cores, frequency, and features."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QJsonObject Result;
            Result[QStringLiteral("architecture")] = QSysInfo::currentCpuArchitecture();
            Result[QStringLiteral("logical_cores")] = QThread::idealThreadCount();
            QFile CpuInfo(QStringLiteral("/proc/cpuinfo"));
            if (CpuInfo.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QByteArray Content = CpuInfo.readAll();
                CpuInfo.close();
                QStringList Lines = QString::fromUtf8(Content).split(QChar('\n'));
                int ProcessorCount = 0;
                QJsonObject FirstCpu;
                for (const QString& Line : Lines) {
                    int Colon = Line.indexOf(QChar(':'));
                    if (Colon <= 0) continue;
                    QString Key = Line.left(Colon).trimmed().toLower().replace(QChar(' '), QChar('_'));
                    QString Val = Line.mid(Colon + 1).trimmed();
                    if (Key == QStringLiteral("processor")) {
                        ProcessorCount++;
                    }
                    if (ProcessorCount <= 1) {
                        if (Key == QStringLiteral("model_name")) FirstCpu[QStringLiteral("model_name")] = Val;
                        else if (Key == QStringLiteral("cpu_mhz")) FirstCpu[QStringLiteral("frequency_mhz")] = Val.toDouble();
                        else if (Key == QStringLiteral("cache_size")) FirstCpu[QStringLiteral("cache_size")] = Val;
                        else if (Key == QStringLiteral("cpu_cores")) FirstCpu[QStringLiteral("physical_cores")] = Val.toInt();
                        else if (Key == QStringLiteral("siblings")) FirstCpu[QStringLiteral("siblings")] = Val.toInt();
                        else if (Key == QStringLiteral("vendor_id")) FirstCpu[QStringLiteral("vendor")] = Val;
                        else if (Key == QStringLiteral("cpu_family")) FirstCpu[QStringLiteral("family")] = Val.toInt();
                        else if (Key == QStringLiteral("model")) FirstCpu[QStringLiteral("model")] = Val.toInt();
                        else if (Key == QStringLiteral("stepping")) FirstCpu[QStringLiteral("stepping")] = Val.toInt();
                        else if (Key == QStringLiteral("flags")) {
                            QStringList FlagList = Val.split(QChar(' '), Qt::SkipEmptyParts);
                            QJsonArray FlagsArr;
                            for (const QString& F : FlagList) FlagsArr.append(F);
                            FirstCpu[QStringLiteral("flags")] = FlagsArr;
                            FirstCpu[QStringLiteral("flag_count")] = FlagsArr.size();
                            QStringList Notable = {
                                QStringLiteral("sse"), QStringLiteral("sse2"), QStringLiteral("sse3"), QStringLiteral("ssse3"),
                                QStringLiteral("sse4_1"), QStringLiteral("sse4_2"), QStringLiteral("avx"), QStringLiteral("avx2"),
                                QStringLiteral("avx512f"), QStringLiteral("aes"), QStringLiteral("vmx"), QStringLiteral("svm"),
                                QStringLiteral("nx"), QStringLiteral("lm"), QStringLiteral("hypervisor")
                            };
                            QJsonObject ImportantFlags;
                            for (const QString& N : Notable) {
                                ImportantFlags[N] = FlagList.contains(N);
                            }
                            FirstCpu[QStringLiteral("notable_features")] = ImportantFlags;
                        }
                    }
                }
                Result[QStringLiteral("logical_processors")] = ProcessorCount;
                Result[QStringLiteral("cpu")] = FirstCpu;
            }
            return Result;
        });

    RegisterTool(QStringLiteral("get_memory_usage"),
        QStringLiteral("Get current system memory usage from /proc/meminfo including total, available, free, buffers, cached, and swap."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QFile MemInfo(QStringLiteral("/proc/meminfo"));
            if (!MemInfo.open(QIODevice::ReadOnly | QIODevice::Text)) {
                return Schema::Err(QStringLiteral("Cannot read /proc/meminfo"));
            }
            QByteArray Content = MemInfo.readAll();
            MemInfo.close();
            QStringList Lines = QString::fromUtf8(Content).split(QChar('\n'));
            QJsonObject Result;
            QMap<QString, qint64> Values;
            for (const QString& Line : Lines) {
                int Colon = Line.indexOf(QChar(':'));
                if (Colon <= 0) continue;
                QString Key = Line.left(Colon).trimmed();
                QString ValStr = Line.mid(Colon + 1).trimmed();
                QStringList Parts = ValStr.split(QChar(' '), Qt::SkipEmptyParts);
                if (!Parts.isEmpty()) {
                    Values[Key] = Parts[0].toLongLong();
                }
            }
            Result[QStringLiteral("total_kb")] = Values.value(QStringLiteral("MemTotal"), 0);
            Result[QStringLiteral("free_kb")] = Values.value(QStringLiteral("MemFree"), 0);
            Result[QStringLiteral("available_kb")] = Values.value(QStringLiteral("MemAvailable"), 0);
            Result[QStringLiteral("buffers_kb")] = Values.value(QStringLiteral("Buffers"), 0);
            Result[QStringLiteral("cached_kb")] = Values.value(QStringLiteral("Cached"), 0);
            Result[QStringLiteral("swap_total_kb")] = Values.value(QStringLiteral("SwapTotal"), 0);
            Result[QStringLiteral("swap_free_kb")] = Values.value(QStringLiteral("SwapFree"), 0);
            qint64 Total = Values.value(QStringLiteral("MemTotal"), 1);
            qint64 Available = Values.value(QStringLiteral("MemAvailable"), 0);
            qint64 Used = Total - Available;
            Result[QStringLiteral("used_kb")] = Used;
            double UsagePercent = (Total > 0) ? (static_cast<double>(Used) / Total * 100.0) : 0.0;
            Result[QStringLiteral("usage_percent")] = QString::number(UsagePercent, 'f', 1).toDouble();
            Result[QStringLiteral("total_mb")] = Total / 1024;
            Result[QStringLiteral("used_mb")] = Used / 1024;
            Result[QStringLiteral("available_mb")] = Available / 1024;
            qint64 SwapTotal = Values.value(QStringLiteral("SwapTotal"), 0);
            qint64 SwapFree = Values.value(QStringLiteral("SwapFree"), 0);
            Result[QStringLiteral("swap_used_kb")] = SwapTotal - SwapFree;
            double SwapPercent = (SwapTotal > 0) ? (static_cast<double>(SwapTotal - SwapFree) / SwapTotal * 100.0) : 0.0;
            Result[QStringLiteral("swap_usage_percent")] = QString::number(SwapPercent, 'f', 1).toDouble();
            return Result;
        });

    RegisterTool(QStringLiteral("get_process_info"),
        QStringLiteral("Get detailed information about a process by PID from /proc filesystem."),
        Schema::Build({
            {QStringLiteral("pid"), Schema::Integer(QStringLiteral("Process ID"), 1)}
        }, {QStringLiteral("pid")}),
        [this](const QJsonObject& A) -> QJsonValue {
            int Pid = A.value(QStringLiteral("pid")).toInt();
            if (Pid <= 0) return Schema::Err(QStringLiteral("Invalid PID"));
            QString ProcDir = QStringLiteral("/proc/") + QString::number(Pid);
            QDir Dir(ProcDir);
            if (!Dir.exists()) {
                return Schema::Err(QStringLiteral("Process ") + QString::number(Pid) + QStringLiteral(" not found"));
            }
            QJsonObject Result;
            Result[QStringLiteral("pid")] = Pid;
            QFile Comm(ProcDir + QStringLiteral("/comm"));
            if (Comm.open(QIODevice::ReadOnly | QIODevice::Text)) {
                Result[QStringLiteral("name")] = QString::fromUtf8(Comm.readAll()).trimmed();
                Comm.close();
            }
            QFile CmdLine(ProcDir + QStringLiteral("/cmdline"));
            if (CmdLine.open(QIODevice::ReadOnly)) {
                QByteArray CmdData = CmdLine.readAll();
                CmdLine.close();
                QString CmdStr = QString::fromUtf8(CmdData).replace(QChar('\0'), QChar(' ')).trimmed();
                Result[QStringLiteral("command_line")] = CmdStr;
            }
            QFile Exe(ProcDir + QStringLiteral("/exe"));
            QFileInfo ExeInfo(ProcDir + QStringLiteral("/exe"));
            if (ExeInfo.exists()) {
                Result[QStringLiteral("exe_path")] = ExeInfo.symLinkTarget();
            }
            QFile Cwd(ProcDir + QStringLiteral("/cwd"));
            QFileInfo CwdInfo(ProcDir + QStringLiteral("/cwd"));
            if (CwdInfo.exists()) {
                Result[QStringLiteral("cwd")] = CwdInfo.symLinkTarget();
            }
            QFile Status(ProcDir + QStringLiteral("/status"));
            if (Status.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QStringList Lines = QString::fromUtf8(Status.readAll()).split(QChar('\n'));
                Status.close();
                for (const QString& Line : Lines) {
                    int Tab = Line.indexOf(QChar(':'));
                    if (Tab <= 0) continue;
                    QString Key = Line.left(Tab).trimmed();
                    QString Val = Line.mid(Tab + 1).trimmed();
                    if (Key == QStringLiteral("State")) Result[QStringLiteral("state")] = Val;
                    else if (Key == QStringLiteral("PPid")) Result[QStringLiteral("parent_pid")] = Val.toInt();
                    else if (Key == QStringLiteral("Uid")) Result[QStringLiteral("uid")] = Val.split(QChar('\t')).first().trimmed().toInt();
                    else if (Key == QStringLiteral("Gid")) Result[QStringLiteral("gid")] = Val.split(QChar('\t')).first().trimmed().toInt();
                    else if (Key == QStringLiteral("Threads")) Result[QStringLiteral("thread_count")] = Val.toInt();
                    else if (Key == QStringLiteral("VmSize")) Result[QStringLiteral("virtual_memory_kb")] = Val.split(QChar(' ')).first().toLongLong();
                    else if (Key == QStringLiteral("VmRSS")) Result[QStringLiteral("resident_memory_kb")] = Val.split(QChar(' ')).first().toLongLong();
                    else if (Key == QStringLiteral("VmPeak")) Result[QStringLiteral("peak_virtual_kb")] = Val.split(QChar(' ')).first().toLongLong();
                    else if (Key == QStringLiteral("VmSwap")) Result[QStringLiteral("swap_kb")] = Val.split(QChar(' ')).first().toLongLong();
                }
            }
            QDir FdDir(ProcDir + QStringLiteral("/fd"));
            if (FdDir.exists()) {
                Result[QStringLiteral("open_file_descriptors")] = static_cast<int>(FdDir.entryList(QDir::AllEntries | QDir::NoDotAndDotDot).size());
            }
            return Result;
        });

    RegisterTool(QStringLiteral("get_cpu_usage"),
        QStringLiteral("Get current CPU usage statistics from /proc/stat including per-core usage."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QFile Stat(QStringLiteral("/proc/stat"));
            if (!Stat.open(QIODevice::ReadOnly | QIODevice::Text)) {
                return Schema::Err(QStringLiteral("Cannot read /proc/stat"));
            }
            QByteArray Content = Stat.readAll();
            Stat.close();
            QStringList Lines = QString::fromUtf8(Content).split(QChar('\n'));
            QJsonObject Result;
            QJsonArray Cores;
            for (const QString& Line : Lines) {
                if (!Line.startsWith(QStringLiteral("cpu"))) continue;
                QStringList Parts = Line.split(QChar(' '), Qt::SkipEmptyParts);
                if (Parts.size() < 8) continue;
                QJsonObject CpuStat;
                CpuStat[QStringLiteral("name")] = Parts[0];
                CpuStat[QStringLiteral("user")] = Parts[1].toLongLong();
                CpuStat[QStringLiteral("nice")] = Parts[2].toLongLong();
                CpuStat[QStringLiteral("system")] = Parts[3].toLongLong();
                CpuStat[QStringLiteral("idle")] = Parts[4].toLongLong();
                CpuStat[QStringLiteral("iowait")] = (Parts.size() > 5) ? Parts[5].toLongLong() : 0;
                CpuStat[QStringLiteral("irq")] = (Parts.size() > 6) ? Parts[6].toLongLong() : 0;
                CpuStat[QStringLiteral("softirq")] = (Parts.size() > 7) ? Parts[7].toLongLong() : 0;
                qint64 Total = 0;
                for (int I = 1; I < Parts.size(); ++I) Total += Parts[I].toLongLong();
                qint64 Idle = Parts[4].toLongLong() + ((Parts.size() > 5) ? Parts[5].toLongLong() : 0);
                double Usage = (Total > 0) ? (static_cast<double>(Total - Idle) / Total * 100.0) : 0.0;
                CpuStat[QStringLiteral("usage_percent")] = QString::number(Usage, 'f', 1).toDouble();
                if (Parts[0] == QStringLiteral("cpu")) {
                    Result[QStringLiteral("overall")] = CpuStat;
                } else {
                    Cores.append(CpuStat);
                }
            }
            Result[QStringLiteral("cores")] = Cores;
            Result[QStringLiteral("core_count")] = Cores.size();
            Result[QStringLiteral("note")] = QStringLiteral("Values are cumulative since boot. Take two snapshots and compute the difference for current usage.");
            return Result;
        });

    RegisterTool(QStringLiteral("get_loaded_drivers"),
        QStringLiteral("List currently loaded kernel modules from /proc/modules."),
        Schema::Build({
            {QStringLiteral("filter"), Schema::String(QStringLiteral("Optional substring filter to match module names"))},
            {QStringLiteral("limit"), Schema::Integer(QStringLiteral("Maximum modules to return"), 1, 5000)}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            QFile Modules(QStringLiteral("/proc/modules"));
            if (!Modules.open(QIODevice::ReadOnly | QIODevice::Text)) {
                return Schema::Err(QStringLiteral("Cannot read /proc/modules"));
            }
            QByteArray Content = Modules.readAll();
            Modules.close();
            QStringList Lines = QString::fromUtf8(Content).split(QChar('\n'), Qt::SkipEmptyParts);
            QString Filter = A.value(QStringLiteral("filter")).toString().toLower();
            int Limit = A.value(QStringLiteral("limit")).toInt(500);
            if (Limit <= 0) Limit = 500;
            QJsonArray ModuleList;
            for (const QString& Line : Lines) {
                QStringList Parts = Line.split(QChar(' '), Qt::SkipEmptyParts);
                if (Parts.size() < 3) continue;
                QString ModName = Parts[0];
                if (!Filter.isEmpty() && !ModName.toLower().contains(Filter)) continue;
                QJsonObject Mod;
                Mod[QStringLiteral("name")] = ModName;
                Mod[QStringLiteral("size")] = Parts[1].toLongLong();
                Mod[QStringLiteral("instances")] = Parts[2].toInt();
                if (Parts.size() > 3) {
                    QString Deps = Parts[3];
                    if (Deps != QStringLiteral("-")) {
                        QStringList DepList = Deps.split(QChar(','), Qt::SkipEmptyParts);
                        QJsonArray DepArr;
                        for (const QString& D : DepList) DepArr.append(D);
                        Mod[QStringLiteral("dependencies")] = DepArr;
                    }
                }
                if (Parts.size() > 4) Mod[QStringLiteral("state")] = Parts[4];
                if (Parts.size() > 5) Mod[QStringLiteral("offset")] = Parts[5];
                ModuleList.append(Mod);
                if (ModuleList.size() >= Limit) break;
            }
            QJsonObject Result;
            Result[QStringLiteral("modules")] = ModuleList;
            Result[QStringLiteral("count")] = ModuleList.size();
            Result[QStringLiteral("total_loaded")] = Lines.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_environment"),
        QStringLiteral("Get environment variables of the current Fidra process, or optionally of a specific process by PID."),
        Schema::Build({
            {QStringLiteral("pid"), Schema::Integer(QStringLiteral("Process ID (omit for Fidra's own environment)"))},
            {QStringLiteral("filter"), Schema::String(QStringLiteral("Optional substring filter for variable names"))}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            int Pid = A.value(QStringLiteral("pid")).toInt(0);
            QString Filter = A.value(QStringLiteral("filter")).toString().toLower();
            QJsonObject Result;
            if (Pid > 0) {
                QFile Environ(QStringLiteral("/proc/") + QString::number(Pid) + QStringLiteral("/environ"));
                if (!Environ.open(QIODevice::ReadOnly)) {
                    return Schema::Err(QStringLiteral("Cannot read environment for PID ") + QString::number(Pid));
                }
                QByteArray Content = Environ.readAll();
                Environ.close();
                QStringList Entries = QString::fromUtf8(Content).split(QChar('\0'), Qt::SkipEmptyParts);
                QJsonObject Vars;
                for (const QString& Entry : Entries) {
                    int Eq = Entry.indexOf(QChar('='));
                    if (Eq <= 0) continue;
                    QString Key = Entry.left(Eq);
                    QString Val = Entry.mid(Eq + 1);
                    if (!Filter.isEmpty() && !Key.toLower().contains(Filter)) continue;
                    Vars[Key] = Val;
                }
                Result[QStringLiteral("pid")] = Pid;
                Result[QStringLiteral("variables")] = Vars;
                Result[QStringLiteral("count")] = Vars.size();
            } else {
                QStringList EnvList = QProcess::systemEnvironment();
                QJsonObject Vars;
                for (const QString& Entry : EnvList) {
                    int Eq = Entry.indexOf(QChar('='));
                    if (Eq <= 0) continue;
                    QString Key = Entry.left(Eq);
                    QString Val = Entry.mid(Eq + 1);
                    if (!Filter.isEmpty() && !Key.toLower().contains(Filter)) continue;
                    Vars[Key] = Val;
                }
                Result[QStringLiteral("source")] = QStringLiteral("fidra_process");
                Result[QStringLiteral("variables")] = Vars;
                Result[QStringLiteral("count")] = Vars.size();
            }
            return Result;
        });

    RegisterTool(QStringLiteral("get_process_maps"),
        QStringLiteral("Get the full memory map of a process from /proc/PID/maps. Shows all mapped regions with permissions, offsets, and paths."),
        Schema::Build({
            {QStringLiteral("pid"), Schema::Integer(QStringLiteral("Process ID"), 1)},
            {QStringLiteral("filter"), Schema::String(QStringLiteral("Optional filter for path/name"))},
            {QStringLiteral("limit"), Schema::Integer(QStringLiteral("Maximum entries to return"), 1, 10000)}
        }, {QStringLiteral("pid")}),
        [this](const QJsonObject& A) -> QJsonValue {
            int Pid = A.value(QStringLiteral("pid")).toInt();
            if (Pid <= 0) return Schema::Err(QStringLiteral("Invalid PID"));
            QString Filter = A.value(QStringLiteral("filter")).toString().toLower();
            int Limit = A.value(QStringLiteral("limit")).toInt(1000);
            QFile Maps(QStringLiteral("/proc/") + QString::number(Pid) + QStringLiteral("/maps"));
            if (!Maps.open(QIODevice::ReadOnly | QIODevice::Text)) {
                return Schema::Err(QStringLiteral("Cannot read maps for PID ") + QString::number(Pid));
            }
            QByteArray Content = Maps.readAll();
            Maps.close();
            QStringList Lines = QString::fromUtf8(Content).split(QChar('\n'), Qt::SkipEmptyParts);
            QJsonArray Entries;
            for (const QString& Line : Lines) {
                if (!Filter.isEmpty() && !Line.toLower().contains(Filter)) continue;
                QStringList Parts = Line.split(QChar(' '), Qt::SkipEmptyParts);
                if (Parts.size() < 5) continue;
                QJsonObject Entry;
                QStringList AddrRange = Parts[0].split(QChar('-'));
                if (AddrRange.size() == 2) {
                    Entry[QStringLiteral("start")] = QStringLiteral("0x") + AddrRange[0].toUpper();
                    Entry[QStringLiteral("end")] = QStringLiteral("0x") + AddrRange[1].toUpper();
                }
                Entry[QStringLiteral("permissions")] = Parts[1];
                Entry[QStringLiteral("offset")] = Parts[2];
                Entry[QStringLiteral("device")] = Parts[3];
                Entry[QStringLiteral("inode")] = Parts[4].toLongLong();
                if (Parts.size() > 5) {
                    Entry[QStringLiteral("path")] = Parts[5];
                }
                Entries.append(Entry);
                if (Entries.size() >= Limit) break;
            }
            QJsonObject Result;
            Result[QStringLiteral("pid")] = Pid;
            Result[QStringLiteral("maps")] = Entries;
            Result[QStringLiteral("count")] = Entries.size();
            Result[QStringLiteral("total_regions")] = Lines.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_process_threads"),
        QStringLiteral("List all threads of a process by reading /proc/PID/task."),
        Schema::Build({
            {QStringLiteral("pid"), Schema::Integer(QStringLiteral("Process ID"), 1)}
        }, {QStringLiteral("pid")}),
        [this](const QJsonObject& A) -> QJsonValue {
            int Pid = A.value(QStringLiteral("pid")).toInt();
            if (Pid <= 0) return Schema::Err(QStringLiteral("Invalid PID"));
            QDir TaskDir(QStringLiteral("/proc/") + QString::number(Pid) + QStringLiteral("/task"));
            if (!TaskDir.exists()) {
                return Schema::Err(QStringLiteral("Process ") + QString::number(Pid) + QStringLiteral(" not found"));
            }
            QStringList ThreadDirs = TaskDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
            QJsonArray Threads;
            for (const QString& TidStr : ThreadDirs) {
                QJsonObject Thread;
                int Tid = TidStr.toInt();
                Thread[QStringLiteral("tid")] = Tid;
                QFile Comm(TaskDir.path() + QStringLiteral("/") + TidStr + QStringLiteral("/comm"));
                if (Comm.open(QIODevice::ReadOnly | QIODevice::Text)) {
                    Thread[QStringLiteral("name")] = QString::fromUtf8(Comm.readAll()).trimmed();
                    Comm.close();
                }
                QFile Status(TaskDir.path() + QStringLiteral("/") + TidStr + QStringLiteral("/status"));
                if (Status.open(QIODevice::ReadOnly | QIODevice::Text)) {
                    QStringList Lines = QString::fromUtf8(Status.readAll()).split(QChar('\n'));
                    Status.close();
                    for (const QString& Line : Lines) {
                        if (Line.startsWith(QStringLiteral("State:"))) {
                            Thread[QStringLiteral("state")] = Line.mid(6).trimmed();
                            break;
                        }
                    }
                }
                Threads.append(Thread);
            }
            QJsonObject Result;
            Result[QStringLiteral("pid")] = Pid;
            Result[QStringLiteral("threads")] = Threads;
            Result[QStringLiteral("count")] = Threads.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_io_counters"),
        QStringLiteral("Get I/O statistics for a process from /proc/PID/io including read/write bytes and syscall counts."),
        Schema::Build({
            {QStringLiteral("pid"), Schema::Integer(QStringLiteral("Process ID"), 1)}
        }, {QStringLiteral("pid")}),
        [this](const QJsonObject& A) -> QJsonValue {
            int Pid = A.value(QStringLiteral("pid")).toInt();
            if (Pid <= 0) return Schema::Err(QStringLiteral("Invalid PID"));
            QFile Io(QStringLiteral("/proc/") + QString::number(Pid) + QStringLiteral("/io"));
            if (!Io.open(QIODevice::ReadOnly | QIODevice::Text)) {
                return Schema::Err(QStringLiteral("Cannot read /proc/") + QString::number(Pid) + QStringLiteral("/io"));
            }
            QByteArray Content = Io.readAll();
            Io.close();
            QStringList Lines = QString::fromUtf8(Content).split(QChar('\n'), Qt::SkipEmptyParts);
            QJsonObject Result;
            Result[QStringLiteral("pid")] = Pid;
            for (const QString& Line : Lines) {
                int Colon = Line.indexOf(QChar(':'));
                if (Colon <= 0) continue;
                QString Key = Line.left(Colon).trimmed();
                qint64 Val = Line.mid(Colon + 1).trimmed().toLongLong();
                if (Key == QStringLiteral("rchar")) Result[QStringLiteral("read_bytes_total")] = Val;
                else if (Key == QStringLiteral("wchar")) Result[QStringLiteral("write_bytes_total")] = Val;
                else if (Key == QStringLiteral("syscr")) Result[QStringLiteral("read_syscalls")] = Val;
                else if (Key == QStringLiteral("syscw")) Result[QStringLiteral("write_syscalls")] = Val;
                else if (Key == QStringLiteral("read_bytes")) Result[QStringLiteral("disk_read_bytes")] = Val;
                else if (Key == QStringLiteral("write_bytes")) Result[QStringLiteral("disk_write_bytes")] = Val;
                else if (Key == QStringLiteral("cancelled_write_bytes")) Result[QStringLiteral("cancelled_write_bytes")] = Val;
            }
            return Result;
        });

    RegisterTool(QStringLiteral("is_process_64bit"),
        QStringLiteral("Check if a process is 64-bit by reading its ELF header."),
        Schema::Build({
            {QStringLiteral("pid"), Schema::Integer(QStringLiteral("Process ID"), 1)}
        }, {QStringLiteral("pid")}),
        [this](const QJsonObject& A) -> QJsonValue {
            int Pid = A.value(QStringLiteral("pid")).toInt();
            if (Pid <= 0) return Schema::Err(QStringLiteral("Invalid PID"));
            QFile Exe(QStringLiteral("/proc/") + QString::number(Pid) + QStringLiteral("/exe"));
            if (!Exe.open(QIODevice::ReadOnly)) {
                return Schema::Err(QStringLiteral("Cannot read executable for PID ") + QString::number(Pid));
            }
            QByteArray Header = Exe.read(20);
            Exe.close();
            if (Header.size() < 5) {
                return Schema::Err(QStringLiteral("Cannot read ELF header"));
            }
            if (Header[0] != 0x7F || Header[1] != 'E' || Header[2] != 'L' || Header[3] != 'F') {
                return Schema::Err(QStringLiteral("Not an ELF executable"));
            }
            uint8_t EiClass = static_cast<uint8_t>(Header[4]);
            QJsonObject Result;
            Result[QStringLiteral("pid")] = Pid;
            Result[QStringLiteral("is_64bit")] = (EiClass == 2);
            Result[QStringLiteral("is_32bit")] = (EiClass == 1);
            Result[QStringLiteral("elf_class")] = (EiClass == 2) ? QStringLiteral("ELFCLASS64") :
                                                  (EiClass == 1) ? QStringLiteral("ELFCLASS32") :
                                                  QStringLiteral("UNKNOWN");
            if (Header.size() >= 6) {
                uint8_t EiData = static_cast<uint8_t>(Header[5]);
                Result[QStringLiteral("endianness")] = (EiData == 1) ? QStringLiteral("little-endian") :
                                                       (EiData == 2) ? QStringLiteral("big-endian") :
                                                       QStringLiteral("unknown");
            }
            if (Header.size() >= 19) {
                uint16_t Machine = static_cast<uint16_t>(static_cast<uint8_t>(Header[18])) << 8 |
                                   static_cast<uint16_t>(static_cast<uint8_t>(Header[19]));
                if (Header[5] == 1) {
                    Machine = static_cast<uint16_t>(static_cast<uint8_t>(Header[19])) << 8 |
                              static_cast<uint16_t>(static_cast<uint8_t>(Header[18]));
                }
                QString MachStr;
                if (Machine == 0x3E) MachStr = QStringLiteral("x86_64");
                else if (Machine == 0x03) MachStr = QStringLiteral("x86");
                else if (Machine == 0xB7) MachStr = QStringLiteral("aarch64");
                else if (Machine == 0x28) MachStr = QStringLiteral("arm");
                else MachStr = QStringLiteral("0x") + QString::number(Machine, 16);
                Result[QStringLiteral("machine")] = MachStr;
            }
            return Result;
        });

    RegisterTool(QStringLiteral("get_process_times"),
        QStringLiteral("Get CPU time statistics for a process from /proc/PID/stat including user time, system time, start time, and uptime."),
        Schema::Build({
            {QStringLiteral("pid"), Schema::Integer(QStringLiteral("Process ID"), 1)}
        }, {QStringLiteral("pid")}),
        [this](const QJsonObject& A) -> QJsonValue {
            int Pid = A.value(QStringLiteral("pid")).toInt();
            if (Pid <= 0) return Schema::Err(QStringLiteral("Invalid PID"));
            QFile StatFile(QStringLiteral("/proc/") + QString::number(Pid) + QStringLiteral("/stat"));
            if (!StatFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
                return Schema::Err(QStringLiteral("Cannot read /proc/") + QString::number(Pid) + QStringLiteral("/stat"));
            }
            QString StatLine = QString::fromUtf8(StatFile.readAll()).trimmed();
            StatFile.close();
            int CloseParen = StatLine.lastIndexOf(QChar(')'));
            if (CloseParen < 0) return Schema::Err(QStringLiteral("Malformed stat line"));
            QStringList Fields = StatLine.mid(CloseParen + 2).split(QChar(' '));
            if (Fields.size() < 20) return Schema::Err(QStringLiteral("Insufficient stat fields"));
            qint64 Utime = Fields[11].toLongLong();
            qint64 Stime = Fields[12].toLongLong();
            qint64 Cutime = Fields[13].toLongLong();
            qint64 Cstime = Fields[14].toLongLong();
            qint64 StartTime = Fields[19].toLongLong();
            long ClkTck = sysconf(_SC_CLK_TCK);
            if (ClkTck <= 0) ClkTck = 100;
            QJsonObject Result;
            Result[QStringLiteral("pid")] = Pid;
            Result[QStringLiteral("user_time_ticks")] = Utime;
            Result[QStringLiteral("system_time_ticks")] = Stime;
            Result[QStringLiteral("children_user_time_ticks")] = Cutime;
            Result[QStringLiteral("children_system_time_ticks")] = Cstime;
            Result[QStringLiteral("user_time_seconds")] = static_cast<double>(Utime) / ClkTck;
            Result[QStringLiteral("system_time_seconds")] = static_cast<double>(Stime) / ClkTck;
            Result[QStringLiteral("total_cpu_seconds")] = static_cast<double>(Utime + Stime) / ClkTck;
            QFile Uptime(QStringLiteral("/proc/uptime"));
            if (Uptime.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QStringList UptimeParts = QString::fromUtf8(Uptime.readAll()).trimmed().split(QChar(' '));
                Uptime.close();
                if (!UptimeParts.isEmpty()) {
                    double SystemUptime = UptimeParts[0].toDouble();
                    double ProcessStartSeconds = static_cast<double>(StartTime) / ClkTck;
                    double ProcessUptime = SystemUptime - ProcessStartSeconds;
                    Result[QStringLiteral("uptime_seconds")] = ProcessUptime;
                    int Hours = static_cast<int>(ProcessUptime / 3600);
                    int Mins = static_cast<int>(static_cast<int>(ProcessUptime) % 3600 / 60);
                    int Secs = static_cast<int>(ProcessUptime) % 60;
                    Result[QStringLiteral("uptime_human")] = QString::number(Hours) + QStringLiteral("h ") +
                                                             QString::number(Mins) + QStringLiteral("m ") +
                                                             QString::number(Secs) + QStringLiteral("s");
                }
            }
            Result[QStringLiteral("clock_ticks_per_second")] = static_cast<int>(ClkTck);
            return Result;
        });

    RegisterTool(QStringLiteral("get_command_line"),
        QStringLiteral("Get the full command line of a process."),
        Schema::Build({
            {QStringLiteral("pid"), Schema::Integer(QStringLiteral("Process ID"), 1)}
        }, {QStringLiteral("pid")}),
        [this](const QJsonObject& A) -> QJsonValue {
            int Pid = A.value(QStringLiteral("pid")).toInt();
            if (Pid <= 0) return Schema::Err(QStringLiteral("Invalid PID"));
            QFile CmdLine(QStringLiteral("/proc/") + QString::number(Pid) + QStringLiteral("/cmdline"));
            if (!CmdLine.open(QIODevice::ReadOnly)) {
                return Schema::Err(QStringLiteral("Cannot read cmdline for PID ") + QString::number(Pid));
            }
            QByteArray Content = CmdLine.readAll();
            CmdLine.close();
            QStringList Args;
            QByteArray Current;
            for (int I = 0; I < Content.size(); ++I) {
                if (Content[I] == '\0') {
                    if (!Current.isEmpty()) {
                        Args.append(QString::fromUtf8(Current));
                    }
                    Current.clear();
                } else {
                    Current.append(Content[I]);
                }
            }
            if (!Current.isEmpty()) Args.append(QString::fromUtf8(Current));
            QJsonObject Result;
            Result[QStringLiteral("pid")] = Pid;
            QJsonArray ArgsArr;
            for (const QString& Arg : Args) ArgsArr.append(Arg);
            Result[QStringLiteral("argv")] = ArgsArr;
            Result[QStringLiteral("argc")] = Args.size();
            if (!Args.isEmpty()) {
                Result[QStringLiteral("executable")] = Args[0];
            }
            Result[QStringLiteral("command_line")] = Args.join(QChar(' '));
            return Result;
        });

    RegisterTool(QStringLiteral("get_current_directory"),
        QStringLiteral("Get the current working directory of a process."),
        Schema::Build({
            {QStringLiteral("pid"), Schema::Integer(QStringLiteral("Process ID (omit for Fidra process)"))}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            int Pid = A.value(QStringLiteral("pid")).toInt(0);
            QJsonObject Result;
            if (Pid > 0) {
                QFileInfo CwdLink(QStringLiteral("/proc/") + QString::number(Pid) + QStringLiteral("/cwd"));
                if (!CwdLink.exists()) {
                    return Schema::Err(QStringLiteral("Cannot read cwd for PID ") + QString::number(Pid));
                }
                Result[QStringLiteral("pid")] = Pid;
                Result[QStringLiteral("cwd")] = CwdLink.symLinkTarget();
            } else {
                Result[QStringLiteral("source")] = QStringLiteral("fidra_process");
                Result[QStringLiteral("cwd")] = QDir::currentPath();
            }
            return Result;
        });

    RegisterTool(QStringLiteral("get_uptime"),
        QStringLiteral("Get system uptime and idle time from /proc/uptime."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QFile Uptime(QStringLiteral("/proc/uptime"));
            if (!Uptime.open(QIODevice::ReadOnly | QIODevice::Text)) {
                return Schema::Err(QStringLiteral("Cannot read /proc/uptime"));
            }
            QStringList Parts = QString::fromUtf8(Uptime.readAll()).trimmed().split(QChar(' '));
            Uptime.close();
            if (Parts.size() < 2) return Schema::Err(QStringLiteral("Malformed uptime data"));
            double UptimeSec = Parts[0].toDouble();
            double IdleSec = Parts[1].toDouble();
            QJsonObject Result;
            Result[QStringLiteral("uptime_seconds")] = UptimeSec;
            Result[QStringLiteral("idle_seconds")] = IdleSec;
            int Days = static_cast<int>(UptimeSec / 86400);
            int Hours = static_cast<int>(static_cast<int>(UptimeSec) % 86400 / 3600);
            int Mins = static_cast<int>(static_cast<int>(UptimeSec) % 3600 / 60);
            int Secs = static_cast<int>(UptimeSec) % 60;
            QString Human;
            if (Days > 0) Human += QString::number(Days) + QStringLiteral("d ");
            Human += QString::number(Hours) + QStringLiteral("h ") +
                     QString::number(Mins) + QStringLiteral("m ") +
                     QString::number(Secs) + QStringLiteral("s");
            Result[QStringLiteral("uptime_human")] = Human;
            int CpuCount = QThread::idealThreadCount();
            if (CpuCount > 0) {
                double IdlePercent = (UptimeSec > 0) ? (IdleSec / (UptimeSec * CpuCount) * 100.0) : 0.0;
                Result[QStringLiteral("idle_percent")] = QString::number(IdlePercent, 'f', 1).toDouble();
            }
            return Result;
        });

    RegisterTool(QStringLiteral("get_disk_usage"),
        QStringLiteral("Get disk space usage for mounted filesystems from /proc/mounts and statfs."),
        Schema::Build({
            {QStringLiteral("path"), Schema::String(QStringLiteral("Specific path to check (default: all mounted filesystems)"))}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(A);
            QFile Mounts(QStringLiteral("/proc/mounts"));
            if (!Mounts.open(QIODevice::ReadOnly | QIODevice::Text)) {
                return Schema::Err(QStringLiteral("Cannot read /proc/mounts"));
            }
            QByteArray Content = Mounts.readAll();
            Mounts.close();
            QStringList Lines = QString::fromUtf8(Content).split(QChar('\n'), Qt::SkipEmptyParts);
            QJsonArray Filesystems;
            for (const QString& Line : Lines) {
                QStringList Parts = Line.split(QChar(' '), Qt::SkipEmptyParts);
                if (Parts.size() < 4) continue;
                QString Device = Parts[0];
                QString MountPoint = Parts[1];
                QString FsType = Parts[2];
                if (FsType == QStringLiteral("proc") || FsType == QStringLiteral("sysfs") ||
                    FsType == QStringLiteral("devpts") || FsType == QStringLiteral("tmpfs") ||
                    FsType == QStringLiteral("cgroup") || FsType == QStringLiteral("cgroup2") ||
                    FsType == QStringLiteral("securityfs") || FsType == QStringLiteral("debugfs") ||
                    FsType == QStringLiteral("pstore") || FsType == QStringLiteral("mqueue") ||
                    FsType == QStringLiteral("hugetlbfs") || FsType == QStringLiteral("fusectl") ||
                    FsType == QStringLiteral("configfs") || FsType == QStringLiteral("binfmt_misc") ||
                    FsType == QStringLiteral("rpc_pipefs") || FsType == QStringLiteral("autofs") ||
                    FsType == QStringLiteral("efivarfs") || FsType == QStringLiteral("devtmpfs")) {
                    continue;
                }
                QJsonObject Fs;
                Fs[QStringLiteral("device")] = Device;
                Fs[QStringLiteral("mount_point")] = MountPoint;
                Fs[QStringLiteral("type")] = FsType;
                QStorageInfo Storage(MountPoint);
                if (Storage.isValid()) {
                    qint64 TotalBytes = Storage.bytesTotal();
                    qint64 FreeBytes = Storage.bytesFree();
                    qint64 AvailBytes = Storage.bytesAvailable();
                    qint64 UsedBytes = TotalBytes - FreeBytes;
                    Fs[QStringLiteral("total_bytes")] = TotalBytes;
                    Fs[QStringLiteral("free_bytes")] = FreeBytes;
                    Fs[QStringLiteral("available_bytes")] = AvailBytes;
                    Fs[QStringLiteral("used_bytes")] = UsedBytes;
                    Fs[QStringLiteral("total_gb")] = QString::number(static_cast<double>(TotalBytes) / (1024.0 * 1024.0 * 1024.0), 'f', 1).toDouble();
                    Fs[QStringLiteral("used_gb")] = QString::number(static_cast<double>(UsedBytes) / (1024.0 * 1024.0 * 1024.0), 'f', 1).toDouble();
                    Fs[QStringLiteral("free_gb")] = QString::number(static_cast<double>(FreeBytes) / (1024.0 * 1024.0 * 1024.0), 'f', 1).toDouble();
                    double UsagePercent = (TotalBytes > 0) ? (static_cast<double>(UsedBytes) / TotalBytes * 100.0) : 0.0;
                    Fs[QStringLiteral("usage_percent")] = QString::number(UsagePercent, 'f', 1).toDouble();
                }
                Filesystems.append(Fs);
            }
            QJsonObject Result;
            Result[QStringLiteral("filesystems")] = Filesystems;
            Result[QStringLiteral("count")] = Filesystems.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_network_interfaces"),
        QStringLiteral("Get list of network interfaces with addresses from /proc/net/dev."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QFile Dev(QStringLiteral("/proc/net/dev"));
            if (!Dev.open(QIODevice::ReadOnly | QIODevice::Text)) {
                return Schema::Err(QStringLiteral("Cannot read /proc/net/dev"));
            }
            QByteArray Content = Dev.readAll();
            Dev.close();
            QStringList Lines = QString::fromUtf8(Content).split(QChar('\n'), Qt::SkipEmptyParts);
            QJsonArray Interfaces;
            for (int I = 2; I < Lines.size(); ++I) {
                QString Line = Lines[I].trimmed();
                int Colon = Line.indexOf(QChar(':'));
                if (Colon <= 0) continue;
                QString IfName = Line.left(Colon).trimmed();
                QStringList Stats = Line.mid(Colon + 1).trimmed().split(QChar(' '), Qt::SkipEmptyParts);
                QJsonObject Iface;
                Iface[QStringLiteral("name")] = IfName;
                if (Stats.size() >= 16) {
                    Iface[QStringLiteral("rx_bytes")] = Stats[0].toLongLong();
                    Iface[QStringLiteral("rx_packets")] = Stats[1].toLongLong();
                    Iface[QStringLiteral("rx_errors")] = Stats[2].toLongLong();
                    Iface[QStringLiteral("rx_dropped")] = Stats[3].toLongLong();
                    Iface[QStringLiteral("tx_bytes")] = Stats[8].toLongLong();
                    Iface[QStringLiteral("tx_packets")] = Stats[9].toLongLong();
                    Iface[QStringLiteral("tx_errors")] = Stats[10].toLongLong();
                    Iface[QStringLiteral("tx_dropped")] = Stats[11].toLongLong();
                    double RxMb = Stats[0].toLongLong() / (1024.0 * 1024.0);
                    double TxMb = Stats[8].toLongLong() / (1024.0 * 1024.0);
                    Iface[QStringLiteral("rx_mb")] = QString::number(RxMb, 'f', 2).toDouble();
                    Iface[QStringLiteral("tx_mb")] = QString::number(TxMb, 'f', 2).toDouble();
                }
                Interfaces.append(Iface);
            }
            QJsonObject Result;
            Result[QStringLiteral("interfaces")] = Interfaces;
            Result[QStringLiteral("count")] = Interfaces.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_fidra_info"),
        QStringLiteral("Get information about the Fidra application itself: version, build info, loaded modules, tool count."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QJsonObject Result;
            Result[QStringLiteral("name")] = QStringLiteral("Fidra Standalone");
            Result[QStringLiteral("version")] = QStringLiteral("1.0.0-dev");
            Result[QStringLiteral("qt_version")] = QString::fromLatin1(qVersion());
            Result[QStringLiteral("compiled_qt")] = QString::fromLatin1(QT_VERSION_STR);
            Result[QStringLiteral("pid")] = QCoreApplication::applicationPid();
            Result[QStringLiteral("application_dir")] = QCoreApplication::applicationDirPath();
            Result[QStringLiteral("application_path")] = QCoreApplication::applicationFilePath();
            int ToolCount = Tools.size();
            Result[QStringLiteral("registered_tools")] = ToolCount;
            QJsonArray ToolNames;
            for (auto It = Tools.constBegin(); It != Tools.constEnd(); ++It) {
                ToolNames.append(It.key());
            }
            Result[QStringLiteral("tool_names")] = ToolNames;
            if (CoreRef) {
                Result[QStringLiteral("core_available")] = true;
                Result[QStringLiteral("process_attached")] = CoreRef->IsAttached();
                if (CoreRef->IsAttached()) {
                    ProcessInfo Proc = CoreRef->CurrentProcess();
                    Result[QStringLiteral("current_process")] = Proc.Name;
                    Result[QStringLiteral("current_pid")] = static_cast<int>(Proc.Pid);
                }
            } else {
                Result[QStringLiteral("core_available")] = false;
            }
            return Result;
        });

    RegisterTool(QStringLiteral("list_all_tools"),
        QStringLiteral("List all registered MCP tools with their names and descriptions. Supports filtering by name or keyword."),
        Schema::Build({
            {QStringLiteral("filter"), Schema::String(QStringLiteral("Optional filter keyword to match tool names or descriptions"))},
            {QStringLiteral("category"), Schema::String(QStringLiteral("Optional category filter (e.g. 'memory', 'debug', 'analysis')"))}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Filter = A.value(QStringLiteral("filter")).toString().toLower();
            QString Category = A.value(QStringLiteral("category")).toString().toLower();
            QJsonArray ToolList;
            for (auto It = Tools.constBegin(); It != Tools.constEnd(); ++It) {
                const McpToolDefinition& Tool = It.value();
                if (!Filter.isEmpty()) {
                    if (!Tool.Name.toLower().contains(Filter) &&
                        !Tool.Description.toLower().contains(Filter)) {
                        continue;
                    }
                }
                if (!Category.isEmpty()) {
                    bool Match = false;
                    if (Category == QStringLiteral("memory") && (Tool.Name.contains(QStringLiteral("memory")) || Tool.Name.contains(QStringLiteral("mem")) || Tool.Name.contains(QStringLiteral("snapshot")) || Tool.Name.contains(QStringLiteral("patch")) || Tool.Name.contains(QStringLiteral("freeze")) || Tool.Name.contains(QStringLiteral("scan")))) Match = true;
                    else if (Category == QStringLiteral("debug") && (Tool.Name.contains(QStringLiteral("debug")) || Tool.Name.contains(QStringLiteral("breakpoint")) || Tool.Name.contains(QStringLiteral("step")) || Tool.Name.contains(QStringLiteral("register")) || Tool.Name.contains(QStringLiteral("stack")) || Tool.Name.contains(QStringLiteral("trace")))) Match = true;
                    else if (Category == QStringLiteral("analysis") && (Tool.Name.contains(QStringLiteral("disasm")) || Tool.Name.contains(QStringLiteral("xref")) || Tool.Name.contains(QStringLiteral("function")) || Tool.Name.contains(QStringLiteral("string")) || Tool.Name.contains(QStringLiteral("vtable")) || Tool.Name.contains(QStringLiteral("struct")))) Match = true;
                    else if (Category == QStringLiteral("network") && (Tool.Name.contains(QStringLiteral("http")) || Tool.Name.contains(QStringLiteral("tcp")) || Tool.Name.contains(QStringLiteral("udp")) || Tool.Name.contains(QStringLiteral("dns")) || Tool.Name.contains(QStringLiteral("socket")) || Tool.Name.contains(QStringLiteral("network")))) Match = true;
                    else if (Category == QStringLiteral("file") && (Tool.Name.contains(QStringLiteral("file")) || Tool.Name.contains(QStringLiteral("elf")) || Tool.Name.contains(QStringLiteral("pe")) || Tool.Name.contains(QStringLiteral("binary")))) Match = true;
                    else if (Category == QStringLiteral("encoding") && (Tool.Name.contains(QStringLiteral("encode")) || Tool.Name.contains(QStringLiteral("decode")) || Tool.Name.contains(QStringLiteral("hash")) || Tool.Name.contains(QStringLiteral("base64")) || Tool.Name.contains(QStringLiteral("hex")) || Tool.Name.contains(QStringLiteral("crypt")))) Match = true;
                    if (!Match) continue;
                }
                QJsonObject ToolInfo;
                ToolInfo[QStringLiteral("name")] = Tool.Name;
                ToolInfo[QStringLiteral("description")] = Tool.Description;
                ToolInfo[QStringLiteral("enabled")] = Tool.Enabled;
                ToolList.append(ToolInfo);
            }
            QJsonObject Result;
            Result[QStringLiteral("tools")] = ToolList;
            Result[QStringLiteral("count")] = ToolList.size();
            Result[QStringLiteral("total_registered")] = Tools.size();
            return Result;
        });
}

}
