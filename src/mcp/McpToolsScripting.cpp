#include "McpToolRegistry.h"
#include "McpSchemaBuilder.h"
#include <QJsonDocument>
#include <QFile>
#include <QDir>
#include <QTextStream>

namespace Fidra {

void McpToolRegistry::RegisterScriptingTools() {

    RegisterTool(QStringLiteral("create_bookmark"),
        QStringLiteral("Create a named bookmark at an address for quick navigation."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Address in hex"))},
            {QStringLiteral("name"), Schema::String(QStringLiteral("Bookmark name"))},
            {QStringLiteral("description"), Schema::String(QStringLiteral("Optional description"))}
        }, {QStringLiteral("address"), QStringLiteral("name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString AddrStr = A.value(QStringLiteral("address")).toString();
            QString Name = A.value(QStringLiteral("name")).toString();
            QString Desc = A.value(QStringLiteral("description")).toString();
            Address Addr = Schema::ParseHexAddress(AddrStr);

            QJsonObject Entry;
            Entry[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Entry[QStringLiteral("name")] = Name;
            Entry[QStringLiteral("description")] = Desc;

            QJsonArray& Arr = Bookmarks[QStringLiteral("default")];
            for (int I = 0; I < Arr.size(); ++I) {
                if (Arr[I].toObject().value(QStringLiteral("name")).toString() == Name) {
                    Arr[I] = Entry;
                    QJsonObject R;
                    R[QStringLiteral("success")] = true;
                    R[QStringLiteral("message")] = QStringLiteral("Bookmark updated: ") + Name;
                    return R;
                }
            }
            Arr.append(Entry);

            QJsonObject R;
            R[QStringLiteral("success")] = true;
            R[QStringLiteral("message")] = QStringLiteral("Bookmark created: ") + Name;
            R[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            return R;
        });

    RegisterTool(QStringLiteral("list_bookmarks"),
        QStringLiteral("List all saved bookmarks."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QJsonObject R;
            QJsonArray All;
            for (auto It = Bookmarks.constBegin(); It != Bookmarks.constEnd(); ++It) {
                for (int I = 0; I < It.value().size(); ++I) {
                    QJsonObject Bm = It.value()[I].toObject();
                    Bm[QStringLiteral("category")] = It.key();
                    All.append(Bm);
                }
            }
            R[QStringLiteral("count")] = All.size();
            R[QStringLiteral("bookmarks")] = All;
            return R;
        });

    RegisterTool(QStringLiteral("delete_bookmark"),
        QStringLiteral("Delete a bookmark by name."),
        Schema::Build({
            {QStringLiteral("name"), Schema::String(QStringLiteral("Bookmark name to delete"))}
        }, {QStringLiteral("name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Name = A.value(QStringLiteral("name")).toString();
            for (auto It = Bookmarks.begin(); It != Bookmarks.end(); ++It) {
                QJsonArray& Arr = It.value();
                for (int I = 0; I < Arr.size(); ++I) {
                    if (Arr[I].toObject().value(QStringLiteral("name")).toString() == Name) {
                        Arr.removeAt(I);
                        return Schema::Ok(QStringLiteral("Bookmark deleted: ") + Name);
                    }
                }
            }
            return Schema::Err(QStringLiteral("Bookmark not found: ") + Name);
        });

    RegisterTool(QStringLiteral("goto_bookmark"),
        QStringLiteral("Look up a bookmark by name and return its address."),
        Schema::Build({
            {QStringLiteral("name"), Schema::String(QStringLiteral("Bookmark name"))}
        }, {QStringLiteral("name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Name = A.value(QStringLiteral("name")).toString();
            for (auto It = Bookmarks.constBegin(); It != Bookmarks.constEnd(); ++It) {
                for (int I = 0; I < It.value().size(); ++I) {
                    QJsonObject Bm = It.value()[I].toObject();
                    if (Bm.value(QStringLiteral("name")).toString() == Name) {
                        QJsonObject R;
                        R[QStringLiteral("address")] = Bm.value(QStringLiteral("address"));
                        R[QStringLiteral("name")] = Name;
                        R[QStringLiteral("description")] = Bm.value(QStringLiteral("description"));
                        return R;
                    }
                }
            }
            return Schema::Err(QStringLiteral("Bookmark not found: ") + Name);
        });

    RegisterTool(QStringLiteral("add_label"),
        QStringLiteral("Add a label/name to an address for easier identification."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Address in hex"))},
            {QStringLiteral("label"), Schema::String(QStringLiteral("Label name"))}
        }, {QStringLiteral("address"), QStringLiteral("label")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString AddrStr = A.value(QStringLiteral("address")).toString();
            QString LabelName = A.value(QStringLiteral("label")).toString();
            Address Addr = Schema::ParseHexAddress(AddrStr);
            QString Key = Schema::FormatAddress(Addr);

            QJsonObject Entry;
            Entry[QStringLiteral("address")] = Key;
            Entry[QStringLiteral("label")] = LabelName;

            QJsonArray& Arr = Labels[QStringLiteral("default")];
            for (int I = 0; I < Arr.size(); ++I) {
                if (Arr[I].toObject().value(QStringLiteral("address")).toString() == Key) {
                    Arr[I] = Entry;
                    return Schema::Ok(QStringLiteral("Label updated at ") + Key);
                }
            }
            Arr.append(Entry);

            QJsonObject R;
            R[QStringLiteral("success")] = true;
            R[QStringLiteral("address")] = Key;
            R[QStringLiteral("label")] = LabelName;
            return R;
        });

    RegisterTool(QStringLiteral("get_label"),
        QStringLiteral("Get the label assigned to a specific address."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Address in hex"))}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QString Key = Schema::FormatAddress(Addr);

            for (auto It = Labels.constBegin(); It != Labels.constEnd(); ++It) {
                for (int I = 0; I < It.value().size(); ++I) {
                    QJsonObject Lbl = It.value()[I].toObject();
                    if (Lbl.value(QStringLiteral("address")).toString() == Key) {
                        QJsonObject R;
                        R[QStringLiteral("address")] = Key;
                        R[QStringLiteral("label")] = Lbl.value(QStringLiteral("label"));
                        return R;
                    }
                }
            }
            return Schema::Err(QStringLiteral("No label at ") + Key);
        });

    RegisterTool(QStringLiteral("list_labels"),
        QStringLiteral("List all labels with their addresses."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QJsonArray All;
            for (auto It = Labels.constBegin(); It != Labels.constEnd(); ++It) {
                for (int I = 0; I < It.value().size(); ++I) {
                    All.append(It.value()[I]);
                }
            }
            QJsonObject R;
            R[QStringLiteral("count")] = All.size();
            R[QStringLiteral("labels")] = All;
            return R;
        });

    RegisterTool(QStringLiteral("delete_label"),
        QStringLiteral("Remove a label from an address."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Address in hex"))}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QString Key = Schema::FormatAddress(Addr);

            for (auto It = Labels.begin(); It != Labels.end(); ++It) {
                QJsonArray& Arr = It.value();
                for (int I = 0; I < Arr.size(); ++I) {
                    if (Arr[I].toObject().value(QStringLiteral("address")).toString() == Key) {
                        Arr.removeAt(I);
                        return Schema::Ok(QStringLiteral("Label deleted at ") + Key);
                    }
                }
            }
            return Schema::Err(QStringLiteral("No label at ") + Key);
        });

    RegisterTool(QStringLiteral("create_macro"),
        QStringLiteral("Create a macro (named sequence of tool calls) for automation."),
        Schema::Build({
            {QStringLiteral("name"), Schema::String(QStringLiteral("Macro name"))},
            {QStringLiteral("description"), Schema::String(QStringLiteral("What this macro does"))},
            {QStringLiteral("steps"), Schema::Array(QStringLiteral("Array of {tool, args} objects"))}
        }, {QStringLiteral("name"), QStringLiteral("steps")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Name = A.value(QStringLiteral("name")).toString();
            QString Desc = A.value(QStringLiteral("description")).toString();
            QJsonArray Steps = A.value(QStringLiteral("steps")).toArray();

            if (Steps.isEmpty()) {
                return Schema::Err(QStringLiteral("Macro must have at least one step"));
            }

            for (int I = 0; I < Steps.size(); ++I) {
                QJsonObject Step = Steps[I].toObject();
                if (!Step.contains(QStringLiteral("tool"))) {
                    return Schema::Err(QStringLiteral("Step ") + QString::number(I) + QStringLiteral(" missing 'tool' field"));
                }
            }

            QJsonObject MacroDef;
            MacroDef[QStringLiteral("name")] = Name;
            MacroDef[QStringLiteral("description")] = Desc;
            MacroDef[QStringLiteral("steps")] = Steps;
            MacroDef[QStringLiteral("step_count")] = Steps.size();

            QJsonArray MacroArr;
            MacroArr.append(MacroDef);
            Macros[Name] = MacroArr;

            QJsonObject R;
            R[QStringLiteral("success")] = true;
            R[QStringLiteral("name")] = Name;
            R[QStringLiteral("step_count")] = Steps.size();
            return R;
        });

    RegisterTool(QStringLiteral("run_macro"),
        QStringLiteral("Execute a stored macro by name, running each tool call in sequence."),
        Schema::Build({
            {QStringLiteral("name"), Schema::String(QStringLiteral("Macro name to run"))}
        }, {QStringLiteral("name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Name = A.value(QStringLiteral("name")).toString();

            if (!Macros.contains(Name)) {
                return Schema::Err(QStringLiteral("Macro not found: ") + Name);
            }

            QJsonArray MacroArr = Macros[Name];
            if (MacroArr.isEmpty()) {
                return Schema::Err(QStringLiteral("Macro is empty"));
            }

            QJsonObject MacroDef = MacroArr[0].toObject();
            QJsonArray Steps = MacroDef.value(QStringLiteral("steps")).toArray();

            QJsonArray Results;
            for (int I = 0; I < Steps.size(); ++I) {
                QJsonObject Step = Steps[I].toObject();
                QString ToolName = Step.value(QStringLiteral("tool")).toString();
                QJsonObject ToolArgs = Step.value(QStringLiteral("args")).toObject();

                QJsonValue Result = CallTool(ToolName, ToolArgs);

                QJsonObject StepResult;
                StepResult[QStringLiteral("step")] = I;
                StepResult[QStringLiteral("tool")] = ToolName;
                StepResult[QStringLiteral("result")] = Result;

                bool IsError = false;
                if (Result.isObject() && Result.toObject().contains(QStringLiteral("error"))) {
                    IsError = true;
                }
                StepResult[QStringLiteral("is_error")] = IsError;
                Results.append(StepResult);
            }

            QJsonObject R;
            R[QStringLiteral("macro")] = Name;
            R[QStringLiteral("steps_executed")] = Results.size();
            R[QStringLiteral("results")] = Results;
            return R;
        });

    RegisterTool(QStringLiteral("list_macros"),
        QStringLiteral("List all stored macros with names and descriptions."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QJsonArray All;
            for (auto It = Macros.constBegin(); It != Macros.constEnd(); ++It) {
                if (!It.value().isEmpty()) {
                    QJsonObject MacroDef = It.value()[0].toObject();
                    QJsonObject Entry;
                    Entry[QStringLiteral("name")] = MacroDef.value(QStringLiteral("name"));
                    Entry[QStringLiteral("description")] = MacroDef.value(QStringLiteral("description"));
                    Entry[QStringLiteral("step_count")] = MacroDef.value(QStringLiteral("step_count"));
                    All.append(Entry);
                }
            }
            QJsonObject R;
            R[QStringLiteral("count")] = All.size();
            R[QStringLiteral("macros")] = All;
            return R;
        });

    RegisterTool(QStringLiteral("delete_macro"),
        QStringLiteral("Delete a stored macro by name."),
        Schema::Build({
            {QStringLiteral("name"), Schema::String(QStringLiteral("Macro name to delete"))}
        }, {QStringLiteral("name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Name = A.value(QStringLiteral("name")).toString();
            if (Macros.remove(Name) > 0) {
                return Schema::Ok(QStringLiteral("Macro deleted: ") + Name);
            }
            return Schema::Err(QStringLiteral("Macro not found: ") + Name);
        });

    RegisterTool(QStringLiteral("export_to_json"),
        QStringLiteral("Export data as formatted JSON. Optionally write to a file."),
        Schema::Build({
            {QStringLiteral("data"), Schema::Object(QStringLiteral("Data to export as JSON"))},
            {QStringLiteral("file_path"), Schema::String(QStringLiteral("Optional file path to write to"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QJsonValue Data = A.value(QStringLiteral("data"));
            QJsonDocument Doc;
            if (Data.isObject()) {
                Doc = QJsonDocument(Data.toObject());
            } else if (Data.isArray()) {
                Doc = QJsonDocument(Data.toArray());
            } else {
                QJsonObject Wrapper;
                Wrapper[QStringLiteral("value")] = Data;
                Doc = QJsonDocument(Wrapper);
            }

            QString JsonStr = QString::fromUtf8(Doc.toJson(QJsonDocument::Indented));

            if (A.contains(QStringLiteral("file_path"))) {
                QString FilePath = A.value(QStringLiteral("file_path")).toString();
                QFile File(FilePath);
                if (!File.open(QIODevice::WriteOnly | QIODevice::Text)) {
                    return Schema::Err(QStringLiteral("Failed to open file: ") + FilePath);
                }
                QTextStream Out(&File);
                Out << JsonStr;
                File.close();

                QJsonObject R;
                R[QStringLiteral("success")] = true;
                R[QStringLiteral("file")] = FilePath;
                R[QStringLiteral("size")] = JsonStr.size();
                return R;
            }

            QJsonObject R;
            R[QStringLiteral("json")] = JsonStr;
            R[QStringLiteral("size")] = JsonStr.size();
            return R;
        });

    RegisterTool(QStringLiteral("export_to_csv"),
        QStringLiteral("Export array of objects as CSV format. Optionally write to a file."),
        Schema::Build({
            {QStringLiteral("data"), Schema::Array(QStringLiteral("Array of objects to export"))},
            {QStringLiteral("file_path"), Schema::String(QStringLiteral("Optional file path to write to"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QJsonArray Data = A.value(QStringLiteral("data")).toArray();
            if (Data.isEmpty()) {
                return Schema::Err(QStringLiteral("Empty data array"));
            }

            QStringList Headers;
            for (int I = 0; I < Data.size(); ++I) {
                QJsonObject Row = Data[I].toObject();
                for (auto It = Row.constBegin(); It != Row.constEnd(); ++It) {
                    if (!Headers.contains(It.key())) {
                        Headers.append(It.key());
                    }
                }
            }

            QString Csv;
            Csv += Headers.join(QStringLiteral(",")) + QStringLiteral("\n");

            for (int I = 0; I < Data.size(); ++I) {
                QJsonObject Row = Data[I].toObject();
                QStringList Values;
                for (const QString& Header : Headers) {
                    QJsonValue Val = Row.value(Header);
                    QString CellStr;
                    if (Val.isString()) {
                        CellStr = QStringLiteral("\"") + Val.toString().replace(QStringLiteral("\""), QStringLiteral("\"\"")) + QStringLiteral("\"");
                    } else if (Val.isDouble()) {
                        CellStr = QString::number(Val.toDouble());
                    } else if (Val.isBool()) {
                        CellStr = Val.toBool() ? QStringLiteral("true") : QStringLiteral("false");
                    } else {
                        CellStr = QStringLiteral("");
                    }
                    Values.append(CellStr);
                }
                Csv += Values.join(QStringLiteral(",")) + QStringLiteral("\n");
            }

            if (A.contains(QStringLiteral("file_path"))) {
                QString FilePath = A.value(QStringLiteral("file_path")).toString();
                QFile File(FilePath);
                if (!File.open(QIODevice::WriteOnly | QIODevice::Text)) {
                    return Schema::Err(QStringLiteral("Failed to open file: ") + FilePath);
                }
                QTextStream Out(&File);
                Out << Csv;
                File.close();

                QJsonObject R;
                R[QStringLiteral("success")] = true;
                R[QStringLiteral("file")] = FilePath;
                R[QStringLiteral("rows")] = Data.size();
                R[QStringLiteral("columns")] = Headers.size();
                return R;
            }

            QJsonObject R;
            R[QStringLiteral("csv")] = Csv;
            R[QStringLiteral("rows")] = Data.size();
            R[QStringLiteral("columns")] = Headers.size();
            return R;
        });

    RegisterTool(QStringLiteral("export_function_list"),
        QStringLiteral("Scan memory for function prologues and export the list of found function addresses."),
        Schema::Build({
            {QStringLiteral("file_path"), Schema::String(QStringLiteral("Optional file path to write to"))}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) {
                return Schema::NotAttached();
            }

            QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
            QJsonArray Functions;
            constexpr int MaxFunctions = 10000;
            constexpr size_t ChunkSize = 4 * 1024 * 1024;

            static const uint8_t Prologue1[] = {0x55, 0x48, 0x89, 0xE5};
            static const uint8_t Prologue2[] = {0x55, 0x89, 0xE5};
            static const uint8_t Prologue3[] = {0x48, 0x89, 0x5C, 0x24};
            static const uint8_t Prologue4[] = {0x48, 0x83, 0xEC};
            static const uint8_t Prologue5[] = {0x40, 0x55};
            static const uint8_t Prologue6[] = {0x40, 0x53};

            for (const MemoryRegion& Region : Regions) {
                if (Functions.size() >= MaxFunctions) break;
                if (!(Region.Protection & 0x10) && !(Region.Protection & 0x20) && !(Region.Protection & 0x40)) continue;

                size_t Remaining = Region.Size;
                Address CurrentBase = Region.Base;

                while (Remaining > 0 && Functions.size() < MaxFunctions) {
                    size_t ToRead = std::min(Remaining, ChunkSize);
                    QByteArray Chunk(static_cast<int>(ToRead), '\0');
                    if (!CoreRef->ReadMemory(CurrentBase, Chunk.data(), ToRead)) {
                        CurrentBase += ToRead;
                        Remaining -= ToRead;
                        continue;
                    }

                    const uint8_t* Data = reinterpret_cast<const uint8_t*>(Chunk.constData());
                    for (size_t I = 0; I + 4 <= ToRead && Functions.size() < MaxFunctions; ++I) {
                        bool Found = false;
                        if (I + 4 <= ToRead && memcmp(Data + I, Prologue1, 4) == 0) Found = true;
                        else if (I + 3 <= ToRead && memcmp(Data + I, Prologue2, 3) == 0) Found = true;
                        else if (I + 4 <= ToRead && memcmp(Data + I, Prologue3, 4) == 0) Found = true;
                        else if (I + 3 <= ToRead && memcmp(Data + I, Prologue4, 3) == 0) Found = true;
                        else if (I + 2 <= ToRead && memcmp(Data + I, Prologue5, 2) == 0) Found = true;
                        else if (I + 2 <= ToRead && memcmp(Data + I, Prologue6, 2) == 0) Found = true;

                        if (Found) {
                            QJsonObject Func;
                            Func[QStringLiteral("address")] = Schema::FormatAddress(CurrentBase + I);
                            if (!Region.ModuleName.isEmpty()) {
                                Func[QStringLiteral("module")] = Region.ModuleName;
                            }
                            Functions.append(Func);
                        }
                    }
                    CurrentBase += ToRead;
                    Remaining -= ToRead;
                }
            }

            if (A.contains(QStringLiteral("file_path"))) {
                QString FilePath = A.value(QStringLiteral("file_path")).toString();
                QJsonObject Wrapper;
                Wrapper[QStringLiteral("functions")] = Functions;
                QFile File(FilePath);
                if (File.open(QIODevice::WriteOnly | QIODevice::Text)) {
                    File.write(QJsonDocument(Wrapper).toJson(QJsonDocument::Indented));
                    File.close();
                }
            }

            QJsonObject R;
            R[QStringLiteral("count")] = Functions.size();
            R[QStringLiteral("functions")] = Functions;
            return R;
        });

    RegisterTool(QStringLiteral("export_string_list"),
        QStringLiteral("Scan memory for printable ASCII strings and export them."),
        Schema::Build({
            {QStringLiteral("min_length"), Schema::Integer(QStringLiteral("Minimum string length"), 1, 1000)},
            {QStringLiteral("file_path"), Schema::String(QStringLiteral("Optional file path to write to"))}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) {
                return Schema::NotAttached();
            }

            int MinLen = A.value(QStringLiteral("min_length")).toInt(4);
            QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
            QJsonArray Strings;
            constexpr int MaxStrings = 10000;
            constexpr size_t ChunkSize = 4 * 1024 * 1024;

            for (const MemoryRegion& Region : Regions) {
                if (Strings.size() >= MaxStrings) break;

                size_t Remaining = Region.Size;
                Address CurrentBase = Region.Base;

                while (Remaining > 0 && Strings.size() < MaxStrings) {
                    size_t ToRead = std::min(Remaining, ChunkSize);
                    QByteArray Chunk(static_cast<int>(ToRead), '\0');
                    if (!CoreRef->ReadMemory(CurrentBase, Chunk.data(), ToRead)) {
                        CurrentBase += ToRead;
                        Remaining -= ToRead;
                        continue;
                    }

                    int RunStart = -1;
                    for (size_t I = 0; I <= ToRead && Strings.size() < MaxStrings; ++I) {
                        bool Printable = (I < ToRead) && (static_cast<uint8_t>(Chunk[static_cast<int>(I)]) >= 0x20) &&
                                         (static_cast<uint8_t>(Chunk[static_cast<int>(I)]) <= 0x7E);
                        if (Printable) {
                            if (RunStart < 0) RunStart = static_cast<int>(I);
                        } else {
                            if (RunStart >= 0) {
                                int RunLen = static_cast<int>(I) - RunStart;
                                if (RunLen >= MinLen) {
                                    QJsonObject Str;
                                    Str[QStringLiteral("address")] = Schema::FormatAddress(CurrentBase + static_cast<size_t>(RunStart));
                                    Str[QStringLiteral("length")] = RunLen;
                                    Str[QStringLiteral("string")] = QString::fromLatin1(Chunk.mid(RunStart, RunLen));
                                    Strings.append(Str);
                                }
                                RunStart = -1;
                            }
                        }
                    }

                    CurrentBase += ToRead;
                    Remaining -= ToRead;
                }
            }

            if (A.contains(QStringLiteral("file_path"))) {
                QString FilePath = A.value(QStringLiteral("file_path")).toString();
                QJsonObject Wrapper;
                Wrapper[QStringLiteral("strings")] = Strings;
                QFile File(FilePath);
                if (File.open(QIODevice::WriteOnly | QIODevice::Text)) {
                    File.write(QJsonDocument(Wrapper).toJson(QJsonDocument::Indented));
                    File.close();
                }
            }

            QJsonObject R;
            R[QStringLiteral("count")] = Strings.size();
            R[QStringLiteral("strings")] = Strings;
            return R;
        });

    RegisterTool(QStringLiteral("export_module_list"),
        QStringLiteral("Export list of loaded modules as JSON."),
        Schema::Build({
            {QStringLiteral("file_path"), Schema::String(QStringLiteral("Optional file path to write to"))}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) {
                return Schema::NotAttached();
            }

            QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
            QMap<QString, Address> ModBases;
            QMap<QString, size_t> ModSizes;

            for (const MemoryRegion& Region : Regions) {
                if (Region.ModuleName.isEmpty()) continue;
                if (!ModBases.contains(Region.ModuleName)) {
                    ModBases[Region.ModuleName] = Region.Base;
                    ModSizes[Region.ModuleName] = Region.Size;
                } else {
                    Address Existing = ModBases[Region.ModuleName];
                    if (Region.Base < Existing) ModBases[Region.ModuleName] = Region.Base;
                    Address End1 = Existing + ModSizes[Region.ModuleName];
                    Address End2 = Region.Base + Region.Size;
                    Address EffBase = std::min(Existing, Region.Base);
                    Address EffEnd = std::max(End1, End2);
                    ModSizes[Region.ModuleName] = EffEnd - EffBase;
                    ModBases[Region.ModuleName] = EffBase;
                }
            }

            QJsonArray Modules;
            for (auto It = ModBases.constBegin(); It != ModBases.constEnd(); ++It) {
                QJsonObject Mod;
                Mod[QStringLiteral("name")] = It.key();
                Mod[QStringLiteral("base")] = Schema::FormatAddress(It.value());
                Mod[QStringLiteral("size")] = static_cast<qint64>(ModSizes[It.key()]);
                Modules.append(Mod);
            }

            if (A.contains(QStringLiteral("file_path"))) {
                QString FilePath = A.value(QStringLiteral("file_path")).toString();
                QJsonObject Wrapper;
                Wrapper[QStringLiteral("modules")] = Modules;
                QFile File(FilePath);
                if (File.open(QIODevice::WriteOnly | QIODevice::Text)) {
                    File.write(QJsonDocument(Wrapper).toJson(QJsonDocument::Indented));
                    File.close();
                }
            }

            QJsonObject R;
            R[QStringLiteral("count")] = Modules.size();
            R[QStringLiteral("modules")] = Modules;
            return R;
        });

    RegisterTool(QStringLiteral("import_labels"),
        QStringLiteral("Import labels from a JSON file (array of {address, label} objects)."),
        Schema::Build({
            {QStringLiteral("file_path"), Schema::String(QStringLiteral("Path to JSON file"))}
        }, {QStringLiteral("file_path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString FilePath = A.value(QStringLiteral("file_path")).toString();
            QFile File(FilePath);
            if (!File.open(QIODevice::ReadOnly | QIODevice::Text)) {
                return Schema::Err(QStringLiteral("Failed to open file: ") + FilePath);
            }

            QByteArray Content = File.readAll();
            File.close();

            QJsonParseError ParseErr;
            QJsonDocument Doc = QJsonDocument::fromJson(Content, &ParseErr);
            if (Doc.isNull()) {
                return Schema::Err(QStringLiteral("JSON parse error: ") + ParseErr.errorString());
            }

            QJsonArray Arr;
            if (Doc.isArray()) {
                Arr = Doc.array();
            } else if (Doc.isObject() && Doc.object().contains(QStringLiteral("labels"))) {
                Arr = Doc.object().value(QStringLiteral("labels")).toArray();
            } else {
                return Schema::Err(QStringLiteral("Expected JSON array or object with 'labels' key"));
            }

            int Imported = 0;
            QJsonArray& LabelArr = Labels[QStringLiteral("default")];
            for (int I = 0; I < Arr.size(); ++I) {
                QJsonObject Obj = Arr[I].toObject();
                if (Obj.contains(QStringLiteral("address")) && (Obj.contains(QStringLiteral("label")) || Obj.contains(QStringLiteral("name")))) {
                    QJsonObject Entry;
                    Entry[QStringLiteral("address")] = Obj.value(QStringLiteral("address"));
                    Entry[QStringLiteral("label")] = Obj.contains(QStringLiteral("label")) ? Obj.value(QStringLiteral("label")) : Obj.value(QStringLiteral("name"));

                    bool Updated = false;
                    QString Addr = Entry.value(QStringLiteral("address")).toString();
                    for (int J = 0; J < LabelArr.size(); ++J) {
                        if (LabelArr[J].toObject().value(QStringLiteral("address")).toString() == Addr) {
                            LabelArr[J] = Entry;
                            Updated = true;
                            break;
                        }
                    }
                    if (!Updated) {
                        LabelArr.append(Entry);
                    }
                    Imported++;
                }
            }

            QJsonObject R;
            R[QStringLiteral("success")] = true;
            R[QStringLiteral("imported")] = Imported;
            return R;
        });

    RegisterTool(QStringLiteral("import_bookmarks"),
        QStringLiteral("Import bookmarks from a JSON file."),
        Schema::Build({
            {QStringLiteral("file_path"), Schema::String(QStringLiteral("Path to JSON file"))}
        }, {QStringLiteral("file_path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString FilePath = A.value(QStringLiteral("file_path")).toString();
            QFile File(FilePath);
            if (!File.open(QIODevice::ReadOnly | QIODevice::Text)) {
                return Schema::Err(QStringLiteral("Failed to open file: ") + FilePath);
            }

            QByteArray Content = File.readAll();
            File.close();

            QJsonParseError ParseErr;
            QJsonDocument Doc = QJsonDocument::fromJson(Content, &ParseErr);
            if (Doc.isNull()) {
                return Schema::Err(QStringLiteral("JSON parse error: ") + ParseErr.errorString());
            }

            QJsonArray Arr;
            if (Doc.isArray()) {
                Arr = Doc.array();
            } else if (Doc.isObject() && Doc.object().contains(QStringLiteral("bookmarks"))) {
                Arr = Doc.object().value(QStringLiteral("bookmarks")).toArray();
            } else {
                return Schema::Err(QStringLiteral("Expected JSON array or object with 'bookmarks' key"));
            }

            int Imported = 0;
            QJsonArray& BmArr = Bookmarks[QStringLiteral("default")];
            for (int I = 0; I < Arr.size(); ++I) {
                QJsonObject Obj = Arr[I].toObject();
                if (Obj.contains(QStringLiteral("address")) && Obj.contains(QStringLiteral("name"))) {
                    QJsonObject Entry;
                    Entry[QStringLiteral("address")] = Obj.value(QStringLiteral("address"));
                    Entry[QStringLiteral("name")] = Obj.value(QStringLiteral("name"));
                    Entry[QStringLiteral("description")] = Obj.value(QStringLiteral("description"));

                    bool Updated = false;
                    QString BmName = Entry.value(QStringLiteral("name")).toString();
                    for (int J = 0; J < BmArr.size(); ++J) {
                        if (BmArr[J].toObject().value(QStringLiteral("name")).toString() == BmName) {
                            BmArr[J] = Entry;
                            Updated = true;
                            break;
                        }
                    }
                    if (!Updated) {
                        BmArr.append(Entry);
                    }
                    Imported++;
                }
            }

            QJsonObject R;
            R[QStringLiteral("success")] = true;
            R[QStringLiteral("imported")] = Imported;
            return R;
        });

    RegisterTool(QStringLiteral("run_tool_sequence"),
        QStringLiteral("Run a sequence of tool calls inline without storing as a macro."),
        Schema::Build({
            {QStringLiteral("steps"), Schema::Array(QStringLiteral("Array of {tool, args} objects"))}
        }, {QStringLiteral("steps")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QJsonArray Steps = A.value(QStringLiteral("steps")).toArray();
            if (Steps.isEmpty()) {
                return Schema::Err(QStringLiteral("No steps provided"));
            }

            QJsonArray Results;
            for (int I = 0; I < Steps.size(); ++I) {
                QJsonObject Step = Steps[I].toObject();
                QString ToolName = Step.value(QStringLiteral("tool")).toString();
                QJsonObject ToolArgs = Step.value(QStringLiteral("args")).toObject();

                if (ToolName.isEmpty()) {
                    QJsonObject StepResult;
                    StepResult[QStringLiteral("step")] = I;
                    StepResult[QStringLiteral("error")] = QStringLiteral("Missing tool name");
                    Results.append(StepResult);
                    continue;
                }

                QJsonValue Result = CallTool(ToolName, ToolArgs);

                QJsonObject StepResult;
                StepResult[QStringLiteral("step")] = I;
                StepResult[QStringLiteral("tool")] = ToolName;
                StepResult[QStringLiteral("result")] = Result;
                Results.append(StepResult);
            }

            QJsonObject R;
            R[QStringLiteral("steps_executed")] = Results.size();
            R[QStringLiteral("results")] = Results;
            return R;
        });

    RegisterTool(QStringLiteral("log_to_file"),
        QStringLiteral("Append a message to a log file."),
        Schema::Build({
            {QStringLiteral("file_path"), Schema::String(QStringLiteral("Log file path"))},
            {QStringLiteral("message"), Schema::String(QStringLiteral("Message to log"))}
        }, {QStringLiteral("file_path"), QStringLiteral("message")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString FilePath = A.value(QStringLiteral("file_path")).toString();
            QString Message = A.value(QStringLiteral("message")).toString();

            QFile File(FilePath);
            if (!File.open(QIODevice::Append | QIODevice::Text)) {
                return Schema::Err(QStringLiteral("Failed to open file: ") + FilePath);
            }

            QTextStream Out(&File);
            Out << QDateTime::currentDateTime().toString(Qt::ISODate) << QStringLiteral(" ") << Message << QStringLiteral("\n");
            File.close();

            return Schema::Ok(QStringLiteral("Logged to ") + FilePath);
        });

    RegisterTool(QStringLiteral("read_from_file"),
        QStringLiteral("Read contents of a file and return as string."),
        Schema::Build({
            {QStringLiteral("file_path"), Schema::String(QStringLiteral("File path to read"))},
            {QStringLiteral("max_size"), Schema::Integer(QStringLiteral("Maximum bytes to read"), 1, 10485760)}
        }, {QStringLiteral("file_path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString FilePath = A.value(QStringLiteral("file_path")).toString();
            int MaxSize = A.value(QStringLiteral("max_size")).toInt(1048576);

            QFile File(FilePath);
            if (!File.open(QIODevice::ReadOnly | QIODevice::Text)) {
                return Schema::Err(QStringLiteral("Failed to open file: ") + FilePath);
            }

            QByteArray Content = File.read(MaxSize);
            File.close();

            QJsonObject R;
            R[QStringLiteral("file")] = FilePath;
            R[QStringLiteral("size")] = Content.size();
            R[QStringLiteral("content")] = QString::fromUtf8(Content);
            return R;
        });

    RegisterTool(QStringLiteral("write_to_file"),
        QStringLiteral("Write string content to a file."),
        Schema::Build({
            {QStringLiteral("file_path"), Schema::String(QStringLiteral("File path to write"))},
            {QStringLiteral("content"), Schema::String(QStringLiteral("Content to write"))},
            {QStringLiteral("append"), Schema::Boolean(QStringLiteral("Append instead of overwrite"))}
        }, {QStringLiteral("file_path"), QStringLiteral("content")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString FilePath = A.value(QStringLiteral("file_path")).toString();
            QString Content = A.value(QStringLiteral("content")).toString();
            bool Append = A.value(QStringLiteral("append")).toBool(false);

            QFile File(FilePath);
            QIODevice::OpenMode Mode = QIODevice::WriteOnly | QIODevice::Text;
            if (Append) Mode |= QIODevice::Append;

            if (!File.open(Mode)) {
                return Schema::Err(QStringLiteral("Failed to open file: ") + FilePath);
            }

            QTextStream Out(&File);
            Out << Content;
            File.close();

            QJsonObject R;
            R[QStringLiteral("success")] = true;
            R[QStringLiteral("file")] = FilePath;
            R[QStringLiteral("bytes_written")] = Content.toUtf8().size();
            return R;
        });

    RegisterTool(QStringLiteral("get_tool_list"),
        QStringLiteral("List all registered MCP tools with names and descriptions."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QList<McpToolDefinition> AllTools = GetAllTools();
            QJsonArray ToolArr;
            for (const McpToolDefinition& Tool : AllTools) {
                QJsonObject Entry;
                Entry[QStringLiteral("name")] = Tool.Name;
                Entry[QStringLiteral("description")] = Tool.Description;
                Entry[QStringLiteral("enabled")] = Tool.Enabled;
                ToolArr.append(Entry);
            }
            QJsonObject R;
            R[QStringLiteral("count")] = ToolArr.size();
            R[QStringLiteral("tools")] = ToolArr;
            return R;
        });

    RegisterTool(QStringLiteral("get_tool_info"),
        QStringLiteral("Get detailed info about a specific tool including its input schema."),
        Schema::Build({
            {QStringLiteral("name"), Schema::String(QStringLiteral("Tool name"))}
        }, {QStringLiteral("name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Name = A.value(QStringLiteral("name")).toString();
            QList<McpToolDefinition> AllTools = GetAllTools();

            for (const McpToolDefinition& Tool : AllTools) {
                if (Tool.Name == Name) {
                    QJsonObject R;
                    R[QStringLiteral("name")] = Tool.Name;
                    R[QStringLiteral("description")] = Tool.Description;
                    R[QStringLiteral("enabled")] = Tool.Enabled;
                    R[QStringLiteral("input_schema")] = Tool.InputSchema;
                    return R;
                }
            }
            return Schema::Err(QStringLiteral("Tool not found: ") + Name);
        });
}

}
