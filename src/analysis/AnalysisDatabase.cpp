#include "AnalysisDatabase.h"
#include <QReadLocker>
#include <QWriteLocker>
#include <QJsonDocument>
#include <algorithm>

namespace Fidra {

AnalysisDatabase::AnalysisDatabase(QObject* Parent)
    : QObject(Parent) {
}

AnalysisDatabase::~AnalysisDatabase() {
}

void AnalysisDatabase::Clear() {
    {
        QWriteLocker Locker(&InsnLock);
        Instructions.clear();
        ItemTypes.clear();
        LimitWarned = false;
    }
    QWriteLocker Locker(&Lock);
    Binary = BinaryInfo{};
    Functions.clear();
    XrefsTo.clear();
    XrefsFrom.clear();
    Strings.clear();
    Names.clear();
    Comments.clear();
    SortedSegments.clear();
    SortedInsnAddrs.clear();
    InsnIndexBuilt = false;
}

void AnalysisDatabase::SetBinaryInfo(const BinaryInfo& Info) {
    QWriteLocker Locker(&Lock);
    Binary = Info;
}

void AnalysisDatabase::BuildSegmentCache() {
    QWriteLocker Locker(&Lock);
    SortedSegments.clear();
    SortedSegments.reserve(static_cast<size_t>(Binary.Segments.size()));
    for (int I = 0; I < Binary.Segments.size(); ++I) {
        const Segment& Seg = Binary.Segments[I];
        SortedSegments.push_back({Seg.VirtualAddress, Seg.VirtualAddress + Seg.VirtualSize, I});
    }
    std::sort(SortedSegments.begin(), SortedSegments.end(),
        [](const SegmentRange& A, const SegmentRange& B) { return A.Start < B.Start; });
}

const Segment* AnalysisDatabase::FindSegmentUnlocked(Address Addr) const {
    if (!SortedSegments.empty()) {
        size_t Lo = 0, Hi = SortedSegments.size();
        while (Lo < Hi) {
            size_t Mid = Lo + (Hi - Lo) / 2;
            if (SortedSegments[Mid].End <= Addr)
                Lo = Mid + 1;
            else if (SortedSegments[Mid].Start > Addr)
                Hi = Mid;
            else
                return &Binary.Segments[SortedSegments[Mid].Index];
        }
        return nullptr;
    }
    for (const Segment& Seg : Binary.Segments) {
        if (Addr >= Seg.VirtualAddress && Addr < Seg.VirtualAddress + Seg.VirtualSize)
            return &Seg;
    }
    return nullptr;
}

BinaryInfo AnalysisDatabase::GetBinaryInfo() const {
    QReadLocker Locker(&Lock);
    return Binary;
}

void AnalysisDatabase::AddInstruction(const AnalyzedInstruction& Inst) {
    QWriteLocker Locker(&InsnLock);
    if (Instructions.size() >= MaxInstructions) {
        if (!LimitWarned) {
            LimitWarned = true;
            qWarning("AnalysisDatabase: instruction limit (%d) reached, dropping further instructions", MaxInstructions);
        }
        return;
    }
    Instructions.insert(Inst.Addr, Inst);
}

AnalyzedInstruction AnalysisDatabase::GetInstruction(Address Addr) const {
    QReadLocker Locker(&InsnLock);
    auto It = Instructions.constFind(Addr);
    if (It != Instructions.constEnd()) {
        return It.value();
    }
    return AnalyzedInstruction{};
}

bool AnalysisDatabase::HasInstruction(Address Addr) const {
    QReadLocker Locker(&InsnLock);
    return Instructions.contains(Addr);
}

QList<AnalyzedInstruction> AnalysisDatabase::GetInstructions(Address Start, Address End) const {
    QReadLocker Locker(&InsnLock);
    QList<AnalyzedInstruction> Result;
    if (End <= Start) return Result;

    if (InsnIndexBuilt) {
        auto Lo = std::lower_bound(SortedInsnAddrs.begin(), SortedInsnAddrs.end(), Start);
        auto Hi = std::lower_bound(Lo, SortedInsnAddrs.end(), End);
        Result.reserve(static_cast<int>(std::distance(Lo, Hi)));
        for (auto It = Lo; It != Hi; ++It) {
            auto Found = Instructions.constFind(*It);
            if (Found != Instructions.constEnd()) {
                Result.append(Found.value());
            }
        }
    } else {
        for (auto It = Instructions.constBegin(); It != Instructions.constEnd(); ++It) {
            if (It.key() >= Start && It.key() < End) {
                Result.append(It.value());
            }
        }
        std::sort(Result.begin(), Result.end(),
            [](const AnalyzedInstruction& A, const AnalyzedInstruction& B) { return A.Addr < B.Addr; });
    }
    return Result;
}

int AnalysisDatabase::InstructionCount() const {
    QReadLocker Locker(&InsnLock);
    return Instructions.size();
}

bool AnalysisDatabase::InstructionLimitReached() const {
    QReadLocker Locker(&InsnLock);
    return Instructions.size() >= MaxInstructions;
}

void AnalysisDatabase::ForEachInstruction(const std::function<void(const AnalyzedInstruction&)>& Callback) const {
    QReadLocker Locker(&InsnLock);
    for (auto It = Instructions.constBegin(); It != Instructions.constEnd(); ++It) {
        Callback(It.value());
    }
}

void AnalysisDatabase::AddFunction(const AnalyzedFunction& Func) {
    QWriteLocker Locker(&Lock);
    Functions.insert(Func.Start, Func);
    if (!Func.Name.isEmpty()) {
        Names.insert(Func.Start, Func.Name);
    }
    emit FunctionAdded(Func.Start, Func.Name);
}

void AnalysisDatabase::UpdateFunction(Address Start, const AnalyzedFunction& Func) {
    QWriteLocker Locker(&Lock);
    Functions.insert(Start, Func);
    if (!Func.Name.isEmpty()) {
        Names.insert(Start, Func.Name);
    }
}

AnalyzedFunction AnalysisDatabase::GetFunction(Address Addr) const {
    QReadLocker Locker(&Lock);
    auto It = Functions.constFind(Addr);
    if (It != Functions.constEnd()) {
        return It.value();
    }
    return AnalyzedFunction{};
}

AnalyzedFunction AnalysisDatabase::GetFunctionContaining(Address Addr) const {
    QReadLocker Locker(&Lock);
    auto It = Functions.upperBound(Addr);
    if (It != Functions.constBegin()) {
        --It;
        const AnalyzedFunction& Func = It.value();
        if (Addr >= Func.Start && Addr < Func.End) {
            return Func;
        }
    }
    return AnalyzedFunction{};
}

bool AnalysisDatabase::HasFunction(Address Addr) const {
    QReadLocker Locker(&Lock);
    return Functions.contains(Addr);
}

QList<AnalyzedFunction> AnalysisDatabase::GetAllFunctions() const {
    QReadLocker Locker(&Lock);
    return Functions.values();
}

void AnalysisDatabase::ForEachFunction(const std::function<void(const AnalyzedFunction&)>& Callback) const {
    QReadLocker Locker(&Lock);
    for (auto It = Functions.constBegin(); It != Functions.constEnd(); ++It) {
        Callback(It.value());
    }
}

int AnalysisDatabase::FunctionCount() const {
    QReadLocker Locker(&Lock);
    return Functions.size();
}

void AnalysisDatabase::AddXref(const Xref& Ref) {
    QWriteLocker Locker(&Lock);
    XrefsTo.insert(Ref.To, Ref);
    XrefsFrom.insert(Ref.From, Ref);
}

QList<Xref> AnalysisDatabase::GetXrefsTo(Address Addr) const {
    QReadLocker Locker(&Lock);
    return XrefsTo.values(Addr);
}

QList<Xref> AnalysisDatabase::GetXrefsFrom(Address Addr) const {
    QReadLocker Locker(&Lock);
    return XrefsFrom.values(Addr);
}

int AnalysisDatabase::XrefCount() const {
    QReadLocker Locker(&Lock);
    return XrefsTo.size();
}

void AnalysisDatabase::AddString(const AnalyzedString& Str) {
    QWriteLocker Locker(&Lock);
    Strings.insert(Str.Addr, Str);
    emit StringFound(Str.Addr, Str.Value);
}

AnalyzedString AnalysisDatabase::GetString(Address Addr) const {
    QReadLocker Locker(&Lock);
    auto It = Strings.constFind(Addr);
    if (It != Strings.constEnd()) {
        return It.value();
    }
    return AnalyzedString{};
}

bool AnalysisDatabase::HasString(Address Addr) const {
    QReadLocker Locker(&Lock);
    return Strings.contains(Addr);
}

QList<AnalyzedString> AnalysisDatabase::GetAllStrings() const {
    QReadLocker Locker(&Lock);
    return Strings.values();
}

void AnalysisDatabase::ForEachString(const std::function<void(const AnalyzedString&)>& Callback) const {
    QReadLocker Locker(&Lock);
    for (auto It = Strings.constBegin(); It != Strings.constEnd(); ++It) {
        Callback(It.value());
    }
}

int AnalysisDatabase::StringCount() const {
    QReadLocker Locker(&Lock);
    return Strings.size();
}

void AnalysisDatabase::SetItemType(Address Addr, ItemType Type) {
    QWriteLocker Locker(&InsnLock);
    ItemTypes.insert(Addr, Type);
}

ItemType AnalysisDatabase::GetItemType(Address Addr) const {
    QReadLocker Locker(&InsnLock);
    return ItemTypes.value(Addr, ItemType::Unexplored);
}

void AnalysisDatabase::SetName(Address Addr, const QString& Name) {
    QWriteLocker Locker(&Lock);
    if (Name.isEmpty()) {
        Names.remove(Addr);
    } else {
        Names.insert(Addr, Name);
    }
}

QString AnalysisDatabase::GetName(Address Addr) const {
    QReadLocker Locker(&Lock);
    return Names.value(Addr, QString());
}

bool AnalysisDatabase::HasName(Address Addr) const {
    QReadLocker Locker(&Lock);
    return Names.contains(Addr);
}

QMap<Address, QString> AnalysisDatabase::GetAllNames() const {
    QReadLocker Locker(&Lock);
    return Names;
}

void AnalysisDatabase::SetComment(Address Addr, const QString& Comment) {
    QWriteLocker Locker(&Lock);
    if (Comment.isEmpty()) {
        Comments.remove(Addr);
    } else {
        Comments.insert(Addr, Comment);
    }
}

QString AnalysisDatabase::GetComment(Address Addr) const {
    QReadLocker Locker(&Lock);
    return Comments.value(Addr, QString());
}

QMap<Address, QString> AnalysisDatabase::GetAllComments() const {
    QReadLocker Locker(&Lock);
    return Comments;
}

void AnalysisDatabase::BuildInstructionIndex() {
    QWriteLocker Locker(&InsnLock);
    SortedInsnAddrs.clear();
    SortedInsnAddrs.reserve(static_cast<size_t>(Instructions.size()));
    for (auto It = Instructions.constBegin(); It != Instructions.constEnd(); ++It) {
        SortedInsnAddrs.push_back(It.key());
    }
    std::sort(SortedInsnAddrs.begin(), SortedInsnAddrs.end());
    InsnIndexBuilt = true;
}

std::optional<Segment> AnalysisDatabase::GetSegmentAt(Address Addr) const {
    QReadLocker Locker(&Lock);
    const Segment* Seg = FindSegmentUnlocked(Addr);
    if (!Seg) return std::nullopt;
    return *Seg;
}

bool AnalysisDatabase::IsCodeAddress(Address Addr) const {
    QReadLocker Locker(&Lock);
    const Segment* Seg = FindSegmentUnlocked(Addr);
    return Seg && Seg->IsExecutable;
}

bool AnalysisDatabase::IsDataAddress(Address Addr) const {
    QReadLocker Locker(&Lock);
    const Segment* Seg = FindSegmentUnlocked(Addr);
    return Seg && !Seg->IsExecutable;
}

bool AnalysisDatabase::IsAddressValid(Address Addr) const {
    QReadLocker Locker(&Lock);
    return FindSegmentUnlocked(Addr) != nullptr;
}

QByteArray AnalysisDatabase::ReadBytes(Address Addr, size_t Size) const {
    QReadLocker Locker(&Lock);
    const Segment* Seg = FindSegmentUnlocked(Addr);
    if (!Seg) return QByteArray();
    size_t Offset = static_cast<size_t>(Addr - Seg->VirtualAddress);
    if (Offset >= static_cast<size_t>(Seg->Data.size()))
        return QByteArray(static_cast<int>(Size), '\0');
    size_t Available = static_cast<size_t>(Seg->Data.size()) - Offset;
    size_t ToRead = std::min(Size, Available);
    QByteArray Result = Seg->Data.mid(static_cast<int>(Offset), static_cast<int>(ToRead));
    if (ToRead < Size)
        Result.append(QByteArray(static_cast<int>(Size - ToRead), '\0'));
    return Result;
}

QJsonObject AnalysisDatabase::ExportToJson() const {
    QReadLocker Locker(&Lock);

    QJsonObject Root;

    QJsonObject BinInfo;
    BinInfo[QStringLiteral("file_path")] = Binary.FilePath;
    BinInfo[QStringLiteral("file_name")] = Binary.FileName;
    BinInfo[QStringLiteral("image_base")] = QStringLiteral("0x") + QString::number(Binary.ImageBase, 16).toUpper();
    BinInfo[QStringLiteral("entry_point")] = QStringLiteral("0x") + QString::number(Binary.EntryPoint, 16).toUpper();
    BinInfo[QStringLiteral("image_size")] = static_cast<qint64>(Binary.ImageSize);
    BinInfo[QStringLiteral("is_64bit")] = Binary.Is64Bit;
    BinInfo[QStringLiteral("is_dll")] = Binary.IsDll;
    BinInfo[QStringLiteral("linker_version")] = Binary.LinkerVersion;
    Root[QStringLiteral("binary")] = BinInfo;

    QJsonArray SegArr;
    for (const Segment& Seg : Binary.Segments) {
        QJsonObject SegObj;
        SegObj[QStringLiteral("name")] = Seg.Name;
        SegObj[QStringLiteral("virtual_address")] = QStringLiteral("0x") + QString::number(Seg.VirtualAddress, 16).toUpper();
        SegObj[QStringLiteral("virtual_size")] = static_cast<qint64>(Seg.VirtualSize);
        SegObj[QStringLiteral("raw_size")] = static_cast<qint64>(Seg.RawSize);
        SegObj[QStringLiteral("executable")] = Seg.IsExecutable;
        SegObj[QStringLiteral("writable")] = Seg.IsWritable;
        SegArr.append(SegObj);
    }
    Root[QStringLiteral("segments")] = SegArr;

    QJsonArray FuncArr;
    for (auto It = Functions.constBegin(); It != Functions.constEnd(); ++It) {
        const AnalyzedFunction& Func = It.value();
        QJsonObject FuncObj;
        FuncObj[QStringLiteral("name")] = Func.Name;
        FuncObj[QStringLiteral("start")] = QStringLiteral("0x") + QString::number(Func.Start, 16).toUpper();
        FuncObj[QStringLiteral("end")] = QStringLiteral("0x") + QString::number(Func.End, 16).toUpper();
        FuncObj[QStringLiteral("size")] = static_cast<qint64>(Func.Size);
        FuncObj[QStringLiteral("instructions")] = Func.InstructionCount;
        FuncObj[QStringLiteral("basic_blocks")] = Func.BasicBlockCount;
        FuncObj[QStringLiteral("stack_frame")] = Func.StackFrameSize;
        FuncObj[QStringLiteral("arg_count")] = Func.ArgCount;
        FuncObj[QStringLiteral("is_imported")] = Func.IsImported;
        FuncObj[QStringLiteral("is_exported")] = Func.IsExported;
        FuncObj[QStringLiteral("is_thunk")] = Func.IsThunk;
        FuncObj[QStringLiteral("callers")] = Func.Callers.size();
        FuncObj[QStringLiteral("callees")] = Func.Callees.size();
        FuncArr.append(FuncObj);
    }
    Root[QStringLiteral("functions")] = FuncArr;

    QJsonArray StrArr;
    for (auto It = Strings.constBegin(); It != Strings.constEnd(); ++It) {
        const AnalyzedString& Str = It.value();
        QJsonObject StrObj;
        StrObj[QStringLiteral("address")] = QStringLiteral("0x") + QString::number(Str.Addr, 16).toUpper();
        StrObj[QStringLiteral("value")] = Str.Value;
        StrObj[QStringLiteral("is_wide")] = Str.IsWide;
        StrObj[QStringLiteral("length")] = Str.Length;
        StrObj[QStringLiteral("references")] = Str.References.size();
        StrArr.append(StrObj);
    }
    Root[QStringLiteral("strings")] = StrArr;

    QJsonArray ImportArr;
    for (const ImportEntry& Imp : Binary.Imports) {
        QJsonObject ImpObj;
        ImpObj[QStringLiteral("dll")] = Imp.DllName;
        ImpObj[QStringLiteral("function")] = Imp.FuncName;
        ImpObj[QStringLiteral("ordinal")] = Imp.Ordinal;
        ImpObj[QStringLiteral("iat_address")] = QStringLiteral("0x") + QString::number(Imp.IatAddress, 16).toUpper();
        ImportArr.append(ImpObj);
    }
    Root[QStringLiteral("imports")] = ImportArr;

    QJsonArray ExportArr;
    for (const ExportEntry& Exp : Binary.Exports) {
        QJsonObject ExpObj;
        ExpObj[QStringLiteral("name")] = Exp.Name;
        ExpObj[QStringLiteral("ordinal")] = Exp.Ordinal;
        ExpObj[QStringLiteral("address")] = QStringLiteral("0x") + QString::number(Exp.Addr, 16).toUpper();
        ExportArr.append(ExpObj);
    }
    Root[QStringLiteral("exports")] = ExportArr;

    QJsonObject Stats;
    Stats[QStringLiteral("instruction_count")] = Instructions.size();
    Stats[QStringLiteral("function_count")] = Functions.size();
    Stats[QStringLiteral("string_count")] = Strings.size();
    Stats[QStringLiteral("xref_count")] = XrefsTo.size();
    Stats[QStringLiteral("name_count")] = Names.size();
    Stats[QStringLiteral("comment_count")] = Comments.size();
    Root[QStringLiteral("stats")] = Stats;

    return Root;
}

void AnalysisDatabase::ImportFromJson(const QJsonObject& Root) {
    QWriteLocker Locker(&Lock);

    Binary = BinaryInfo{};
    Instructions.clear();
    Functions.clear();
    XrefsTo.clear();
    XrefsFrom.clear();
    Strings.clear();
    ItemTypes.clear();
    Names.clear();
    Comments.clear();
    SortedSegments.clear();
    SortedInsnAddrs.clear();
    InsnIndexBuilt = false;

    QJsonObject BinInfo = Root[QStringLiteral("binary")].toObject();
    Binary.FilePath = BinInfo[QStringLiteral("file_path")].toString();
    Binary.FileName = BinInfo[QStringLiteral("file_name")].toString();
    Binary.ImageBase = BinInfo[QStringLiteral("image_base")].toString().toULongLong(nullptr, 0);
    Binary.EntryPoint = BinInfo[QStringLiteral("entry_point")].toString().toULongLong(nullptr, 0);
    Binary.ImageSize = static_cast<size_t>(BinInfo[QStringLiteral("image_size")].toInteger());
    Binary.Is64Bit = BinInfo[QStringLiteral("is_64bit")].toBool();
    Binary.IsDll = BinInfo[QStringLiteral("is_dll")].toBool();
    Binary.LinkerVersion = BinInfo[QStringLiteral("linker_version")].toString();

    QJsonArray SegArr = Root[QStringLiteral("segments")].toArray();
    for (const QJsonValue& Val : SegArr) {
        QJsonObject SegObj = Val.toObject();
        Segment Seg{};
        Seg.Name = SegObj[QStringLiteral("name")].toString();
        Seg.VirtualAddress = SegObj[QStringLiteral("virtual_address")].toString().toULongLong(nullptr, 0);
        Seg.VirtualSize = static_cast<size_t>(SegObj[QStringLiteral("virtual_size")].toInteger());
        Seg.RawSize = static_cast<size_t>(SegObj[QStringLiteral("raw_size")].toInteger());
        Seg.IsExecutable = SegObj[QStringLiteral("executable")].toBool();
        Seg.IsWritable = SegObj[QStringLiteral("writable")].toBool();
        Seg.IsReadable = true;
        Seg.RawOffset = 0;
        Seg.Characteristics = 0;
        Seg.Type = Seg.IsExecutable ? SegmentType::Code : SegmentType::Data;
        Binary.Segments.append(Seg);
    }

    QJsonArray FuncArr = Root[QStringLiteral("functions")].toArray();
    for (const QJsonValue& Val : FuncArr) {
        QJsonObject FuncObj = Val.toObject();
        AnalyzedFunction Func{};
        Func.Name = FuncObj[QStringLiteral("name")].toString();
        Func.Start = FuncObj[QStringLiteral("start")].toString().toULongLong(nullptr, 0);
        Func.End = FuncObj[QStringLiteral("end")].toString().toULongLong(nullptr, 0);
        Func.Size = static_cast<size_t>(FuncObj[QStringLiteral("size")].toInteger());
        Func.InstructionCount = FuncObj[QStringLiteral("instructions")].toInt();
        Func.BasicBlockCount = FuncObj[QStringLiteral("basic_blocks")].toInt();
        Func.StackFrameSize = FuncObj[QStringLiteral("stack_frame")].toInt();
        Func.ArgCount = FuncObj[QStringLiteral("arg_count")].toInt();
        Func.IsImported = FuncObj[QStringLiteral("is_imported")].toBool();
        Func.IsExported = FuncObj[QStringLiteral("is_exported")].toBool();
        Func.IsThunk = FuncObj[QStringLiteral("is_thunk")].toBool();
        Functions.insert(Func.Start, Func);
        if (!Func.Name.isEmpty()) {
            Names.insert(Func.Start, Func.Name);
        }
    }

    QJsonArray StrArr = Root[QStringLiteral("strings")].toArray();
    for (const QJsonValue& Val : StrArr) {
        QJsonObject StrObj = Val.toObject();
        AnalyzedString Str{};
        Str.Addr = StrObj[QStringLiteral("address")].toString().toULongLong(nullptr, 0);
        Str.Value = StrObj[QStringLiteral("value")].toString();
        Str.IsWide = StrObj[QStringLiteral("is_wide")].toBool();
        Str.Length = StrObj[QStringLiteral("length")].toInt();
        Strings.insert(Str.Addr, Str);
    }

    QJsonArray ImportArr = Root[QStringLiteral("imports")].toArray();
    for (const QJsonValue& Val : ImportArr) {
        QJsonObject ImpObj = Val.toObject();
        ImportEntry Imp{};
        Imp.DllName = ImpObj[QStringLiteral("dll")].toString();
        Imp.FuncName = ImpObj[QStringLiteral("function")].toString();
        Imp.Ordinal = static_cast<uint16_t>(ImpObj[QStringLiteral("ordinal")].toInt());
        Imp.IatAddress = ImpObj[QStringLiteral("iat_address")].toString().toULongLong(nullptr, 0);
        Imp.ThunkAddress = 0;
        Imp.IsBound = false;
        Binary.Imports.append(Imp);
    }

    QJsonArray ExportArr = Root[QStringLiteral("exports")].toArray();
    for (const QJsonValue& Val : ExportArr) {
        QJsonObject ExpObj = Val.toObject();
        ExportEntry Exp{};
        Exp.Name = ExpObj[QStringLiteral("name")].toString();
        Exp.Ordinal = static_cast<uint16_t>(ExpObj[QStringLiteral("ordinal")].toInt());
        Exp.Addr = ExpObj[QStringLiteral("address")].toString().toULongLong(nullptr, 0);
        Exp.Rva = 0;
        Exp.IsForwarder = false;
        Binary.Exports.append(Exp);
    }

    if (Root.contains(QStringLiteral("names"))) {
        QJsonObject NamesObj = Root[QStringLiteral("names")].toObject();
        for (auto It = NamesObj.constBegin(); It != NamesObj.constEnd(); ++It) {
            bool Ok = false;
            Address Addr = It.key().toULongLong(&Ok, 0);
            if (Ok) {
                Names.insert(Addr, It.value().toString());
            }
        }
    }

    if (Root.contains(QStringLiteral("comments"))) {
        QJsonObject CommentsObj = Root[QStringLiteral("comments")].toObject();
        for (auto It = CommentsObj.constBegin(); It != CommentsObj.constEnd(); ++It) {
            bool Ok = false;
            Address Addr = It.key().toULongLong(&Ok, 0);
            if (Ok) {
                Comments.insert(Addr, It.value().toString());
            }
        }
    }
}

}
