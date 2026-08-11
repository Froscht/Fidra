#include "DataInspector.h"
#include "../analysis/AnalysisDatabase.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QDateTime>
#include <QTimeZone>
#include <QtEndian>
#include <cstring>
#include <cmath>

namespace Fidra {

DataInspector::DataInspector(QWidget* Parent)
    : QWidget(Parent)
    , CurrentAddress(0)
    , CurrentDb(nullptr)
    , BigEndianMode(false)
    , UpdatingValues(false)
{
    MonoFont = QFont("Monospace", 9);
    MonoFont.setStyleHint(QFont::Monospace);

    auto* Layout = new QVBoxLayout(this);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(2);

    auto* ToolbarLayout = new QHBoxLayout();
    ToolbarLayout->setContentsMargins(4, 2, 4, 2);

    auto* TitleLabel = new QLabel("Data Inspector", this);
    TitleLabel->setStyleSheet("font-weight: bold;");
    ToolbarLayout->addWidget(TitleLabel);

    ToolbarLayout->addStretch();

    EndianButton = new QToolButton(this);
    EndianButton->setText("LE");
    EndianButton->setToolTip("Toggle Endianness (Little Endian / Big Endian)");
    EndianButton->setCheckable(true);
    ToolbarLayout->addWidget(EndianButton);

    Layout->addLayout(ToolbarLayout);

    Table = new QTableWidget(RowCount, 2, this);
    Table->setHorizontalHeaderLabels({"Type", "Value"});
    Table->setAlternatingRowColors(true);
    Table->setSelectionMode(QAbstractItemView::SingleSelection);
    Table->setSelectionBehavior(QAbstractItemView::SelectRows);
    Table->verticalHeader()->setVisible(false);
    Table->horizontalHeader()->setStretchLastSection(true);
    Table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    Table->setFont(MonoFont);
    Table->setEditTriggers(QAbstractItemView::DoubleClicked);

    Layout->addWidget(Table);

    PopulateTable();

    connect(EndianButton, &QToolButton::clicked, this, &DataInspector::OnToggleEndianness);
    connect(Table, &QTableWidget::cellChanged, this, &DataInspector::OnCellChanged);
}

DataInspector::~DataInspector() = default;

void DataInspector::PopulateTable() {
    UpdatingValues = true;

    struct TypeEntry {
        int Row;
        QString Name;
    };

    TypeEntry Entries[] = {
        { RowInt8,        "int8_t" },
        { RowUInt8,       "uint8_t" },
        { RowInt16LE,     "int16_t (LE)" },
        { RowUInt16LE,    "uint16_t (LE)" },
        { RowInt16BE,     "int16_t (BE)" },
        { RowUInt16BE,    "uint16_t (BE)" },
        { RowInt32LE,     "int32_t (LE)" },
        { RowUInt32LE,    "uint32_t (LE)" },
        { RowInt32BE,     "int32_t (BE)" },
        { RowUInt32BE,    "uint32_t (BE)" },
        { RowInt64LE,     "int64_t (LE)" },
        { RowUInt64LE,    "uint64_t (LE)" },
        { RowInt64BE,     "int64_t (BE)" },
        { RowUInt64BE,    "uint64_t (BE)" },
        { RowFloatLE,     "float (LE)" },
        { RowFloatBE,     "float (BE)" },
        { RowDoubleLE,    "double (LE)" },
        { RowDoubleBE,    "double (BE)" },
        { RowAscii,       "ASCII" },
        { RowUtf8,        "UTF-8" },
        { RowUtf16LE,     "UTF-16 LE" },
        { RowUtf16BE,     "UTF-16 BE" },
        { RowBinary,      "Binary" },
        { RowOctal,       "Octal" },
        { RowUnixTime32,  "Unix time_t (32)" },
        { RowUnixTime64,  "Unix time_t (64)" },
        { RowFileTime,    "Windows FILETIME" },
        { RowDosDateTime, "DOS DateTime" },
        { RowGuid,        "GUID" },
        { RowIpv4,        "IPv4" },
        { RowRgb,         "RGB" },
        { RowPointer64,   "Pointer (64)" },
    };

    for (const auto& Entry : Entries) {
        auto* TypeItem = new QTableWidgetItem(Entry.Name);
        TypeItem->setFlags(TypeItem->flags() & ~Qt::ItemIsEditable);
        TypeItem->setFont(MonoFont);
        Table->setItem(Entry.Row, 0, TypeItem);

        auto* ValueItem = new QTableWidgetItem("");
        ValueItem->setFont(MonoFont);
        Table->setItem(Entry.Row, 1, ValueItem);
    }

    UpdatingValues = false;
}

void DataInspector::InspectAddress(AnalysisDatabase* Db, Address Addr) {
    CurrentDb = Db;
    CurrentAddress = Addr;

    if (!Db) {
        RawBytes.clear();
        return;
    }

    RawBytes = Db->ReadBytes(Addr, 16);
    if (RawBytes.isEmpty()) {
        RawBytes = QByteArray(16, '\0');
    }
    while (RawBytes.size() < 16) {
        RawBytes.append('\0');
    }

    UpdateValues();
}

void DataInspector::SetEndianness(bool BigEndian) {
    BigEndianMode = BigEndian;
    EndianButton->setText(BigEndian ? "BE" : "LE");
    EndianButton->setChecked(BigEndian);
    UpdateValues();
}

bool DataInspector::IsBigEndian() const {
    return BigEndianMode;
}

void DataInspector::OnToggleEndianness() {
    BigEndianMode = !BigEndianMode;
    EndianButton->setText(BigEndianMode ? "BE" : "LE");
    UpdateValues();
}

void DataInspector::OnCellChanged(int Row, int Column) {
    if (UpdatingValues || Column != 1)
        return;

    QTableWidgetItem* Item = Table->item(Row, Column);
    if (!Item)
        return;

    QString Text = Item->text().trimmed();
    if (Text.isEmpty())
        return;

    TryParseAndWrite(Row, Text);
}

void DataInspector::UpdateValues() {
    if (RawBytes.size() < 16)
        return;

    UpdatingValues = true;

    auto SetValue = [this](int Row, const QString& Value) {
        QTableWidgetItem* Item = Table->item(Row, 1);
        if (Item)
            Item->setText(Value);
    };

    SetValue(RowInt8, FormatInt8());
    SetValue(RowUInt8, FormatUInt8());
    SetValue(RowInt16LE, FormatInt16(false));
    SetValue(RowUInt16LE, FormatUInt16(false));
    SetValue(RowInt16BE, FormatInt16(true));
    SetValue(RowUInt16BE, FormatUInt16(true));
    SetValue(RowInt32LE, FormatInt32(false));
    SetValue(RowUInt32LE, FormatUInt32(false));
    SetValue(RowInt32BE, FormatInt32(true));
    SetValue(RowUInt32BE, FormatUInt32(true));
    SetValue(RowInt64LE, FormatInt64(false));
    SetValue(RowUInt64LE, FormatUInt64(false));
    SetValue(RowInt64BE, FormatInt64(true));
    SetValue(RowUInt64BE, FormatUInt64(true));
    SetValue(RowFloatLE, FormatFloat(false));
    SetValue(RowFloatBE, FormatFloat(true));
    SetValue(RowDoubleLE, FormatDouble(false));
    SetValue(RowDoubleBE, FormatDouble(true));
    SetValue(RowAscii, FormatAscii());
    SetValue(RowUtf8, FormatUtf8());
    SetValue(RowUtf16LE, FormatUtf16(false));
    SetValue(RowUtf16BE, FormatUtf16(true));
    SetValue(RowBinary, FormatBinary());
    SetValue(RowOctal, FormatOctal());
    SetValue(RowUnixTime32, FormatUnixTime32(false));
    SetValue(RowUnixTime64, FormatUnixTime64(false));
    SetValue(RowFileTime, FormatFileTime());
    SetValue(RowDosDateTime, FormatDosDateTime());
    SetValue(RowGuid, FormatGuid());
    SetValue(RowIpv4, FormatIpv4());
    SetValue(RowRgb, FormatRgb());
    SetValue(RowPointer64, FormatPointer64(false));

    QTableWidgetItem* RgbItem = Table->item(RowRgb, 1);
    if (RgbItem) {
        const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
        QColor SwatchColor(D[0], D[1], D[2]);
        RgbItem->setBackground(SwatchColor);
        int Luma = (D[0] * 299 + D[1] * 587 + D[2] * 114) / 1000;
        RgbItem->setForeground(Luma > 128 ? QColor(0, 0, 0) : QColor(255, 255, 255));
    }

    UpdatingValues = false;
}

uint16_t DataInspector::ReadU16(const uint8_t* Data, bool BigEndian) const {
    if (BigEndian)
        return static_cast<uint16_t>((Data[0] << 8) | Data[1]);
    return static_cast<uint16_t>(Data[0] | (Data[1] << 8));
}

uint32_t DataInspector::ReadU32(const uint8_t* Data, bool BigEndian) const {
    if (BigEndian)
        return (static_cast<uint32_t>(Data[0]) << 24) |
               (static_cast<uint32_t>(Data[1]) << 16) |
               (static_cast<uint32_t>(Data[2]) << 8) |
               static_cast<uint32_t>(Data[3]);
    return static_cast<uint32_t>(Data[0]) |
           (static_cast<uint32_t>(Data[1]) << 8) |
           (static_cast<uint32_t>(Data[2]) << 16) |
           (static_cast<uint32_t>(Data[3]) << 24);
}

uint64_t DataInspector::ReadU64(const uint8_t* Data, bool BigEndian) const {
    if (BigEndian)
        return (static_cast<uint64_t>(Data[0]) << 56) |
               (static_cast<uint64_t>(Data[1]) << 48) |
               (static_cast<uint64_t>(Data[2]) << 40) |
               (static_cast<uint64_t>(Data[3]) << 32) |
               (static_cast<uint64_t>(Data[4]) << 24) |
               (static_cast<uint64_t>(Data[5]) << 16) |
               (static_cast<uint64_t>(Data[6]) << 8) |
               static_cast<uint64_t>(Data[7]);
    return static_cast<uint64_t>(Data[0]) |
           (static_cast<uint64_t>(Data[1]) << 8) |
           (static_cast<uint64_t>(Data[2]) << 16) |
           (static_cast<uint64_t>(Data[3]) << 24) |
           (static_cast<uint64_t>(Data[4]) << 32) |
           (static_cast<uint64_t>(Data[5]) << 40) |
           (static_cast<uint64_t>(Data[6]) << 48) |
           (static_cast<uint64_t>(Data[7]) << 56);
}

QString DataInspector::FormatInt8() const {
    int8_t Val;
    std::memcpy(&Val, RawBytes.constData(), 1);
    return QString::number(Val);
}

QString DataInspector::FormatUInt8() const {
    uint8_t Val = static_cast<uint8_t>(RawBytes.at(0));
    return QString::number(Val);
}

QString DataInspector::FormatInt16(bool BigEndian) const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    uint16_t Raw = ReadU16(D, BigEndian);
    int16_t Val;
    std::memcpy(&Val, &Raw, 2);
    return QString::number(Val);
}

QString DataInspector::FormatUInt16(bool BigEndian) const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    return QString::number(ReadU16(D, BigEndian));
}

QString DataInspector::FormatInt32(bool BigEndian) const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    uint32_t Raw = ReadU32(D, BigEndian);
    int32_t Val;
    std::memcpy(&Val, &Raw, 4);
    return QString::number(Val);
}

QString DataInspector::FormatUInt32(bool BigEndian) const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    return QString::number(ReadU32(D, BigEndian));
}

QString DataInspector::FormatInt64(bool BigEndian) const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    uint64_t Raw = ReadU64(D, BigEndian);
    int64_t Val;
    std::memcpy(&Val, &Raw, 8);
    return QString::number(Val);
}

QString DataInspector::FormatUInt64(bool BigEndian) const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    return QString::number(ReadU64(D, BigEndian));
}

QString DataInspector::FormatFloat(bool BigEndian) const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    uint32_t Raw = ReadU32(D, BigEndian);
    float Val;
    std::memcpy(&Val, &Raw, 4);
    if (std::isnan(Val))
        return "NaN";
    if (std::isinf(Val))
        return Val > 0 ? "+Inf" : "-Inf";
    return QString::number(static_cast<double>(Val), 'g', 9);
}

QString DataInspector::FormatDouble(bool BigEndian) const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    uint64_t Raw = ReadU64(D, BigEndian);
    double Val;
    std::memcpy(&Val, &Raw, 8);
    if (std::isnan(Val))
        return "NaN";
    if (std::isinf(Val))
        return Val > 0 ? "+Inf" : "-Inf";
    return QString::number(Val, 'g', 17);
}

QString DataInspector::FormatAscii() const {
    QString Result;
    Result.reserve(18);
    Result.append('"');
    for (int I = 0; I < 16; ++I) {
        uint8_t Ch = static_cast<uint8_t>(RawBytes.at(I));
        if (Ch == 0)
            break;
        if (Ch >= 0x20 && Ch <= 0x7E) {
            if (Ch == '"')
                Result.append("\\\"");
            else if (Ch == '\\')
                Result.append("\\\\");
            else
                Result.append(QChar(Ch));
        } else {
            switch (Ch) {
                case '\n': Result.append("\\n"); break;
                case '\r': Result.append("\\r"); break;
                case '\t': Result.append("\\t"); break;
                case '\0': Result.append("\\0"); break;
                default:
                    Result.append(QString("\\x%1").arg(Ch, 2, 16, QChar('0')));
                    break;
            }
        }
    }
    Result.append('"');
    return Result;
}

QString DataInspector::FormatUtf8() const {
    QByteArray Slice = RawBytes.left(16);
    int Len = Slice.indexOf('\0');
    if (Len >= 0)
        Slice.truncate(Len);
    QString Decoded = QString::fromUtf8(Slice);
    QString Result;
    Result.reserve(Decoded.size() + 2);
    Result.append('"');
    for (const QChar& Ch : Decoded) {
        if (Ch.isPrint())
            Result.append(Ch);
        else
            Result.append(QString("\\u%1").arg(Ch.unicode(), 4, 16, QChar('0')));
    }
    Result.append('"');
    return Result;
}

QString DataInspector::FormatUtf16(bool BigEndian) const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    QString Result;
    Result.append('"');
    for (int I = 0; I < 14; I += 2) {
        uint16_t CodeUnit = ReadU16(D + I, BigEndian);
        if (CodeUnit == 0)
            break;
        QChar Ch(CodeUnit);
        if (Ch.isPrint())
            Result.append(Ch);
        else
            Result.append(QString("\\u%1").arg(CodeUnit, 4, 16, QChar('0')));
    }
    Result.append('"');
    return Result;
}

QString DataInspector::FormatBinary() const {
    QString Result;
    int BytesToShow = std::min(8, static_cast<int>(RawBytes.size()));
    for (int I = 0; I < BytesToShow; ++I) {
        if (I > 0)
            Result.append(' ');
        uint8_t Val = static_cast<uint8_t>(RawBytes.at(I));
        for (int Bit = 7; Bit >= 0; --Bit)
            Result.append((Val & (1 << Bit)) ? '1' : '0');
    }
    return Result;
}

QString DataInspector::FormatOctal() const {
    QString Result;
    int BytesToShow = std::min(8, static_cast<int>(RawBytes.size()));
    for (int I = 0; I < BytesToShow; ++I) {
        if (I > 0)
            Result.append(' ');
        uint8_t Val = static_cast<uint8_t>(RawBytes.at(I));
        Result.append(QString("%1").arg(Val, 3, 8, QChar('0')));
    }
    return Result;
}

QString DataInspector::FormatUnixTime32(bool BigEndian) const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    uint32_t Raw = ReadU32(D, BigEndian);
    int32_t Timestamp;
    std::memcpy(&Timestamp, &Raw, 4);
    if (Timestamp <= 0)
        return "(invalid)";
    QDateTime Dt = QDateTime::fromSecsSinceEpoch(Timestamp, QTimeZone::utc());
    if (!Dt.isValid())
        return "(invalid)";
    return Dt.toString("yyyy-MM-dd HH:mm:ss UTC");
}

QString DataInspector::FormatUnixTime64(bool BigEndian) const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    uint64_t Raw = ReadU64(D, BigEndian);
    int64_t Timestamp;
    std::memcpy(&Timestamp, &Raw, 8);
    if (Timestamp <= 0 || Timestamp > 253402300799LL)
        return "(invalid)";
    QDateTime Dt = QDateTime::fromSecsSinceEpoch(Timestamp, QTimeZone::utc());
    if (!Dt.isValid())
        return "(invalid)";
    return Dt.toString("yyyy-MM-dd HH:mm:ss UTC");
}

QString DataInspector::FormatFileTime() const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    uint64_t Ft = ReadU64(D, false);
    if (Ft == 0 || Ft < 116444736000000000ULL)
        return "(invalid)";
    uint64_t UnixHundredNs = Ft - 116444736000000000ULL;
    int64_t UnixSecs = static_cast<int64_t>(UnixHundredNs / 10000000ULL);
    int64_t RemainderMs = static_cast<int64_t>((UnixHundredNs % 10000000ULL) / 10000ULL);
    QDateTime Dt = QDateTime::fromSecsSinceEpoch(UnixSecs, QTimeZone::utc());
    Dt = Dt.addMSecs(RemainderMs);
    if (!Dt.isValid() || Dt.date().year() < 1601 || Dt.date().year() > 9999)
        return "(invalid)";
    return Dt.toString("yyyy-MM-dd HH:mm:ss.zzz UTC");
}

QString DataInspector::FormatDosDateTime() const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    uint16_t Time = ReadU16(D, false);
    uint16_t Date = ReadU16(D + 2, false);

    int Second = (Time & 0x1F) * 2;
    int Minute = (Time >> 5) & 0x3F;
    int Hour = (Time >> 11) & 0x1F;
    int Day = Date & 0x1F;
    int Month = (Date >> 5) & 0x0F;
    int Year = ((Date >> 9) & 0x7F) + 1980;

    if (Month < 1 || Month > 12 || Day < 1 || Day > 31 || Hour > 23 || Minute > 59 || Second > 59)
        return "(invalid)";

    return QString("%1-%2-%3 %4:%5:%6")
        .arg(Year, 4, 10, QChar('0'))
        .arg(Month, 2, 10, QChar('0'))
        .arg(Day, 2, 10, QChar('0'))
        .arg(Hour, 2, 10, QChar('0'))
        .arg(Minute, 2, 10, QChar('0'))
        .arg(Second, 2, 10, QChar('0'));
}

QString DataInspector::FormatGuid() const {
    if (RawBytes.size() < 16)
        return "(need 16 bytes)";

    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    uint32_t Data1 = ReadU32(D, false);
    uint16_t Data2 = ReadU16(D + 4, false);
    uint16_t Data3 = ReadU16(D + 6, false);

    return QString("{%1-%2-%3-%4%5-%6%7%8%9%10%11}")
        .arg(Data1, 8, 16, QChar('0'))
        .arg(Data2, 4, 16, QChar('0'))
        .arg(Data3, 4, 16, QChar('0'))
        .arg(D[8], 2, 16, QChar('0'))
        .arg(D[9], 2, 16, QChar('0'))
        .arg(D[10], 2, 16, QChar('0'))
        .arg(D[11], 2, 16, QChar('0'))
        .arg(D[12], 2, 16, QChar('0'))
        .arg(D[13], 2, 16, QChar('0'))
        .arg(D[14], 2, 16, QChar('0'))
        .arg(D[15], 2, 16, QChar('0'))
        .toUpper();
}

QString DataInspector::FormatIpv4() const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    return QString("%1.%2.%3.%4")
        .arg(D[0]).arg(D[1]).arg(D[2]).arg(D[3]);
}

QString DataInspector::FormatRgb() const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    return QString("#%1%2%3")
        .arg(D[0], 2, 16, QChar('0'))
        .arg(D[1], 2, 16, QChar('0'))
        .arg(D[2], 2, 16, QChar('0'))
        .toUpper();
}

QString DataInspector::FormatPointer64(bool BigEndian) const {
    const uint8_t* D = reinterpret_cast<const uint8_t*>(RawBytes.constData());
    uint64_t Val = ReadU64(D, BigEndian);
    return QString("0x") + QString("%1").arg(Val, 16, 16, QChar('0')).toUpper();
}

bool DataInspector::TryParseAndWrite(int Row, const QString& Text) {
    if (!CurrentDb)
        return false;

    QByteArray NewBytes = RawBytes;
    uint8_t* D = reinterpret_cast<uint8_t*>(NewBytes.data());
    bool Ok = false;

    switch (Row) {
        case RowInt8: {
            int Val = Text.toInt(&Ok);
            if (Ok && Val >= -128 && Val <= 127) {
                int8_t V = static_cast<int8_t>(Val);
                std::memcpy(D, &V, 1);
            }
            break;
        }
        case RowUInt8: {
            uint Val = Text.toUInt(&Ok);
            if (Ok && Val <= 255) {
                D[0] = static_cast<uint8_t>(Val);
            }
            break;
        }
        case RowInt16LE:
        case RowInt16BE: {
            bool Be = (Row == RowInt16BE);
            int Val = Text.toInt(&Ok);
            if (Ok && Val >= -32768 && Val <= 32767) {
                uint16_t Raw;
                int16_t V = static_cast<int16_t>(Val);
                std::memcpy(&Raw, &V, 2);
                if (Be) {
                    D[0] = static_cast<uint8_t>(Raw >> 8);
                    D[1] = static_cast<uint8_t>(Raw & 0xFF);
                } else {
                    D[0] = static_cast<uint8_t>(Raw & 0xFF);
                    D[1] = static_cast<uint8_t>(Raw >> 8);
                }
            }
            break;
        }
        case RowUInt16LE:
        case RowUInt16BE: {
            bool Be = (Row == RowUInt16BE);
            uint Val = Text.toUInt(&Ok);
            if (Ok && Val <= 65535) {
                uint16_t Raw = static_cast<uint16_t>(Val);
                if (Be) {
                    D[0] = static_cast<uint8_t>(Raw >> 8);
                    D[1] = static_cast<uint8_t>(Raw & 0xFF);
                } else {
                    D[0] = static_cast<uint8_t>(Raw & 0xFF);
                    D[1] = static_cast<uint8_t>(Raw >> 8);
                }
            }
            break;
        }
        case RowInt32LE:
        case RowInt32BE: {
            bool Be = (Row == RowInt32BE);
            int Val = Text.toInt(&Ok);
            if (Ok) {
                uint32_t Raw;
                std::memcpy(&Raw, &Val, 4);
                if (Be) {
                    D[0] = static_cast<uint8_t>((Raw >> 24) & 0xFF);
                    D[1] = static_cast<uint8_t>((Raw >> 16) & 0xFF);
                    D[2] = static_cast<uint8_t>((Raw >> 8) & 0xFF);
                    D[3] = static_cast<uint8_t>(Raw & 0xFF);
                } else {
                    D[0] = static_cast<uint8_t>(Raw & 0xFF);
                    D[1] = static_cast<uint8_t>((Raw >> 8) & 0xFF);
                    D[2] = static_cast<uint8_t>((Raw >> 16) & 0xFF);
                    D[3] = static_cast<uint8_t>((Raw >> 24) & 0xFF);
                }
            }
            break;
        }
        case RowUInt32LE:
        case RowUInt32BE: {
            bool Be = (Row == RowUInt32BE);
            quint64 Val = Text.toULongLong(&Ok);
            if (Ok && Val <= 0xFFFFFFFFULL) {
                uint32_t Raw = static_cast<uint32_t>(Val);
                if (Be) {
                    D[0] = static_cast<uint8_t>((Raw >> 24) & 0xFF);
                    D[1] = static_cast<uint8_t>((Raw >> 16) & 0xFF);
                    D[2] = static_cast<uint8_t>((Raw >> 8) & 0xFF);
                    D[3] = static_cast<uint8_t>(Raw & 0xFF);
                } else {
                    D[0] = static_cast<uint8_t>(Raw & 0xFF);
                    D[1] = static_cast<uint8_t>((Raw >> 8) & 0xFF);
                    D[2] = static_cast<uint8_t>((Raw >> 16) & 0xFF);
                    D[3] = static_cast<uint8_t>((Raw >> 24) & 0xFF);
                }
            }
            break;
        }
        case RowInt64LE:
        case RowInt64BE: {
            bool Be = (Row == RowInt64BE);
            qint64 Val = Text.toLongLong(&Ok);
            if (Ok) {
                uint64_t Raw;
                std::memcpy(&Raw, &Val, 8);
                for (int I = 0; I < 8; ++I) {
                    int Shift = Be ? ((7 - I) * 8) : (I * 8);
                    D[I] = static_cast<uint8_t>((Raw >> Shift) & 0xFF);
                }
            }
            break;
        }
        case RowUInt64LE:
        case RowUInt64BE: {
            bool Be = (Row == RowUInt64BE);
            quint64 Val = Text.toULongLong(&Ok);
            if (Ok) {
                for (int I = 0; I < 8; ++I) {
                    int Shift = Be ? ((7 - I) * 8) : (I * 8);
                    D[I] = static_cast<uint8_t>((Val >> Shift) & 0xFF);
                }
            }
            break;
        }
        case RowFloatLE:
        case RowFloatBE: {
            bool Be = (Row == RowFloatBE);
            float Val = Text.toFloat(&Ok);
            if (Ok) {
                uint32_t Raw;
                std::memcpy(&Raw, &Val, 4);
                if (Be) {
                    D[0] = static_cast<uint8_t>((Raw >> 24) & 0xFF);
                    D[1] = static_cast<uint8_t>((Raw >> 16) & 0xFF);
                    D[2] = static_cast<uint8_t>((Raw >> 8) & 0xFF);
                    D[3] = static_cast<uint8_t>(Raw & 0xFF);
                } else {
                    D[0] = static_cast<uint8_t>(Raw & 0xFF);
                    D[1] = static_cast<uint8_t>((Raw >> 8) & 0xFF);
                    D[2] = static_cast<uint8_t>((Raw >> 16) & 0xFF);
                    D[3] = static_cast<uint8_t>((Raw >> 24) & 0xFF);
                }
            }
            break;
        }
        case RowDoubleLE:
        case RowDoubleBE: {
            bool Be = (Row == RowDoubleBE);
            double Val = Text.toDouble(&Ok);
            if (Ok) {
                uint64_t Raw;
                std::memcpy(&Raw, &Val, 8);
                for (int I = 0; I < 8; ++I) {
                    int Shift = Be ? ((7 - I) * 8) : (I * 8);
                    D[I] = static_cast<uint8_t>((Raw >> Shift) & 0xFF);
                }
            }
            break;
        }
        default:
            return false;
    }

    if (Ok && NewBytes != RawBytes) {
        RawBytes = NewBytes;
        emit BytesModified(CurrentAddress, NewBytes);
        UpdateValues();
    }

    return Ok;
}

}
