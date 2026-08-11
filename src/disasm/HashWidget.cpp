#include "HashWidget.h"
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QClipboard>
#include <QApplication>
#include <QCryptographicHash>
#include <QPainter>
#include <QPaintEvent>
#include <cstring>
#include <cmath>

namespace Fidra {

ByteHistogramWidget::ByteHistogramWidget(QWidget* Parent)
    : QWidget(Parent)
    , MaxFrequency(0)
    , TotalBytes(0)
{
    std::memset(Frequencies, 0, sizeof(Frequencies));
    setMinimumHeight(80);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    setToolTip("Byte frequency distribution (0x00-0xFF)");
}

ByteHistogramWidget::~ByteHistogramWidget() = default;

void ByteHistogramWidget::SetData(const QByteArray& Data) {
    std::memset(Frequencies, 0, sizeof(Frequencies));
    MaxFrequency = 0;
    TotalBytes = Data.size();

    for (int I = 0; I < Data.size(); ++I) {
        uint8_t Byte = static_cast<uint8_t>(Data.at(I));
        Frequencies[Byte]++;
    }

    for (int I = 0; I < 256; ++I) {
        if (Frequencies[I] > MaxFrequency)
            MaxFrequency = Frequencies[I];
    }

    update();
}

void ByteHistogramWidget::Clear() {
    std::memset(Frequencies, 0, sizeof(Frequencies));
    MaxFrequency = 0;
    TotalBytes = 0;
    update();
}

QSize ByteHistogramWidget::minimumSizeHint() const {
    return QSize(256, 80);
}

void ByteHistogramWidget::paintEvent(QPaintEvent* Event) {
    Q_UNUSED(Event);
    QPainter Painter(this);
    Painter.setRenderHint(QPainter::Antialiasing, false);

    QRect Area = rect();
    Painter.fillRect(Area, palette().color(QPalette::Base));

    if (MaxFrequency == 0 || TotalBytes == 0) {
        Painter.setPen(palette().color(QPalette::PlaceholderText));
        Painter.drawText(Area, Qt::AlignCenter, "No data");
        return;
    }

    double BarWidth = static_cast<double>(Area.width()) / 256.0;
    int MaxBarHeight = Area.height() - 4;

    for (int I = 0; I < 256; ++I) {
        if (Frequencies[I] == 0)
            continue;

        double Ratio = static_cast<double>(Frequencies[I]) / static_cast<double>(MaxFrequency);
        int BarHeight = static_cast<int>(Ratio * MaxBarHeight);
        if (BarHeight < 1)
            BarHeight = 1;

        int X = static_cast<int>(I * BarWidth);
        int W = std::max(static_cast<int>(BarWidth), 1);

        double Hue;
        if (I == 0x00)
            Hue = 0.0;
        else if (I >= 0x20 && I <= 0x7E)
            Hue = 120.0;
        else if (I == 0xFF)
            Hue = 240.0;
        else
            Hue = 30.0;

        QColor BarColor = QColor::fromHsvF(Hue / 360.0, 0.7, 0.8);
        Painter.fillRect(X, Area.height() - 2 - BarHeight, W, BarHeight, BarColor);
    }

    Painter.setPen(palette().color(QPalette::Mid));
    Painter.drawRect(Area.adjusted(0, 0, -1, -1));
}

HashWidget::HashWidget(QWidget* Parent)
    : QWidget(Parent)
    , CurrentDb(nullptr)
    , RangeStart(0)
    , RangeEnd(0)
{
    MonoFont = QFont("Monospace", 9);
    MonoFont.setStyleHint(QFont::Monospace);

    auto* Layout = new QVBoxLayout(this);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(2);

    auto* ToolbarLayout = new QHBoxLayout();
    ToolbarLayout->setContentsMargins(4, 2, 4, 2);

    auto* TitleLabel = new QLabel("Hash / Checksum", this);
    TitleLabel->setStyleSheet("font-weight: bold;");
    ToolbarLayout->addWidget(TitleLabel);

    ToolbarLayout->addStretch();

    HashSelectionButton = new QToolButton(this);
    HashSelectionButton->setText("Hash Selection");
    HashSelectionButton->setToolTip("Hash the currently selected byte range");
    ToolbarLayout->addWidget(HashSelectionButton);

    SegmentCombo = new QComboBox(this);
    SegmentCombo->setMinimumWidth(120);
    SegmentCombo->setToolTip("Select segment to hash");
    ToolbarLayout->addWidget(SegmentCombo);

    HashSegmentButton = new QToolButton(this);
    HashSegmentButton->setText("Hash Segment");
    HashSegmentButton->setToolTip("Hash the selected segment");
    ToolbarLayout->addWidget(HashSegmentButton);

    Layout->addLayout(ToolbarLayout);

    Table = new QTableWidget(RowCount, 3, this);
    Table->setHorizontalHeaderLabels({"Algorithm", "Value", ""});
    Table->setAlternatingRowColors(true);
    Table->setSelectionMode(QAbstractItemView::SingleSelection);
    Table->setSelectionBehavior(QAbstractItemView::SelectRows);
    Table->verticalHeader()->setVisible(false);
    Table->horizontalHeader()->setStretchLastSection(false);
    Table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    Table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    Table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    Table->setFont(MonoFont);
    Table->setEditTriggers(QAbstractItemView::NoEditTriggers);

    Layout->addWidget(Table);

    auto* BottomLayout = new QHBoxLayout();
    BottomLayout->setContentsMargins(4, 2, 4, 2);

    CopyAllButton = new QPushButton("Copy All", this);
    CopyAllButton->setToolTip("Copy all hash values to clipboard");
    BottomLayout->addWidget(CopyAllButton);
    BottomLayout->addStretch();

    Layout->addLayout(BottomLayout);

    Histogram = new ByteHistogramWidget(this);
    Layout->addWidget(Histogram);

    PopulateTable();

    connect(HashSelectionButton, &QToolButton::clicked, this, &HashWidget::OnHashSelection);
    connect(HashSegmentButton, &QToolButton::clicked, this, &HashWidget::OnHashSegment);
    connect(CopyAllButton, &QPushButton::clicked, this, &HashWidget::OnCopyAll);
}

HashWidget::~HashWidget() = default;

void HashWidget::PopulateTable() {
    struct AlgoEntry {
        int Row;
        QString Name;
    };

    AlgoEntry Entries[] = {
        { RowCrc32,    "CRC32" },
        { RowAdler32,  "Adler-32" },
        { RowMd5,      "MD5" },
        { RowSha1,     "SHA-1" },
        { RowSha256,   "SHA-256" },
        { RowSha512,   "SHA-512" },
        { RowXxHash32, "xxHash32" },
        { RowXxHash64, "xxHash64" },
        { RowSize,     "Size" },
        { RowEntropy,  "Entropy" },
    };

    for (const auto& Entry : Entries) {
        auto* AlgoItem = new QTableWidgetItem(Entry.Name);
        AlgoItem->setFlags(AlgoItem->flags() & ~Qt::ItemIsEditable);
        AlgoItem->setFont(MonoFont);
        Table->setItem(Entry.Row, 0, AlgoItem);

        auto* ValueItem = new QTableWidgetItem("");
        ValueItem->setFlags(ValueItem->flags() & ~Qt::ItemIsEditable);
        ValueItem->setFont(MonoFont);
        Table->setItem(Entry.Row, 1, ValueItem);

        auto* CopyButton = new QPushButton("Copy", Table);
        CopyButton->setFixedWidth(50);
        int RowIdx = Entry.Row;
        connect(CopyButton, &QPushButton::clicked, this, [this, RowIdx]() {
            OnCopyValue(RowIdx);
        });
        Table->setCellWidget(Entry.Row, 2, CopyButton);
    }
}

void HashWidget::SetDatabase(AnalysisDatabase* Db) {
    CurrentDb = Db;
    PopulateSegmentDropdown();
}

void HashWidget::PopulateSegmentDropdown() {
    SegmentCombo->clear();
    if (!CurrentDb)
        return;

    BinaryInfo Info = CurrentDb->GetBinaryInfo();
    for (const Segment& Seg : Info.Segments) {
        SegmentCombo->addItem(Seg.Name, QVariant::fromValue(static_cast<quint64>(Seg.VirtualAddress)));
    }
}

void HashWidget::HashRange(AnalysisDatabase* Db, Address Start, Address End) {
    CurrentDb = Db;
    RangeStart = Start;
    RangeEnd = End;

    if (!Db || Start >= End) {
        for (int I = 0; I < RowCount; ++I) {
            QTableWidgetItem* Item = Table->item(I, 1);
            if (Item)
                Item->setText("");
        }
        Histogram->Clear();
        return;
    }

    size_t Size = static_cast<size_t>(End - Start);
    QByteArray Data = Db->ReadBytes(Start, Size);
    UpdateHashes(Data);
}

void HashWidget::HashSegment(AnalysisDatabase* Db, const QString& SegmentName) {
    CurrentDb = Db;
    if (!Db)
        return;

    BinaryInfo Info = Db->GetBinaryInfo();
    for (const Segment& Seg : Info.Segments) {
        if (Seg.Name == SegmentName) {
            RangeStart = Seg.VirtualAddress;
            RangeEnd = Seg.VirtualAddress + Seg.VirtualSize;
            UpdateHashes(Seg.Data);
            return;
        }
    }
}

void HashWidget::UpdateHashes(const QByteArray& Data) {
    auto SetValue = [this](int Row, const QString& Value) {
        QTableWidgetItem* Item = Table->item(Row, 1);
        if (Item)
            Item->setText(Value);
    };

    SetValue(RowCrc32, QString("%1").arg(CalculateCrc32(Data), 8, 16, QChar('0')).toUpper());
    SetValue(RowAdler32, QString("%1").arg(CalculateAdler32(Data), 8, 16, QChar('0')).toUpper());

    QByteArray Md5Hash = QCryptographicHash::hash(Data, QCryptographicHash::Md5);
    SetValue(RowMd5, FormatHash(Md5Hash));

    QByteArray Sha1Hash = QCryptographicHash::hash(Data, QCryptographicHash::Sha1);
    SetValue(RowSha1, FormatHash(Sha1Hash));

    QByteArray Sha256Hash = QCryptographicHash::hash(Data, QCryptographicHash::Sha256);
    SetValue(RowSha256, FormatHash(Sha256Hash));

    QByteArray Sha512Hash = QCryptographicHash::hash(Data, QCryptographicHash::Sha512);
    SetValue(RowSha512, FormatHash(Sha512Hash));

    SetValue(RowXxHash32, QString("%1").arg(CalculateXxHash32(Data), 8, 16, QChar('0')).toUpper());
    SetValue(RowXxHash64, QString("%1").arg(CalculateXxHash64(Data), 16, 16, QChar('0')).toUpper());

    SetValue(RowSize, FormatSize(Data.size()));

    double Ent = CalculateEntropy(Data);
    SetValue(RowEntropy, QString::number(Ent, 'f', 6));

    QTableWidgetItem* EntropyItem = Table->item(RowEntropy, 1);
    if (EntropyItem) {
        QColor EntropyColor;
        if (Ent < 1.0)
            EntropyColor = QColor(0x40, 0x40, 0xFF);
        else if (Ent < 4.0)
            EntropyColor = QColor(0x00, 0xA0, 0x00);
        else if (Ent < 6.0)
            EntropyColor = QColor(0xC0, 0xA0, 0x00);
        else if (Ent < 7.5)
            EntropyColor = QColor(0xFF, 0x80, 0x00);
        else
            EntropyColor = QColor(0xFF, 0x20, 0x20);
        EntropyItem->setForeground(EntropyColor);
    }

    Histogram->SetData(Data);
}

void HashWidget::OnCopyValue(int Row) {
    QTableWidgetItem* Item = Table->item(Row, 1);
    if (!Item)
        return;

    QClipboard* Clipboard = QApplication::clipboard();
    Clipboard->setText(Item->text());
}

void HashWidget::OnCopyAll() {
    QString AllText;
    for (int I = 0; I < RowCount; ++I) {
        QTableWidgetItem* AlgoItem = Table->item(I, 0);
        QTableWidgetItem* ValueItem = Table->item(I, 1);
        if (AlgoItem && ValueItem) {
            AllText += QString("%1: %2\n").arg(AlgoItem->text(), -12).arg(ValueItem->text());
        }
    }
    AllText += QString("\nRange: 0x%1 - 0x%2\n")
        .arg(RangeStart, 16, 16, QChar('0'))
        .arg(RangeEnd, 16, 16, QChar('0'));

    QClipboard* Clipboard = QApplication::clipboard();
    Clipboard->setText(AllText);
}

void HashWidget::OnHashSelection() {
    if (CurrentDb && RangeStart < RangeEnd) {
        HashRange(CurrentDb, RangeStart, RangeEnd);
    }
}

void HashWidget::OnHashSegment() {
    if (!CurrentDb)
        return;

    QString SegName = SegmentCombo->currentText();
    if (!SegName.isEmpty())
        HashSegment(CurrentDb, SegName);
}

uint32_t HashWidget::CalculateCrc32(const QByteArray& Data) const {
    static uint32_t CrcTable[256];
    static bool TableBuilt = false;

    if (!TableBuilt) {
        for (uint32_t I = 0; I < 256; ++I) {
            uint32_t Crc = I;
            for (int J = 0; J < 8; ++J) {
                if (Crc & 1)
                    Crc = (Crc >> 1) ^ 0xEDB88320;
                else
                    Crc >>= 1;
            }
            CrcTable[I] = Crc;
        }
        TableBuilt = true;
    }

    uint32_t Crc = 0xFFFFFFFF;
    const uint8_t* Bytes = reinterpret_cast<const uint8_t*>(Data.constData());
    for (int I = 0; I < Data.size(); ++I) {
        Crc = CrcTable[(Crc ^ Bytes[I]) & 0xFF] ^ (Crc >> 8);
    }
    return Crc ^ 0xFFFFFFFF;
}

uint32_t HashWidget::CalculateAdler32(const QByteArray& Data) const {
    uint32_t A = 1;
    uint32_t B = 0;
    const uint32_t Mod = 65521;
    const uint8_t* Bytes = reinterpret_cast<const uint8_t*>(Data.constData());

    for (int I = 0; I < Data.size(); ++I) {
        A = (A + Bytes[I]) % Mod;
        B = (B + A) % Mod;
    }

    return (B << 16) | A;
}

static uint32_t XxhRotl32(uint32_t Val, int Bits) {
    return (Val << Bits) | (Val >> (32 - Bits));
}

static uint64_t XxhRotl64(uint64_t Val, int Bits) {
    return (Val << Bits) | (Val >> (64 - Bits));
}

uint32_t HashWidget::CalculateXxHash32(const QByteArray& Data, uint32_t Seed) const {
    const uint32_t Prime1 = 0x9E3779B1U;
    const uint32_t Prime2 = 0x85EBCA77U;
    const uint32_t Prime3 = 0xC2B2AE3DU;
    const uint32_t Prime4 = 0x27D4EB2FU;
    const uint32_t Prime5 = 0x165667B1U;

    const uint8_t* Input = reinterpret_cast<const uint8_t*>(Data.constData());
    int Len = Data.size();
    const uint8_t* End = Input + Len;
    uint32_t H32;

    if (Len >= 16) {
        uint32_t V1 = Seed + Prime1 + Prime2;
        uint32_t V2 = Seed + Prime2;
        uint32_t V3 = Seed;
        uint32_t V4 = Seed - Prime1;

        const uint8_t* Limit = End - 16;
        do {
            uint32_t K;
            std::memcpy(&K, Input, 4); V1 += K * Prime2; V1 = XxhRotl32(V1, 13); V1 *= Prime1; Input += 4;
            std::memcpy(&K, Input, 4); V2 += K * Prime2; V2 = XxhRotl32(V2, 13); V2 *= Prime1; Input += 4;
            std::memcpy(&K, Input, 4); V3 += K * Prime2; V3 = XxhRotl32(V3, 13); V3 *= Prime1; Input += 4;
            std::memcpy(&K, Input, 4); V4 += K * Prime2; V4 = XxhRotl32(V4, 13); V4 *= Prime1; Input += 4;
        } while (Input <= Limit);

        H32 = XxhRotl32(V1, 1) + XxhRotl32(V2, 7) + XxhRotl32(V3, 12) + XxhRotl32(V4, 18);
    } else {
        H32 = Seed + Prime5;
    }

    H32 += static_cast<uint32_t>(Len);

    while (Input + 4 <= End) {
        uint32_t K;
        std::memcpy(&K, Input, 4);
        H32 += K * Prime3;
        H32 = XxhRotl32(H32, 17) * Prime4;
        Input += 4;
    }

    while (Input < End) {
        H32 += (*Input) * Prime5;
        H32 = XxhRotl32(H32, 11) * Prime1;
        Input++;
    }

    H32 ^= H32 >> 15;
    H32 *= Prime2;
    H32 ^= H32 >> 13;
    H32 *= Prime3;
    H32 ^= H32 >> 16;

    return H32;
}

uint64_t HashWidget::CalculateXxHash64(const QByteArray& Data, uint64_t Seed) const {
    const uint64_t Prime1 = 0x9E3779B185EBCA87ULL;
    const uint64_t Prime2 = 0xC2B2AE3D27D4EB4FULL;
    const uint64_t Prime3 = 0x165667B19E3779F9ULL;
    const uint64_t Prime4 = 0x85EBCA77C2B2AE63ULL;
    const uint64_t Prime5 = 0x27D4EB2F165667C5ULL;

    const uint8_t* Input = reinterpret_cast<const uint8_t*>(Data.constData());
    int Len = Data.size();
    const uint8_t* End = Input + Len;
    uint64_t H64;

    if (Len >= 32) {
        uint64_t V1 = Seed + Prime1 + Prime2;
        uint64_t V2 = Seed + Prime2;
        uint64_t V3 = Seed;
        uint64_t V4 = Seed - Prime1;

        const uint8_t* Limit = End - 32;
        do {
            uint64_t K;
            std::memcpy(&K, Input, 8); V1 += K * Prime2; V1 = XxhRotl64(V1, 31); V1 *= Prime1; Input += 8;
            std::memcpy(&K, Input, 8); V2 += K * Prime2; V2 = XxhRotl64(V2, 31); V2 *= Prime1; Input += 8;
            std::memcpy(&K, Input, 8); V3 += K * Prime2; V3 = XxhRotl64(V3, 31); V3 *= Prime1; Input += 8;
            std::memcpy(&K, Input, 8); V4 += K * Prime2; V4 = XxhRotl64(V4, 31); V4 *= Prime1; Input += 8;
        } while (Input <= Limit);

        H64 = XxhRotl64(V1, 1) + XxhRotl64(V2, 7) + XxhRotl64(V3, 12) + XxhRotl64(V4, 18);

        auto MergeAccum = [&](uint64_t Acc, uint64_t V) -> uint64_t {
            V *= Prime2;
            V = XxhRotl64(V, 31);
            V *= Prime1;
            Acc ^= V;
            Acc = Acc * Prime1 + Prime4;
            return Acc;
        };

        H64 = MergeAccum(H64, V1);
        H64 = MergeAccum(H64, V2);
        H64 = MergeAccum(H64, V3);
        H64 = MergeAccum(H64, V4);
    } else {
        H64 = Seed + Prime5;
    }

    H64 += static_cast<uint64_t>(Len);

    while (Input + 8 <= End) {
        uint64_t K;
        std::memcpy(&K, Input, 8);
        K *= Prime2;
        K = XxhRotl64(K, 31);
        K *= Prime1;
        H64 ^= K;
        H64 = XxhRotl64(H64, 27) * Prime1 + Prime4;
        Input += 8;
    }

    while (Input + 4 <= End) {
        uint32_t K;
        std::memcpy(&K, Input, 4);
        H64 ^= static_cast<uint64_t>(K) * Prime1;
        H64 = XxhRotl64(H64, 23) * Prime2 + Prime3;
        Input += 4;
    }

    while (Input < End) {
        H64 ^= (*Input) * Prime5;
        H64 = XxhRotl64(H64, 11) * Prime1;
        Input++;
    }

    H64 ^= H64 >> 33;
    H64 *= Prime2;
    H64 ^= H64 >> 29;
    H64 *= Prime3;
    H64 ^= H64 >> 32;

    return H64;
}

double HashWidget::CalculateEntropy(const QByteArray& Data) const {
    if (Data.isEmpty())
        return 0.0;

    uint64_t Freq[256];
    std::memset(Freq, 0, sizeof(Freq));

    const uint8_t* Bytes = reinterpret_cast<const uint8_t*>(Data.constData());
    for (int I = 0; I < Data.size(); ++I) {
        Freq[Bytes[I]]++;
    }

    double Entropy = 0.0;
    double Total = static_cast<double>(Data.size());

    for (int I = 0; I < 256; ++I) {
        if (Freq[I] == 0)
            continue;
        double P = static_cast<double>(Freq[I]) / Total;
        Entropy -= P * std::log2(P);
    }

    return Entropy;
}

QString HashWidget::FormatHash(const QByteArray& Hash) const {
    return Hash.toHex().toLower();
}

QString HashWidget::FormatSize(qint64 Size) const {
    if (Size < 1024)
        return QString("%1 bytes").arg(Size);
    if (Size < 1024 * 1024)
        return QString("%1 bytes (%2 KB)").arg(Size).arg(static_cast<double>(Size) / 1024.0, 0, 'f', 2);
    if (Size < 1024LL * 1024 * 1024)
        return QString("%1 bytes (%2 MB)").arg(Size).arg(static_cast<double>(Size) / (1024.0 * 1024.0), 0, 'f', 2);
    return QString("%1 bytes (%2 GB)").arg(Size).arg(static_cast<double>(Size) / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
}

}
