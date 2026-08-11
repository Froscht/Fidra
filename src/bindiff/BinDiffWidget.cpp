#include "BinDiffWidget.h"

#include <QPainter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFileDialog>
#include <QFile>
#include <QWheelEvent>
#include <QFontMetrics>
#include <QApplication>
#include <QStyle>

namespace Fidra {

HexDiffView::HexDiffView(QWidget* Parent)
    : QWidget(Parent)
    , LeftSide(true)
    , BytesPerRow(16)
    , RowHeight(0)
    , HeaderWidth(0)
    , CellWidth(0)
    , AsciiCellWidth(0) {

    QFont MonoFont(QStringLiteral("Monospace"), 10);
    MonoFont.setStyleHint(QFont::Monospace);
    setFont(MonoFont);

    QFontMetrics Fm(MonoFont);
    RowHeight = Fm.height() + 4;
    HeaderWidth = Fm.horizontalAdvance(QStringLiteral("00000000: "));
    CellWidth = Fm.horizontalAdvance(QStringLiteral("00 "));
    AsciiCellWidth = Fm.horizontalAdvance(QStringLiteral("X"));

    VerticalScroll = new QScrollBar(Qt::Vertical, this);
    connect(VerticalScroll, &QScrollBar::valueChanged, this, [this](int Value) {
        update();
        emit ScrollChanged(Value);
    });

    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setMinimumWidth(HeaderWidth + CellWidth * 16 + CellWidth + AsciiCellWidth * 16 + 30);
}

void HexDiffView::SetData(const QByteArray& FileData, const QVector<DiffRegion>& Regions, bool IsLeftSide) {
    Data = FileData;
    DiffRegions = Regions;
    LeftSide = IsLeftSide;
    UpdateScrollBar();
    VerticalScroll->setValue(0);
    update();
}

void HexDiffView::SetScrollValue(int Value) {
    VerticalScroll->setValue(Value);
}

int HexDiffView::TotalRows() const {
    if (Data.isEmpty())
        return 0;
    return (Data.size() + BytesPerRow - 1) / BytesPerRow;
}

int HexDiffView::VisibleRows() const {
    if (RowHeight <= 0)
        return 0;
    return height() / RowHeight;
}

void HexDiffView::ScrollToOffset(uint64_t Offset) {
    int Row = static_cast<int>(Offset / BytesPerRow);
    VerticalScroll->setValue(Row);
}

int HexDiffView::CurrentScroll() const {
    return VerticalScroll->value();
}

QColor HexDiffView::ColorForOffset(uint64_t Offset) const {
    int Lo = 0;
    int Hi = DiffRegions.size() - 1;

    while (Lo <= Hi) {
        int Mid = (Lo + Hi) / 2;
        const DiffRegion& Region = DiffRegions[Mid];

        if (Offset < Region.Offset) {
            Hi = Mid - 1;
        } else if (Offset >= Region.Offset + Region.Size) {
            Lo = Mid + 1;
        } else {
            switch (Region.Type) {
                case DiffRegionType::Match:
                    return QColor(40, 80, 40);
                case DiffRegionType::Modified:
                    return QColor(120, 40, 40);
                case DiffRegionType::Added:
                    return QColor(120, 120, 40);
                case DiffRegionType::Removed:
                    return QColor(120, 120, 40);
            }
        }
    }

    return QColor(40, 40, 40);
}

void HexDiffView::UpdateScrollBar() {
    int Total = TotalRows();
    int Visible = VisibleRows();
    int Max = qMax(0, Total - Visible);
    VerticalScroll->setRange(0, Max);
    VerticalScroll->setPageStep(Visible);
    VerticalScroll->setSingleStep(1);
}

void HexDiffView::paintEvent(QPaintEvent*) {
    QPainter Painter(this);
    Painter.setRenderHint(QPainter::TextAntialiasing);
    Painter.fillRect(rect(), QColor(30, 30, 30));

    if (Data.isEmpty())
        return;

    QFont MonoFont = font();
    Painter.setFont(MonoFont);
    QFontMetrics Fm(MonoFont);
    int Baseline = Fm.ascent() + 2;

    int ScrollbarWidth = VerticalScroll->width();
    int AvailableWidth = width() - ScrollbarWidth;

    int StartRow = VerticalScroll->value();
    int RowCount = VisibleRows() + 1;

    int HexStartX = HeaderWidth;
    int GapWidth = CellWidth / 2;
    int AsciiStartX = HexStartX + CellWidth * 16 + GapWidth + CellWidth / 2;

    for (int Row = 0; Row < RowCount; ++Row) {
        int DataRow = StartRow + Row;
        uint64_t RowOffset = static_cast<uint64_t>(DataRow) * BytesPerRow;

        if (RowOffset >= static_cast<uint64_t>(Data.size()))
            break;

        int Y = Row * RowHeight;

        Painter.setPen(QColor(120, 120, 120));
        QString OffsetStr = QStringLiteral("%1: ").arg(RowOffset, 8, 16, QLatin1Char('0'));
        Painter.drawText(2, Y + Baseline, OffsetStr);

        for (int Col = 0; Col < BytesPerRow; ++Col) {
            uint64_t ByteOffset = RowOffset + Col;
            if (ByteOffset >= static_cast<uint64_t>(Data.size()))
                break;

            int ExtraGap = (Col >= 8) ? GapWidth : 0;
            int HexX = HexStartX + Col * CellWidth + ExtraGap;

            QColor BgColor = ColorForOffset(ByteOffset);
            Painter.fillRect(HexX, Y, CellWidth - 1, RowHeight, BgColor);

            uint8_t ByteVal = static_cast<uint8_t>(Data[static_cast<int>(ByteOffset)]);
            QString HexStr = QStringLiteral("%1").arg(ByteVal, 2, 16, QLatin1Char('0')).toUpper();
            Painter.setPen(QColor(220, 220, 220));
            Painter.drawText(HexX + 1, Y + Baseline, HexStr);

            int AsciiX = AsciiStartX + Col * AsciiCellWidth;
            Painter.fillRect(AsciiX, Y, AsciiCellWidth, RowHeight, BgColor);

            QChar AsciiChar = (ByteVal >= 0x20 && ByteVal <= 0x7E) ? QChar(ByteVal) : QChar('.');
            Painter.setPen(QColor(180, 180, 180));
            Painter.drawText(AsciiX, Y + Baseline, QString(AsciiChar));
        }
    }
}

void HexDiffView::resizeEvent(QResizeEvent* Event) {
    int ScrollWidth = VerticalScroll->sizeHint().width();
    VerticalScroll->setGeometry(width() - ScrollWidth, 0, ScrollWidth, height());
    UpdateScrollBar();
    QWidget::resizeEvent(Event);
}

void HexDiffView::wheelEvent(QWheelEvent* Event) {
    int Delta = Event->angleDelta().y() / 120;
    VerticalScroll->setValue(VerticalScroll->value() - Delta * 3);
    Event->accept();
}

BinDiffWidget::BinDiffWidget(QWidget* Parent)
    : QWidget(Parent)
    , SyncingScroll(false)
    , Db1Ref(nullptr)
    , Db2Ref(nullptr) {

    Engine = new BinDiffEngine(this);

    QVBoxLayout* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(4, 4, 4, 4);
    MainLayout->setSpacing(4);

    QHBoxLayout* FileBar = new QHBoxLayout();
    FileBar->setSpacing(4);

    File1Path = new QLineEdit(this);
    File1Path->setPlaceholderText(QStringLiteral("File 1..."));
    FileBar->addWidget(File1Path, 1);

    BrowseBtn1 = new QPushButton(QStringLiteral("Browse"), this);
    BrowseBtn1->setMaximumWidth(70);
    FileBar->addWidget(BrowseBtn1);

    File2Path = new QLineEdit(this);
    File2Path->setPlaceholderText(QStringLiteral("File 2..."));
    FileBar->addWidget(File2Path, 1);

    BrowseBtn2 = new QPushButton(QStringLiteral("Browse"), this);
    BrowseBtn2->setMaximumWidth(70);
    FileBar->addWidget(BrowseBtn2);

    CompareBtn = new QPushButton(QStringLiteral("Compare"), this);
    CompareBtn->setMaximumWidth(80);
    FileBar->addWidget(CompareBtn);

    MainLayout->addLayout(FileBar);

    MainSplitter = new QSplitter(Qt::Vertical, this);

    QWidget* HexContainer = new QWidget(this);
    QHBoxLayout* HexLayout = new QHBoxLayout(HexContainer);
    HexLayout->setContentsMargins(0, 0, 0, 0);
    HexLayout->setSpacing(2);

    LeftView = new HexDiffView(this);
    RightView = new HexDiffView(this);
    HexLayout->addWidget(LeftView);
    HexLayout->addWidget(RightView);

    MainSplitter->addWidget(HexContainer);

    FunctionTable = new QTableWidget(0, 5, this);
    FunctionTable->setHorizontalHeaderLabels({
        QStringLiteral("Name (File 1)"),
        QStringLiteral("Name (File 2)"),
        QStringLiteral("Address 1"),
        QStringLiteral("Address 2"),
        QStringLiteral("Similarity")
    });
    FunctionTable->horizontalHeader()->setStretchLastSection(true);
    FunctionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    FunctionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    FunctionTable->setSortingEnabled(true);
    FunctionTable->setAlternatingRowColors(true);
    MainSplitter->addWidget(FunctionTable);

    MainSplitter->setStretchFactor(0, 3);
    MainSplitter->setStretchFactor(1, 1);

    MainLayout->addWidget(MainSplitter, 1);

    QHBoxLayout* BottomBar = new QHBoxLayout();
    BottomBar->setSpacing(4);

    PrevDiffBtn = new QPushButton(QStringLiteral("< Prev Diff"), this);
    PrevDiffBtn->setMaximumWidth(100);
    PrevDiffBtn->setEnabled(false);
    BottomBar->addWidget(PrevDiffBtn);

    NextDiffBtn = new QPushButton(QStringLiteral("Next Diff >"), this);
    NextDiffBtn->setMaximumWidth(100);
    NextDiffBtn->setEnabled(false);
    BottomBar->addWidget(NextDiffBtn);

    BottomBar->addSpacing(10);

    SummaryLabel = new QLabel(QStringLiteral("No comparison loaded"), this);
    BottomBar->addWidget(SummaryLabel, 1);

    MainLayout->addLayout(BottomBar);

    connect(BrowseBtn1, &QPushButton::clicked, this, &BinDiffWidget::OnBrowseFile1);
    connect(BrowseBtn2, &QPushButton::clicked, this, &BinDiffWidget::OnBrowseFile2);
    connect(CompareBtn, &QPushButton::clicked, this, &BinDiffWidget::OnCompare);
    connect(NextDiffBtn, &QPushButton::clicked, this, &BinDiffWidget::OnNextDiff);
    connect(PrevDiffBtn, &QPushButton::clicked, this, &BinDiffWidget::OnPrevDiff);
    connect(LeftView, &HexDiffView::ScrollChanged, this, &BinDiffWidget::OnLeftScrollChanged);
    connect(RightView, &HexDiffView::ScrollChanged, this, &BinDiffWidget::OnRightScrollChanged);
}

void BinDiffWidget::SetDatabases(AnalysisDatabase* Db1, AnalysisDatabase* Db2) {
    Db1Ref = Db1;
    Db2Ref = Db2;
}

void BinDiffWidget::OnBrowseFile1() {
    QString Path = QFileDialog::getOpenFileName(this, QStringLiteral("Select File 1"));
    if (!Path.isEmpty())
        File1Path->setText(Path);
}

void BinDiffWidget::OnBrowseFile2() {
    QString Path = QFileDialog::getOpenFileName(this, QStringLiteral("Select File 2"));
    if (!Path.isEmpty())
        File2Path->setText(Path);
}

void BinDiffWidget::OnCompare() {
    QString Path1 = File1Path->text();
    QString Path2 = File2Path->text();

    if (Path1.isEmpty() || Path2.isEmpty())
        return;

    CurrentResult = Engine->CompareBytes(Path1, Path2);

    QFile F1(Path1);
    QFile F2(Path2);
    QByteArray Data1;
    QByteArray Data2;

    if (F1.open(QIODevice::ReadOnly))
        Data1 = F1.readAll();
    if (F2.open(QIODevice::ReadOnly))
        Data2 = F2.readAll();

    LeftView->SetData(Data1, CurrentResult.Regions, true);
    RightView->SetData(Data2, CurrentResult.Regions, false);

    UpdateSummary();

    bool HasDiffs = false;
    for (const auto& Region : CurrentResult.Regions) {
        if (Region.Type != DiffRegionType::Match) {
            HasDiffs = true;
            break;
        }
    }
    NextDiffBtn->setEnabled(HasDiffs);
    PrevDiffBtn->setEnabled(HasDiffs);

    if (Db1Ref && Db2Ref) {
        DiffResult FuncResult = Engine->CompareFunctions(Db1Ref, Db2Ref);
        CurrentResult.FunctionMatches = FuncResult.FunctionMatches;
        PopulateFunctionTable();
    }
}

void BinDiffWidget::OnNextDiff() {
    uint64_t CurrentOffset = static_cast<uint64_t>(LeftView->CurrentScroll()) * 16;
    int NextOffset = FindNextDiffOffset(CurrentOffset, true);
    if (NextOffset >= 0) {
        LeftView->ScrollToOffset(static_cast<uint64_t>(NextOffset));
        SyncingScroll = true;
        RightView->SetScrollValue(LeftView->CurrentScroll());
        SyncingScroll = false;
    }
}

void BinDiffWidget::OnPrevDiff() {
    uint64_t CurrentOffset = static_cast<uint64_t>(LeftView->CurrentScroll()) * 16;
    int PrevOffset = FindNextDiffOffset(CurrentOffset, false);
    if (PrevOffset >= 0) {
        LeftView->ScrollToOffset(static_cast<uint64_t>(PrevOffset));
        SyncingScroll = true;
        RightView->SetScrollValue(LeftView->CurrentScroll());
        SyncingScroll = false;
    }
}

void BinDiffWidget::OnLeftScrollChanged(int Value) {
    if (SyncingScroll)
        return;
    SyncingScroll = true;
    RightView->SetScrollValue(Value);
    SyncingScroll = false;
}

void BinDiffWidget::OnRightScrollChanged(int Value) {
    if (SyncingScroll)
        return;
    SyncingScroll = true;
    LeftView->SetScrollValue(Value);
    SyncingScroll = false;
}

void BinDiffWidget::UpdateSummary() {
    QString Summary = QStringLiteral("%1% match | %2 bytes match | %3 bytes differ")
        .arg(CurrentResult.MatchPercent)
        .arg(CurrentResult.MatchingBytes)
        .arg(CurrentResult.DifferingBytes);

    if (CurrentResult.OnlyInFile1 > 0)
        Summary += QStringLiteral(" | %1 bytes only in File 1").arg(CurrentResult.OnlyInFile1);
    if (CurrentResult.OnlyInFile2 > 0)
        Summary += QStringLiteral(" | %1 bytes only in File 2").arg(CurrentResult.OnlyInFile2);

    SummaryLabel->setText(Summary);
}

void BinDiffWidget::PopulateFunctionTable() {
    FunctionTable->setRowCount(0);
    FunctionTable->setSortingEnabled(false);

    for (const auto& Match : CurrentResult.FunctionMatches) {
        int Row = FunctionTable->rowCount();
        FunctionTable->insertRow(Row);

        FunctionTable->setItem(Row, 0, new QTableWidgetItem(Match.Name1));
        FunctionTable->setItem(Row, 1, new QTableWidgetItem(Match.Name2));
        FunctionTable->setItem(Row, 2, new QTableWidgetItem(
            QStringLiteral("0x%1").arg(Match.Addr1, 0, 16)));
        FunctionTable->setItem(Row, 3, new QTableWidgetItem(
            QStringLiteral("0x%1").arg(Match.Addr2, 0, 16)));

        QTableWidgetItem* SimItem = new QTableWidgetItem();
        SimItem->setData(Qt::DisplayRole, QStringLiteral("%1%").arg(Match.Similarity * 100.0, 0, 'f', 1));
        SimItem->setData(Qt::UserRole, Match.Similarity);

        QColor SimColor;
        if (Match.Similarity >= 0.9)
            SimColor = QColor(60, 180, 60);
        else if (Match.Similarity >= 0.7)
            SimColor = QColor(200, 200, 60);
        else
            SimColor = QColor(200, 60, 60);
        SimItem->setForeground(SimColor);

        FunctionTable->setItem(Row, 4, SimItem);
    }

    FunctionTable->setSortingEnabled(true);
    FunctionTable->resizeColumnsToContents();
}

int BinDiffWidget::FindNextDiffOffset(uint64_t CurrentOffset, bool Forward) const {
    if (Forward) {
        for (const auto& Region : CurrentResult.Regions) {
            if (Region.Type != DiffRegionType::Match && Region.Offset > CurrentOffset)
                return static_cast<int>(Region.Offset);
        }
    } else {
        for (int I = CurrentResult.Regions.size() - 1; I >= 0; --I) {
            const auto& Region = CurrentResult.Regions[I];
            if (Region.Type != DiffRegionType::Match && Region.Offset + Region.Size <= CurrentOffset)
                return static_cast<int>(Region.Offset);
        }
    }
    return -1;
}

}
