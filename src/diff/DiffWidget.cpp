#include "DiffWidget.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QSplitter>
#include <QHeaderView>
#include <QFileDialog>
#include <QFile>
#include <QScrollBar>
#include <QTextCharFormat>
#include <QTextCursor>
#include <QTextBlock>
#include <QtConcurrent>

namespace Fidra {

DiffWidget::DiffWidget(QWidget* Parent, ICore* Core)
    : QWidget(Parent)
    , CoreRef(Core)
    , Engine(new DiffEngine(this))
    , CurrentDiffIndex(-1)
{
    SetupUi();

    connect(Engine, &DiffEngine::ProgressChanged, ProgressBar, &QProgressBar::setValue);
}

void DiffWidget::SetupUi() {
    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(4, 4, 4, 4);

    auto* FileGroup = new QGroupBox("Files");
    auto* FileLayout = new QVBoxLayout(FileGroup);

    auto* OldRow = new QHBoxLayout();
    OldRow->addWidget(new QLabel("Old:"));
    OldFileEdit = new QLineEdit();
    OldFileEdit->setPlaceholderText("Select old binary...");
    OldRow->addWidget(OldFileEdit);
    BrowseOldButton = new QPushButton("...");
    BrowseOldButton->setFixedWidth(30);
    OldRow->addWidget(BrowseOldButton);
    FileLayout->addLayout(OldRow);

    auto* NewRow = new QHBoxLayout();
    NewRow->addWidget(new QLabel("New:"));
    NewFileEdit = new QLineEdit();
    NewFileEdit->setPlaceholderText("Select new binary...");
    NewRow->addWidget(NewFileEdit);
    BrowseNewButton = new QPushButton("...");
    BrowseNewButton->setFixedWidth(30);
    NewRow->addWidget(BrowseNewButton);
    FileLayout->addLayout(NewRow);

    auto* ControlRow = new QHBoxLayout();
    RunButton = new QPushButton("Compare");
    ControlRow->addWidget(RunButton);

    FilterCombo = new QComboBox();
    FilterCombo->addItem("All Changes");
    FilterCombo->addItem("Modified Only");
    FilterCombo->addItem("Added Only");
    FilterCombo->addItem("Removed Only");
    ControlRow->addWidget(new QLabel("Filter:"));
    ControlRow->addWidget(FilterCombo);

    ShowUnchangedCheck = new QCheckBox("Show Unchanged");
    ControlRow->addWidget(ShowUnchangedCheck);
    ControlRow->addStretch();

    FileLayout->addLayout(ControlRow);
    MainLayout->addWidget(FileGroup);

    auto* StatsGroup = new QGroupBox("Summary Stats");
    auto* StatsLayout = new QHBoxLayout(StatsGroup);
    StatsChangedLabel = new QLabel("Modified: 0 bytes");
    StatsAddedLabel = new QLabel("Added: 0 bytes");
    StatsRemovedLabel = new QLabel("Removed: 0 bytes");
    StatsSimilarityLabel = new QLabel("Similarity: -");
    StatsLayout->addWidget(StatsChangedLabel);
    StatsLayout->addWidget(StatsAddedLabel);
    StatsLayout->addWidget(StatsRemovedLabel);
    StatsLayout->addWidget(StatsSimilarityLabel);
    StatsLayout->addStretch();
    MainLayout->addWidget(StatsGroup);

    auto* NavRow = new QHBoxLayout();
    PrevDiffButton = new QPushButton("<< Prev Diff");
    PrevDiffButton->setEnabled(false);
    NextDiffButton = new QPushButton("Next Diff >>");
    NextDiffButton->setEnabled(false);
    DiffNavLabel = new QLabel("No diffs");
    NavRow->addWidget(PrevDiffButton);
    NavRow->addWidget(DiffNavLabel);
    NavRow->addWidget(NextDiffButton);
    NavRow->addStretch();
    MainLayout->addLayout(NavRow);

    ResultTabs = new QTabWidget();

    HexSplitter = new QSplitter(Qt::Horizontal);
    auto* OldHexGroup = new QGroupBox("Old Binary");
    auto* OldHexLayout = new QVBoxLayout(OldHexGroup);
    OldHexEdit = new QPlainTextEdit();
    OldHexEdit->setReadOnly(true);
    OldHexEdit->setFont(QFont("Monospace", 10));
    OldHexEdit->setLineWrapMode(QPlainTextEdit::NoWrap);
    OldHexLayout->addWidget(OldHexEdit);
    OldHexLayout->setContentsMargins(2, 2, 2, 2);

    auto* NewHexGroup = new QGroupBox("New Binary");
    auto* NewHexLayout = new QVBoxLayout(NewHexGroup);
    NewHexEdit = new QPlainTextEdit();
    NewHexEdit->setReadOnly(true);
    NewHexEdit->setFont(QFont("Monospace", 10));
    NewHexEdit->setLineWrapMode(QPlainTextEdit::NoWrap);
    NewHexLayout->addWidget(NewHexEdit);
    NewHexLayout->setContentsMargins(2, 2, 2, 2);

    HexSplitter->addWidget(OldHexGroup);
    HexSplitter->addWidget(NewHexGroup);
    ResultTabs->addTab(HexSplitter, "Side-by-Side Hex");

    connect(OldHexEdit->verticalScrollBar(), &QScrollBar::valueChanged,
            NewHexEdit->verticalScrollBar(), &QScrollBar::setValue);
    connect(NewHexEdit->verticalScrollBar(), &QScrollBar::valueChanged,
            OldHexEdit->verticalScrollBar(), &QScrollBar::setValue);

    SummaryText = new QTextEdit();
    SummaryText->setReadOnly(true);
    SummaryText->setFont(QFont("Monospace", 10));
    ResultTabs->addTab(SummaryText, "Summary");

    ByteTable = new QTableWidget();
    ByteTable->setColumnCount(5);
    ByteTable->setHorizontalHeaderLabels({"Offset", "Length", "Type", "Old", "New"});
    ByteTable->horizontalHeader()->setStretchLastSection(true);
    ByteTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ByteTable->setAlternatingRowColors(true);
    ResultTabs->addTab(ByteTable, "Byte Diffs");

    FunctionTable = new QTableWidget();
    FunctionTable->setColumnCount(5);
    FunctionTable->setHorizontalHeaderLabels({"Function", "Old Address", "New Address", "Status", "Similarity"});
    FunctionTable->horizontalHeader()->setStretchLastSection(true);
    FunctionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    FunctionTable->setAlternatingRowColors(true);
    ResultTabs->addTab(FunctionTable, "Functions");

    MainLayout->addWidget(ResultTabs, 1);

    ProgressBar = new QProgressBar();
    ProgressBar->setRange(0, 100);
    ProgressBar->setValue(0);
    ProgressBar->setTextVisible(true);
    ProgressBar->setFixedHeight(20);
    MainLayout->addWidget(ProgressBar);

    StatusLabel = new QLabel("Ready");
    MainLayout->addWidget(StatusLabel);

    connect(BrowseOldButton, &QPushButton::clicked, this, &DiffWidget::OnBrowseOld);
    connect(BrowseNewButton, &QPushButton::clicked, this, &DiffWidget::OnBrowseNew);
    connect(RunButton, &QPushButton::clicked, this, &DiffWidget::OnRunDiff);
    connect(FilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &DiffWidget::OnFilterChanged);
    connect(ShowUnchangedCheck, &QCheckBox::toggled, this, &DiffWidget::OnFilterChanged);
    connect(PrevDiffButton, &QPushButton::clicked, this, &DiffWidget::OnPrevDiff);
    connect(NextDiffButton, &QPushButton::clicked, this, &DiffWidget::OnNextDiff);
    connect(FunctionTable, &QTableWidget::cellClicked, this, &DiffWidget::OnFunctionTableClicked);
}

void DiffWidget::OnBrowseOld() {
    QString Path = QFileDialog::getOpenFileName(this, "Select Old File", QString(), "All Files (*)");
    if (!Path.isEmpty())
        OldFileEdit->setText(Path);
}

void DiffWidget::OnBrowseNew() {
    QString Path = QFileDialog::getOpenFileName(this, "Select New File", QString(), "All Files (*)");
    if (!Path.isEmpty())
        NewFileEdit->setText(Path);
}

void DiffWidget::OnRunDiff() {
    QString OldPath = OldFileEdit->text();
    QString NewPath = NewFileEdit->text();

    if (OldPath.isEmpty() || NewPath.isEmpty()) {
        StatusLabel->setText("Select both files first");
        return;
    }

    CompareFiles(OldPath, NewPath);
}

void DiffWidget::CompareFiles(const QString& OldPath, const QString& NewPath) {
    QFile OldFile(OldPath);
    QFile NewFile(NewPath);

    if (!OldFile.open(QIODevice::ReadOnly)) {
        StatusLabel->setText("Failed to open old file: " + OldPath);
        return;
    }
    if (!NewFile.open(QIODevice::ReadOnly)) {
        StatusLabel->setText("Failed to open new file: " + NewPath);
        return;
    }

    OldFileData = OldFile.readAll();
    NewFileData = NewFile.readAll();
    OldFile.close();
    NewFile.close();

    OldFileEdit->setText(OldPath);
    NewFileEdit->setText(NewPath);

    RunButton->setEnabled(false);
    StatusLabel->setText("Comparing...");
    ProgressBar->setValue(0);

    (void)QtConcurrent::run([this]() {
        DiffResult Result = Engine->CompareBinaries(OldFileData, NewFileData);

        QMetaObject::invokeMethod(this, [this, Result]() {
            CurrentResult = Result;
            CurrentResult.OldFileName = OldFileEdit->text();
            CurrentResult.NewFileName = NewFileEdit->text();

            DiffOffsets.clear();
            for (const auto& Diff : CurrentResult.ByteDiffs) {
                if (Diff.Type != DiffType::Unchanged) {
                    DiffOffsets.append(Diff.Offset);
                }
            }
            CurrentDiffIndex = DiffOffsets.isEmpty() ? -1 : 0;

            PopulateSummary();
            PopulateByteTable();
            PopulateFunctionTable();
            UpdateHexView();
            UpdateDiffNavLabel();

            StatsChangedLabel->setText(QString("Modified: %1 bytes").arg(CurrentResult.TotalChanged));
            StatsAddedLabel->setText(QString("Added: %1 bytes").arg(CurrentResult.TotalAdded));
            StatsRemovedLabel->setText(QString("Removed: %1 bytes").arg(CurrentResult.TotalRemoved));
            StatsSimilarityLabel->setText(QString("Similarity: %1%").arg(static_cast<int>(CurrentResult.OverallSimilarity * 100)));

            PrevDiffButton->setEnabled(!DiffOffsets.isEmpty());
            NextDiffButton->setEnabled(!DiffOffsets.isEmpty());

            RunButton->setEnabled(true);
            StatusLabel->setText(QString("Done - %1 diffs found, %2% similar")
                .arg(CurrentResult.ByteDiffs.size())
                .arg(static_cast<int>(CurrentResult.OverallSimilarity * 100)));
        }, Qt::QueuedConnection);
    });
}

void DiffWidget::PopulateSummary() {
    QString Summary;
    Summary += QString("=== Binary Diff Summary ===\n\n");
    Summary += QString("Old: %1 (%2 bytes)\n").arg(CurrentResult.OldFileName).arg(CurrentResult.OldSize);
    Summary += QString("New: %1 (%2 bytes)\n").arg(CurrentResult.NewFileName).arg(CurrentResult.NewSize);
    Summary += QString("\nSimilarity: %1%\n").arg(static_cast<int>(CurrentResult.OverallSimilarity * 100));
    Summary += QString("\nModified: %1 bytes\n").arg(CurrentResult.TotalChanged);
    Summary += QString("Added:    %1 bytes\n").arg(CurrentResult.TotalAdded);
    Summary += QString("Removed:  %1 bytes\n").arg(CurrentResult.TotalRemoved);
    Summary += QString("\nTotal diff regions: %1\n").arg(CurrentResult.ByteDiffs.size());

    if (!CurrentResult.FunctionDiffs.isEmpty()) {
        int ModifiedFuncs = 0, AddedFuncs = 0, RemovedFuncs = 0, UnchangedFuncs = 0;
        for (const auto& FD : CurrentResult.FunctionDiffs) {
            switch (FD.Type) {
            case DiffType::Modified: ++ModifiedFuncs; break;
            case DiffType::Added: ++AddedFuncs; break;
            case DiffType::Removed: ++RemovedFuncs; break;
            case DiffType::Unchanged: ++UnchangedFuncs; break;
            }
        }
        Summary += QString("\n=== Function Diff ===\n");
        Summary += QString("Modified:  %1\n").arg(ModifiedFuncs);
        Summary += QString("Added:     %1\n").arg(AddedFuncs);
        Summary += QString("Removed:   %1\n").arg(RemovedFuncs);
        Summary += QString("Unchanged: %1\n").arg(UnchangedFuncs);
    }

    SummaryText->setPlainText(Summary);
}

void DiffWidget::PopulateByteTable() {
    int FilterIndex = FilterCombo->currentIndex();

    QVector<ByteDiff> Filtered;
    for (const auto& Diff : CurrentResult.ByteDiffs) {
        switch (FilterIndex) {
        case 1:
            if (Diff.Type == DiffType::Modified) Filtered.append(Diff);
            break;
        case 2:
            if (Diff.Type == DiffType::Added) Filtered.append(Diff);
            break;
        case 3:
            if (Diff.Type == DiffType::Removed) Filtered.append(Diff);
            break;
        default:
            Filtered.append(Diff);
            break;
        }
    }

    ByteTable->setRowCount(Filtered.size());

    for (int I = 0; I < Filtered.size(); ++I) {
        const auto& Diff = Filtered[I];

        auto* OffsetItem = new QTableWidgetItem(QString("0x%1").arg(Diff.Offset, 8, 16, QChar('0')));
        auto* LengthItem = new QTableWidgetItem(QString::number(Diff.Length));

        QString TypeStr;
        QColor TypeColor;
        switch (Diff.Type) {
        case DiffType::Modified: TypeStr = "Modified"; TypeColor = QColor(200, 150, 0); break;
        case DiffType::Added: TypeStr = "Added"; TypeColor = QColor(0, 150, 0); break;
        case DiffType::Removed: TypeStr = "Removed"; TypeColor = QColor(200, 0, 0); break;
        default: TypeStr = "Unchanged"; TypeColor = palette().color(QPalette::Text); break;
        }
        auto* TypeItem = new QTableWidgetItem(TypeStr);
        TypeItem->setForeground(TypeColor);

        int PreviewLen = std::min(Diff.Length, 16);
        QString OldHex, NewHex;
        for (int B = 0; B < PreviewLen; ++B) {
            if (B < Diff.OldData.size())
                OldHex += QString("%1 ").arg(static_cast<uint8_t>(Diff.OldData[B]), 2, 16, QChar('0'));
            if (B < Diff.NewData.size())
                NewHex += QString("%1 ").arg(static_cast<uint8_t>(Diff.NewData[B]), 2, 16, QChar('0'));
        }
        if (Diff.Length > 16) {
            OldHex += "...";
            NewHex += "...";
        }

        ByteTable->setItem(I, 0, OffsetItem);
        ByteTable->setItem(I, 1, LengthItem);
        ByteTable->setItem(I, 2, TypeItem);
        ByteTable->setItem(I, 3, new QTableWidgetItem(OldHex.trimmed()));
        ByteTable->setItem(I, 4, new QTableWidgetItem(NewHex.trimmed()));
    }

    ByteTable->resizeColumnsToContents();
}

void DiffWidget::PopulateFunctionTable() {
    int FilterIndex = FilterCombo->currentIndex();
    bool ShowUnchanged = ShowUnchangedCheck->isChecked();

    QVector<FunctionDiff> Filtered;
    for (const auto& FD : CurrentResult.FunctionDiffs) {
        if (!ShowUnchanged && FD.Type == DiffType::Unchanged) continue;

        switch (FilterIndex) {
        case 1:
            if (FD.Type == DiffType::Modified) Filtered.append(FD);
            break;
        case 2:
            if (FD.Type == DiffType::Added) Filtered.append(FD);
            break;
        case 3:
            if (FD.Type == DiffType::Removed) Filtered.append(FD);
            break;
        default:
            Filtered.append(FD);
            break;
        }
    }

    FunctionTable->setRowCount(Filtered.size());

    for (int I = 0; I < Filtered.size(); ++I) {
        const auto& FD = Filtered[I];

        auto* NameItem = new QTableWidgetItem(FD.Name);

        QString OldAddr = FD.OldAddr ? QString("0x%1").arg(FD.OldAddr, 0, 16) : "-";
        QString NewAddr = FD.NewAddr ? QString("0x%1").arg(FD.NewAddr, 0, 16) : "-";

        QString StatusStr;
        QColor StatusColor;
        switch (FD.Type) {
        case DiffType::Modified: StatusStr = "Modified"; StatusColor = QColor(200, 150, 0); break;
        case DiffType::Added: StatusStr = "Added"; StatusColor = QColor(0, 150, 0); break;
        case DiffType::Removed: StatusStr = "Removed"; StatusColor = QColor(200, 0, 0); break;
        case DiffType::Unchanged: StatusStr = "Unchanged"; StatusColor = palette().color(QPalette::Text); break;
        }

        auto* StatusItem = new QTableWidgetItem(StatusStr);
        StatusItem->setForeground(StatusColor);

        auto* SimItem = new QTableWidgetItem(QString("%1%").arg(static_cast<int>(FD.Similarity * 100)));

        FunctionTable->setItem(I, 0, NameItem);
        FunctionTable->setItem(I, 1, new QTableWidgetItem(OldAddr));
        FunctionTable->setItem(I, 2, new QTableWidgetItem(NewAddr));
        FunctionTable->setItem(I, 3, StatusItem);
        FunctionTable->setItem(I, 4, SimItem);
    }

    FunctionTable->resizeColumnsToContents();
}

QString DiffWidget::FormatHexDump(const QByteArray& Data, int BytesPerLine) {
    QString Result;
    int TotalLines = (Data.size() + BytesPerLine - 1) / BytesPerLine;

    for (int Line = 0; Line < TotalLines; ++Line) {
        int BaseOffset = Line * BytesPerLine;

        Result += QString("%1  ").arg(BaseOffset, 8, 16, QChar('0'));

        for (int B = 0; B < BytesPerLine; ++B) {
            int Offset = BaseOffset + B;
            if (Offset < Data.size()) {
                uint8_t Val = static_cast<uint8_t>(Data[Offset]);
                Result += QString("%1 ").arg(Val, 2, 16, QChar('0'));
            } else {
                Result += "   ";
            }
            if (B == 7) Result += " ";
        }

        Result += " |";
        for (int B = 0; B < BytesPerLine; ++B) {
            int Offset = BaseOffset + B;
            if (Offset < Data.size()) {
                uint8_t Val = static_cast<uint8_t>(Data[Offset]);
                Result += (Val >= 32 && Val < 127) ? QChar(Val) : QChar('.');
            } else {
                Result += ' ';
            }
        }
        Result += "|\n";
    }

    return Result;
}

void DiffWidget::UpdateHexView() {
    OldHexEdit->setPlainText(FormatHexDump(OldFileData));
    NewHexEdit->setPlainText(FormatHexDump(NewFileData));

    HighlightHexDiffs();
}

void DiffWidget::HighlightHexDiffs() {
    int BytesPerLine = 16;

    auto HighlightEdit = [&](QPlainTextEdit* Edit, const QByteArray& Data, bool IsNew) {
        QList<QTextEdit::ExtraSelection> Selections;

        for (const auto& Diff : CurrentResult.ByteDiffs) {
            if (Diff.Type == DiffType::Unchanged) continue;

            QColor BgColor;
            switch (Diff.Type) {
            case DiffType::Added: BgColor = QColor(0, 180, 0, 60); break;
            case DiffType::Removed: BgColor = QColor(220, 0, 0, 60); break;
            case DiffType::Modified: BgColor = QColor(220, 180, 0, 60); break;
            default: continue;
            }

            QColor FgColor;
            switch (Diff.Type) {
            case DiffType::Added: FgColor = QColor(0, 220, 0); break;
            case DiffType::Removed: FgColor = QColor(255, 80, 80); break;
            case DiffType::Modified: FgColor = QColor(255, 220, 50); break;
            default: FgColor = palette().color(QPalette::Text); break;
            }

            for (int B = 0; B < Diff.Length; ++B) {
                int64_t ByteOffset = Diff.Offset + B;
                if (ByteOffset >= Data.size()) continue;

                int LineNum = static_cast<int>(ByteOffset / BytesPerLine);
                int ByteInLine = static_cast<int>(ByteOffset % BytesPerLine);

                int HexCharPos = 10 + ByteInLine * 3;
                if (ByteInLine >= 8) HexCharPos += 1;

                QTextBlock Block = Edit->document()->findBlockByLineNumber(LineNum);
                if (!Block.isValid()) continue;

                int BlockStart = Block.position();

                QTextEdit::ExtraSelection HexSel;
                HexSel.format.setBackground(BgColor);
                HexSel.format.setForeground(FgColor);
                HexSel.cursor = QTextCursor(Edit->document());
                HexSel.cursor.setPosition(BlockStart + HexCharPos);
                HexSel.cursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, 2);
                Selections.append(HexSel);

                int AsciiStart = 10 + BytesPerLine * 3 + 1 + 2;
                if (BytesPerLine > 8) AsciiStart += 1;
                int AsciiCharPos = AsciiStart + ByteInLine;

                QTextEdit::ExtraSelection AsciiSel;
                AsciiSel.format.setBackground(BgColor);
                AsciiSel.format.setForeground(FgColor);
                AsciiSel.cursor = QTextCursor(Edit->document());
                AsciiSel.cursor.setPosition(BlockStart + AsciiCharPos);
                AsciiSel.cursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, 1);
                Selections.append(AsciiSel);
            }
        }

        Edit->setExtraSelections(Selections);
    };

    HighlightEdit(OldHexEdit, OldFileData, false);
    HighlightEdit(NewHexEdit, NewFileData, true);
}

void DiffWidget::ScrollToByteOffset(int64_t Offset) {
    int BytesPerLine = 16;
    int LineNum = static_cast<int>(Offset / BytesPerLine);

    auto ScrollEdit = [&](QPlainTextEdit* Edit) {
        QTextBlock Block = Edit->document()->findBlockByLineNumber(LineNum);
        if (!Block.isValid()) return;

        QTextCursor Cursor(Block);
        Edit->setTextCursor(Cursor);
        Edit->centerCursor();
    };

    ScrollEdit(OldHexEdit);
    ScrollEdit(NewHexEdit);

    ResultTabs->setCurrentWidget(HexSplitter);
}

void DiffWidget::OnPrevDiff() {
    if (DiffOffsets.isEmpty()) return;

    CurrentDiffIndex--;
    if (CurrentDiffIndex < 0) CurrentDiffIndex = DiffOffsets.size() - 1;

    ScrollToByteOffset(DiffOffsets[CurrentDiffIndex]);
    UpdateDiffNavLabel();
}

void DiffWidget::OnNextDiff() {
    if (DiffOffsets.isEmpty()) return;

    CurrentDiffIndex++;
    if (CurrentDiffIndex >= DiffOffsets.size()) CurrentDiffIndex = 0;

    ScrollToByteOffset(DiffOffsets[CurrentDiffIndex]);
    UpdateDiffNavLabel();
}

void DiffWidget::UpdateDiffNavLabel() {
    if (DiffOffsets.isEmpty()) {
        DiffNavLabel->setText("No diffs");
        return;
    }

    DiffNavLabel->setText(QString("Diff %1 / %2 (offset 0x%3)")
        .arg(CurrentDiffIndex + 1)
        .arg(DiffOffsets.size())
        .arg(DiffOffsets[CurrentDiffIndex], 0, 16));
}

void DiffWidget::OnFilterChanged() {
    PopulateByteTable();
    PopulateFunctionTable();
}

void DiffWidget::OnFunctionTableClicked(int Row, int Column) {
    Q_UNUSED(Column);
    if (Row < 0 || Row >= CurrentResult.FunctionDiffs.size()) return;

    const auto& FD = CurrentResult.FunctionDiffs[Row];
    Address TargetAddr = FD.OldAddr ? FD.OldAddr : FD.NewAddr;
    if (TargetAddr > 0) {
        ScrollToByteOffset(static_cast<int64_t>(TargetAddr));
    }
}

}
