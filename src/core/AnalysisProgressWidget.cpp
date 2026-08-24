#include "AnalysisProgressWidget.h"
#include "../analysis/AnalysisDatabase.h"
#include <QPainter>
#include <QPaintEvent>
#include <QMouseEvent>
#include <QHBoxLayout>
#include <QFrame>
#include <QFont>
#include <QToolTip>
#include <QLocale>

namespace Fidra {

NavigatorBand::NavigatorBand(QWidget* Parent)
    : QWidget(Parent) {
    setFixedHeight(22);
    setCursor(Qt::PointingHandCursor);
    setMouseTracking(true);
}

void NavigatorBand::SetSegments(const QList<Segment>& Segments) {
    Segs = Segments;
    if (!Segs.isEmpty()) {
        MinAddr = Segs.first().VirtualAddress;
        MaxAddr = 0;
        for (auto& S : Segs) {
            if (S.VirtualAddress < MinAddr) MinAddr = S.VirtualAddress;
            Address End = S.VirtualAddress + S.VirtualSize;
            if (End > MaxAddr) MaxAddr = End;
        }
    }
    update();
}

void NavigatorBand::SetCurrentAddress(Address Addr) {
    CurrentAddr = Addr;
    update();
}

QColor NavigatorBand::ColorForSegment(const Segment& Seg) const {
    if (Seg.IsExecutable && Seg.Type == SegmentType::Code)
        return QColor(86, 156, 214);
    if (Seg.IsExecutable)
        return QColor(78, 201, 176);
    if (Seg.Type == SegmentType::Import)
        return QColor(206, 145, 120);
    if (Seg.Type == SegmentType::Data)
        return QColor(181, 206, 168);
    if (Seg.Type == SegmentType::Bss)
        return QColor(80, 80, 80);
    if (Seg.Type == SegmentType::Resource)
        return QColor(197, 134, 192);
    if (Seg.Type == SegmentType::Reloc)
        return QColor(220, 220, 170);
    if (Seg.Type == SegmentType::Export)
        return QColor(206, 145, 120);
    return QColor(100, 100, 100);
}

int NavigatorBand::AddressToX(Address Addr) const {
    if (MaxAddr <= MinAddr) return 0;
    double Ratio = static_cast<double>(Addr - MinAddr) / static_cast<double>(MaxAddr - MinAddr);
    return static_cast<int>(Ratio * (width() - 2)) + 1;
}

Address NavigatorBand::XToAddress(int X) const {
    if (width() <= 2) return MinAddr;
    double Ratio = static_cast<double>(X - 1) / static_cast<double>(width() - 2);
    return MinAddr + static_cast<Address>(Ratio * (MaxAddr - MinAddr));
}

QString NavigatorBand::SegmentAtX(int X) const {
    Address Addr = XToAddress(X);
    for (auto& Seg : Segs) {
        if (Addr >= Seg.VirtualAddress && Addr < Seg.VirtualAddress + Seg.VirtualSize) {
            QString Flags;
            if (Seg.IsReadable) Flags += "R";
            if (Seg.IsWritable) Flags += "W";
            if (Seg.IsExecutable) Flags += "X";
            double SizeMb = Seg.VirtualSize / (1024.0 * 1024.0);
            return QString("%1  0x%2  %3 MB  [%4]")
                .arg(Seg.Name)
                .arg(Seg.VirtualAddress, 0, 16)
                .arg(SizeMb, 0, 'f', 1)
                .arg(Flags);
        }
    }
    return QString();
}

void NavigatorBand::paintEvent(QPaintEvent*) {
    QPainter P(this);
    P.setRenderHint(QPainter::Antialiasing, false);

    P.fillRect(rect(), QColor(20, 20, 20));

    if (Segs.isEmpty() || MaxAddr <= MinAddr) return;

    for (auto& Seg : Segs) {
        int X1 = AddressToX(Seg.VirtualAddress);
        int X2 = AddressToX(Seg.VirtualAddress + Seg.VirtualSize);
        if (X2 - X1 < 1) X2 = X1 + 1;

        QColor Col = ColorForSegment(Seg);
        Col.setAlpha(160);
        P.fillRect(X1, 0, X2 - X1, height(), Col);

        if (X2 - X1 > 2) {
            P.setPen(Col.darker(150));
            P.drawLine(X1, 0, X1, height() - 1);
        }
    }

    QFont F = font();
    F.setPixelSize(9);
    F.setBold(true);
    P.setFont(F);
    P.setPen(QColor(240, 240, 240));
    int TextY = height() / 2 + 3;
    for (auto& Seg : Segs) {
        int X1 = AddressToX(Seg.VirtualAddress);
        int X2 = AddressToX(Seg.VirtualAddress + Seg.VirtualSize);
        int SegWidth = X2 - X1;
        if (SegWidth > 25) {
            QFontMetrics Fm(F);
            int TextWidth = Fm.horizontalAdvance(Seg.Name);
            if (TextWidth < SegWidth - 4) {
                P.drawText(X1 + (SegWidth - TextWidth) / 2, TextY, Seg.Name);
            }
        }
    }

    if (CurrentAddr >= MinAddr && CurrentAddr <= MaxAddr) {
        int Cx = AddressToX(CurrentAddr);
        P.setPen(QPen(QColor(255, 200, 0), 2));
        P.drawLine(Cx, 0, Cx, height());
    }
}

void NavigatorBand::mousePressEvent(QMouseEvent* Event) {
    if (Event->button() == Qt::LeftButton && MaxAddr > MinAddr) {
        emit AddressClicked(XToAddress(Event->pos().x()));
    }
}

void NavigatorBand::mouseMoveEvent(QMouseEvent* Event) {
    QString Tip = SegmentAtX(Event->pos().x());
    if (!Tip.isEmpty()) {
        QToolTip::showText(Event->globalPosition().toPoint(), Tip, this);
    }
}

AnalysisProgressWidget::AnalysisProgressWidget(QWidget* Parent)
    : QWidget(Parent) {
    SetupUi();
    ElapsedTimer = new QTimer(this);
    connect(ElapsedTimer, &QTimer::timeout, this, [this]() {
        if (!Finished && LastElapsedMs > 0)
            ElapsedLabel->setText(FormatDuration(LastElapsedMs));
    });
}

void AnalysisProgressWidget::SetupUi() {
    auto* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(0, 0, 0, 0);
    MainLayout->setSpacing(0);

    NavBand = new NavigatorBand(this);
    MainLayout->addWidget(NavBand);

    auto* InfoBar = new QWidget(this);
    InfoBar->setStyleSheet("background: #252525; border-bottom: 1px solid #3e3e3e;");
    InfoBar->setFixedHeight(24);
    auto* InfoLayout = new QHBoxLayout(InfoBar);
    InfoLayout->setContentsMargins(8, 0, 8, 0);
    InfoLayout->setSpacing(12);

    PhaseLabel = new QLabel("Idle", InfoBar);
    PhaseLabel->setStyleSheet("font-weight: bold; color: #569cd6; font-size: 11px; border: none;");
    InfoLayout->addWidget(PhaseLabel);

    OverallProgress = new QProgressBar(InfoBar);
    OverallProgress->setFixedHeight(12);
    OverallProgress->setFixedWidth(200);
    OverallProgress->setTextVisible(false);
    OverallProgress->setRange(0, 100);
    OverallProgress->setValue(0);
    OverallProgress->setStyleSheet(
        "QProgressBar { border: 1px solid #3e3e3e; border-radius: 2px; background: #1e1e1e; }"
        "QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0e639c, stop:1 #1177bb); border-radius: 1px; }"
    );
    InfoLayout->addWidget(OverallProgress);

    StatsLabel = new QLabel("", InfoBar);
    StatsLabel->setStyleSheet("color: #b0b0b0; font-size: 10px; border: none;");
    InfoLayout->addWidget(StatsLabel, 1);

    ElapsedLabel = new QLabel("0:00", InfoBar);
    ElapsedLabel->setStyleSheet("color: #808080; font-size: 10px; border: none;");
    ElapsedLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    InfoLayout->addWidget(ElapsedLabel);

    MainLayout->addWidget(InfoBar);

    setMaximumHeight(46);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
}

void AnalysisProgressWidget::SetDatabase(AnalysisDatabase* Database) {
    Db = Database;
    if (!Db) return;

    BinaryInfo Info = Db->GetBinaryInfo();
    NavBand->SetSegments(Info.Segments);
    ElapsedTimer->start(500);
    Finished = false;
}

void AnalysisProgressWidget::OnProgress(const AnalysisProgress& Progress) {
    PhaseLabel->setText(StateToString(Progress.State));
    OverallProgress->setValue(Progress.Percentage);

    QString Stats;
    if (Progress.FunctionsFound > 0)
        Stats += QString("Func: %1  ").arg(FormatCount(Progress.FunctionsFound));
    Stats += QString("Insn: %1").arg(FormatCount(Progress.InstructionsDisassembled));
    if (Progress.StringsFound > 0)
        Stats += QString("  Str: %1").arg(FormatCount(Progress.StringsFound));
    if (Progress.XrefsBuilt > 0)
        Stats += QString("  Xref: %1").arg(FormatCount(Progress.XrefsBuilt));

    if (Progress.ElapsedMs > 1000 && Progress.InstructionsDisassembled > 0) {
        double Speed = static_cast<double>(Progress.InstructionsDisassembled) / (Progress.ElapsedMs / 1000.0);
        if (Speed > 1000000.0)
            Stats += QString("  [%1M/s]").arg(Speed / 1000000.0, 0, 'f', 1);
        else if (Speed > 1000.0)
            Stats += QString("  [%1K/s]").arg(Speed / 1000.0, 0, 'f', 0);
    }

    StatsLabel->setText(Stats);

    LastElapsedMs = Progress.ElapsedMs;
    ElapsedLabel->setText(FormatDuration(Progress.ElapsedMs));

    if (Progress.CurrentAddress > 0)
        NavBand->SetCurrentAddress(Progress.CurrentAddress);
}

void AnalysisProgressWidget::OnFinished(bool Success) {
    Finished = true;
    ElapsedTimer->stop();

    if (Success) {
        PhaseLabel->setText("Complete");
        PhaseLabel->setStyleSheet("font-weight: bold; color: #4ec9b0; font-size: 11px; border: none;");
        OverallProgress->setValue(100);
    } else {
        PhaseLabel->setText("Failed");
        PhaseLabel->setStyleSheet("font-weight: bold; color: #f44747; font-size: 11px; border: none;");
    }

    if (Db) {
        QString Stats = QString("Func: %1  Insn: %2  Str: %3  Xref: %4")
            .arg(FormatCount(Db->FunctionCount()))
            .arg(FormatCount(Db->InstructionCount()))
            .arg(FormatCount(Db->StringCount()))
            .arg(FormatCount(Db->XrefCount()));
        StatsLabel->setText(Stats);
    }
}

void AnalysisProgressWidget::Reset() {
    PhaseLabel->setText("Idle");
    PhaseLabel->setStyleSheet("font-weight: bold; color: #569cd6; font-size: 11px; border: none;");
    StatsLabel->setText("");
    OverallProgress->setValue(0);
    ElapsedLabel->setText("0:00");
    LastElapsedMs = 0;
    Finished = false;
    NavBand->SetSegments({});
}

QString AnalysisProgressWidget::FormatDuration(qint64 Ms) const {
    int TotalSec = static_cast<int>(Ms / 1000);
    int Hours = TotalSec / 3600;
    int Minutes = (TotalSec % 3600) / 60;
    int Seconds = TotalSec % 60;
    if (Hours > 0)
        return QString("%1:%2:%3").arg(Hours).arg(Minutes, 2, 10, QChar('0')).arg(Seconds, 2, 10, QChar('0'));
    return QString("%1:%2").arg(Minutes).arg(Seconds, 2, 10, QChar('0'));
}

QString AnalysisProgressWidget::FormatCount(int Count) const {
    if (Count >= 1000000)
        return QString("%1M").arg(Count / 1000000.0, 0, 'f', 1);
    if (Count >= 1000)
        return QString("%1K").arg(Count / 1000.0, 0, 'f', 1);
    return QString::number(Count);
}

QString AnalysisProgressWidget::StateToString(AnalysisState State) const {
    switch (State) {
        case AnalysisState::Idle: return "Idle";
        case AnalysisState::Loading: return "Loading";
        case AnalysisState::Disassembling: return "Disassembling";
        case AnalysisState::FindingFunctions: return "Finding Functions";
        case AnalysisState::BuildingXrefs: return "Building Xrefs";
        case AnalysisState::FindingStrings: return "Finding Strings";
        case AnalysisState::AnalyzingFunctions: return "Analyzing";
        case AnalysisState::Complete: return "Complete";
        case AnalysisState::Failed: return "Failed";
    }
    return "Unknown";
}

}
