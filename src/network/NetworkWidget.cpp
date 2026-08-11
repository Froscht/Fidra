#include "NetworkWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QFont>
#include <QScrollBar>
#include <QTextCursor>
#include <QTextCharFormat>
#include <QApplication>

namespace Fidra {

NetworkWidget::NetworkWidget(QWidget* Parent)
    : QWidget(Parent)
    , CoreRef(nullptr)
    , ToolBar(nullptr)
    , StartStopAction(nullptr)
    , InterfaceCombo(nullptr)
    , FilterInput(nullptr)
    , FilterApplyBtn(nullptr)
    , FilterClearBtn(nullptr)
    , StatusLabel(nullptr)
    , MainSplitter(nullptr)
    , BottomSplitter(nullptr)
    , PacketTable(nullptr)
    , DetailTree(nullptr)
    , HexView(nullptr)
    , Model(nullptr)
    , Capture(nullptr)
    , CaptureActive(false)
    , PacketCount(0) {
    Model = new PacketModel(this);
    Capture = new PacketCapture(this);
    SetupUi();
    SetupToolbar();
    PopulateInterfaces();

    connect(Capture, &PacketCapture::PacketCaptured, this, &NetworkWidget::OnPacketCaptured, Qt::QueuedConnection);
    connect(Capture, &PacketCapture::Error, this, &NetworkWidget::OnCaptureError);
    connect(Capture, &PacketCapture::CaptureStopped, this, [this]() {
        CaptureActive = false;
        StartStopAction->setText("Start");
        StartStopAction->setIcon(style()->standardIcon(QStyle::SP_MediaPlay));
        UpdateStatusLabel();
    });
}

NetworkWidget::~NetworkWidget() {
    if (CaptureActive) {
        Capture->Stop();
    }
}

void NetworkWidget::SetCore(ICore* Core) {
    CoreRef = Core;
}

void NetworkWidget::SetupUi() {
    QVBoxLayout* Layout = new QVBoxLayout(this);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(0);

    ToolBar = new QToolBar(this);
    ToolBar->setMovable(false);
    ToolBar->setIconSize(QSize(16, 16));
    Layout->addWidget(ToolBar);

    QWidget* FilterBar = new QWidget(this);
    QHBoxLayout* FilterLayout = new QHBoxLayout(FilterBar);
    FilterLayout->setContentsMargins(4, 2, 4, 2);
    FilterLayout->setSpacing(4);

    QLabel* FilterLabel = new QLabel("Filter:", FilterBar);
    FilterLayout->addWidget(FilterLabel);

    FilterInput = new QLineEdit(FilterBar);
    FilterInput->setPlaceholderText("Display filter (e.g. tcp, udp, ip.src==192.168.1.1, tcp.port==80)");
    FilterInput->setFont(QFont("Consolas", 9));
    FilterLayout->addWidget(FilterInput);

    FilterApplyBtn = new QPushButton("Apply", FilterBar);
    FilterApplyBtn->setFixedWidth(60);
    FilterLayout->addWidget(FilterApplyBtn);

    FilterClearBtn = new QPushButton("Clear", FilterBar);
    FilterClearBtn->setFixedWidth(60);
    FilterLayout->addWidget(FilterClearBtn);

    Layout->addWidget(FilterBar);

    MainSplitter = new QSplitter(Qt::Vertical, this);
    PacketTable = new QTableView(MainSplitter);
    PacketTable->setModel(Model);
    PacketTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    PacketTable->setSelectionMode(QAbstractItemView::SingleSelection);
    PacketTable->setAlternatingRowColors(true);
    PacketTable->setSortingEnabled(true);
    PacketTable->setShowGrid(false);
    PacketTable->verticalHeader()->hide();
    PacketTable->verticalHeader()->setDefaultSectionSize(20);
    PacketTable->horizontalHeader()->setStretchLastSection(true);
    PacketTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    PacketTable->setFont(QFont("Consolas", 9));

    PacketTable->setColumnWidth(PacketModel::ColNumber, 60);
    PacketTable->setColumnWidth(PacketModel::ColTime, 100);
    PacketTable->setColumnWidth(PacketModel::ColSource, 160);
    PacketTable->setColumnWidth(PacketModel::ColDestination, 160);
    PacketTable->setColumnWidth(PacketModel::ColProtocol, 70);
    PacketTable->setColumnWidth(PacketModel::ColLength, 60);

    MainSplitter->addWidget(PacketTable);

    BottomSplitter = new QSplitter(Qt::Horizontal, MainSplitter);

    DetailTree = new QTreeWidget(BottomSplitter);
    DetailTree->setHeaderHidden(true);
    DetailTree->setFont(QFont("Consolas", 9));
    DetailTree->setIndentation(16);
    DetailTree->setAnimated(true);
    BottomSplitter->addWidget(DetailTree);

    HexView = new QTextEdit(BottomSplitter);
    HexView->setReadOnly(true);
    HexView->setFont(QFont("Consolas", 9));
    HexView->setLineWrapMode(QTextEdit::NoWrap);
    HexView->setStyleSheet("QTextEdit { background-color: #1a1a2e; color: #cccccc; }");
    BottomSplitter->addWidget(HexView);

    BottomSplitter->setSizes({400, 400});
    MainSplitter->addWidget(BottomSplitter);
    MainSplitter->setSizes({400, 300});

    Layout->addWidget(MainSplitter);

    StatusLabel = new QLabel("Ready", this);
    StatusLabel->setContentsMargins(6, 2, 6, 2);
    StatusLabel->setFont(QFont("Consolas", 8));
    Layout->addWidget(StatusLabel);

    connect(PacketTable->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, &NetworkWidget::OnPacketSelected);
    connect(FilterApplyBtn, &QPushButton::clicked, this, &NetworkWidget::OnFilterApplied);
    connect(FilterClearBtn, &QPushButton::clicked, this, [this]() {
        FilterInput->clear();
        Model->SetDisplayFilter("");
        UpdateStatusLabel();
    });
    connect(FilterInput, &QLineEdit::returnPressed, this, &NetworkWidget::OnFilterApplied);

    connect(DetailTree, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* Current, QTreeWidgetItem*) {
        if (!Current) return;
        int Offset = Current->data(0, Qt::UserRole).toInt();
        int Length = Current->data(0, Qt::UserRole + 1).toInt();
        if (Length > 0) {
            HighlightHexRange(Offset, Length);
        }
    });
}

void NetworkWidget::SetupToolbar() {
    StartStopAction = ToolBar->addAction(style()->standardIcon(QStyle::SP_MediaPlay), "Start");
    connect(StartStopAction, &QAction::triggered, this, &NetworkWidget::OnStartStopCapture);

    ToolBar->addSeparator();

    QLabel* IfaceLabel = new QLabel(" Interface: ", ToolBar);
    ToolBar->addWidget(IfaceLabel);

    InterfaceCombo = new QComboBox(ToolBar);
    InterfaceCombo->setMinimumWidth(200);
    ToolBar->addWidget(InterfaceCombo);

    QAction* RefreshAction = ToolBar->addAction(style()->standardIcon(QStyle::SP_BrowserReload), "Refresh");
    connect(RefreshAction, &QAction::triggered, this, &NetworkWidget::PopulateInterfaces);

    ToolBar->addSeparator();

    QAction* ClearAction = ToolBar->addAction(style()->standardIcon(QStyle::SP_DialogResetButton), "Clear");
    connect(ClearAction, &QAction::triggered, this, &NetworkWidget::OnClearPackets);

    ToolBar->addSeparator();

    QAction* SaveAction = ToolBar->addAction(style()->standardIcon(QStyle::SP_DialogSaveButton), "Save PCAP");
    connect(SaveAction, &QAction::triggered, this, &NetworkWidget::OnSavePcap);

    QAction* LoadAction = ToolBar->addAction(style()->standardIcon(QStyle::SP_DialogOpenButton), "Load PCAP");
    connect(LoadAction, &QAction::triggered, this, &NetworkWidget::OnLoadPcap);
}

void NetworkWidget::PopulateInterfaces() {
    InterfaceCombo->clear();
    QStringList Interfaces = Capture->GetAvailableInterfaces();
    for (const auto& Iface : Interfaces) {
        InterfaceCombo->addItem(Iface);
    }
}

void NetworkWidget::OnStartStopCapture() {
    if (CaptureActive) {
        Capture->Stop();
        CaptureActive = false;
        StartStopAction->setText("Start");
        StartStopAction->setIcon(style()->standardIcon(QStyle::SP_MediaPlay));
    } else {
        QString InterfaceText = InterfaceCombo->currentText();
        QString InterfaceName;

        int ParenStart = InterfaceText.indexOf('(');
        int ParenEnd = InterfaceText.indexOf(')');
        if (ParenStart >= 0 && ParenEnd > ParenStart) {
            InterfaceName = InterfaceText.mid(ParenStart + 1, ParenEnd - ParenStart - 1);
        } else {
            InterfaceName = InterfaceText;
        }

        Capture->Start(InterfaceName);
        CaptureActive = true;
        StartStopAction->setText("Stop");
        StartStopAction->setIcon(style()->standardIcon(QStyle::SP_MediaStop));
    }
    UpdateStatusLabel();
}

void NetworkWidget::OnPacketCaptured(const NetworkPacket& Packet) {
    Model->AddPacket(Packet);
    PacketCount++;

    if (PacketCount % 100 == 0) {
        UpdateStatusLabel();
    }
}

void NetworkWidget::OnPacketSelected(const QModelIndex& Index) {
    if (!Index.isValid()) return;
    ShowPacketDetail(Index.row());
}

void NetworkWidget::OnFilterApplied() {
    QString Filter = FilterInput->text().trimmed();
    Model->SetDisplayFilter(Filter);
    UpdateStatusLabel();

    if (!Filter.isEmpty()) {
        FilterInput->setStyleSheet("QLineEdit { background-color: #1a3a1a; }");
    } else {
        FilterInput->setStyleSheet("");
    }
}

void NetworkWidget::OnClearPackets() {
    Model->Clear();
    DetailTree->clear();
    HexView->clear();
    PacketCount = 0;
    UpdateStatusLabel();
}

void NetworkWidget::OnSavePcap() {
    QString FilePath = QFileDialog::getSaveFileName(this, "Save PCAP File", QString(), "PCAP Files (*.pcap);;All Files (*)");
    if (FilePath.isEmpty()) return;

    QList<NetworkPacket> Packets;
    for (int I = 0; I < Model->DisplayedPacketCount(); ++I) {
        Packets.append(Model->GetPacket(I));
    }

    if (Capture->SaveToPcap(FilePath, Packets)) {
        if (CoreRef) {
            CoreRef->Log(QString("Saved %1 packets to %2").arg(Packets.size()).arg(FilePath), LogLevel::Info);
        }
    }
}

void NetworkWidget::OnLoadPcap() {
    QString FilePath = QFileDialog::getOpenFileName(this, "Open PCAP File", QString(), "PCAP Files (*.pcap *.cap);;All Files (*)");
    if (FilePath.isEmpty()) return;

    QList<NetworkPacket> Packets = Capture->LoadFromPcap(FilePath);
    if (!Packets.isEmpty()) {
        Model->Clear();
        Model->AddPackets(Packets);
        PacketCount = Packets.size();
        UpdateStatusLabel();

        if (CoreRef) {
            CoreRef->Log(QString("Loaded %1 packets from %2").arg(Packets.size()).arg(FilePath), LogLevel::Info);
        }
    }
}

void NetworkWidget::OnCaptureError(const QString& Message) {
    if (CoreRef) {
        CoreRef->Log("Capture error: " + Message, LogLevel::Error);
    }
    StatusLabel->setText("Error: " + Message);
}

void NetworkWidget::UpdateStatusLabel() {
    QString Status;
    if (CaptureActive) {
        Status = "Capturing";
    } else {
        Status = "Stopped";
    }

    int Total = Model->TotalPacketCount();
    int Displayed = Model->DisplayedPacketCount();

    if (Total == Displayed) {
        Status += QString(" | Packets: %1").arg(Total);
    } else {
        Status += QString(" | Displayed: %1 of %2").arg(Displayed).arg(Total);
    }

    StatusLabel->setText(Status);
}

void NetworkWidget::ShowPacketDetail(int Row) {
    DetailTree->clear();
    HexView->clear();

    DissectedPacket Dissection = Model->GetDissection(Row);
    QByteArray RawData = Model->GetPacketData(Row);

    for (const auto& Layer : Dissection.Layers) {
        QTreeWidgetItem* LayerItem = new QTreeWidgetItem(DetailTree);
        LayerItem->setText(0, QString("%1, Len: %2").arg(Layer.Protocol).arg(Layer.Length));
        LayerItem->setData(0, Qt::UserRole, Layer.Offset);
        LayerItem->setData(0, Qt::UserRole + 1, Layer.Length);
        LayerItem->setExpanded(true);

        QFont BoldFont = LayerItem->font(0);
        BoldFont.setBold(true);
        LayerItem->setFont(0, BoldFont);

        AddFieldsToTree(LayerItem, Layer.Fields);
    }

    ShowHexDump(RawData);
}

void NetworkWidget::AddFieldsToTree(QTreeWidgetItem* Parent, const QList<DissectedField>& Fields) {
    for (const auto& Field : Fields) {
        QTreeWidgetItem* Item = new QTreeWidgetItem(Parent);
        Item->setText(0, QString("%1: %2").arg(Field.Name, Field.Value));
        Item->setData(0, Qt::UserRole, Field.Offset);
        Item->setData(0, Qt::UserRole + 1, Field.Length);

        if (!Field.Children.isEmpty()) {
            AddFieldsToTree(Item, Field.Children);
        }
    }
}

void NetworkWidget::ShowHexDump(const QByteArray& Data) {
    if (Data.isEmpty()) return;

    QString HexText;
    int BytesPerLine = 16;

    for (int Offset = 0; Offset < Data.size(); Offset += BytesPerLine) {
        QString OffsetStr = QString("%1  ").arg(Offset, 8, 16, QChar('0'));

        QString HexPart;
        QString AsciiPart;

        for (int I = 0; I < BytesPerLine; ++I) {
            if (Offset + I < Data.size()) {
                uint8_t Byte = static_cast<uint8_t>(Data[Offset + I]);
                HexPart += QString("%1 ").arg(Byte, 2, 16, QChar('0'));

                if (Byte >= 0x20 && Byte <= 0x7E) {
                    AsciiPart += QChar(Byte);
                } else {
                    AsciiPart += '.';
                }
            } else {
                HexPart += "   ";
                AsciiPart += ' ';
            }

            if (I == 7) {
                HexPart += ' ';
            }
        }

        HexText += OffsetStr + HexPart + " |" + AsciiPart + "|\n";
    }

    HexView->setPlainText(HexText);
}

void NetworkWidget::HighlightHexRange(int Offset, int Length) {
    if (Length <= 0 || Offset < 0) return;

    QByteArray CurrentData;
    auto Selection = PacketTable->selectionModel()->selectedRows();
    if (!Selection.isEmpty()) {
        CurrentData = Model->GetPacketData(Selection[0].row());
    }
    if (CurrentData.isEmpty()) return;

    ShowHexDump(CurrentData);

    QTextCursor Cursor = HexView->textCursor();
    QTextCharFormat HighlightFormat;
    HighlightFormat.setBackground(QColor(38, 79, 120));
    HighlightFormat.setForeground(QColor(255, 255, 255));

    int BytesPerLine = 16;

    for (int I = 0; I < Length && (Offset + I) < CurrentData.size(); ++I) {
        int BytePos = Offset + I;
        int LineNum = BytePos / BytesPerLine;
        int ColInLine = BytePos % BytesPerLine;

        int LineStart = 0;
        for (int L = 0; L < LineNum; ++L) {
            LineStart += 10 + (BytesPerLine * 3) + 1 + 2 + BytesPerLine + 2;
        }

        int HexCharPos = LineStart + 10 + (ColInLine * 3);
        if (ColInLine > 7) HexCharPos += 1;

        Cursor.setPosition(HexCharPos);
        Cursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, 2);
        Cursor.mergeCharFormat(HighlightFormat);
    }
}

}
