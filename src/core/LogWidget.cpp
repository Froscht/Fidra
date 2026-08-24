#include "LogWidget.h"
#include <QDateTime>
#include <QScrollBar>

namespace Fidra {

LogWidget::LogWidget(QWidget* Parent)
    : QWidget(Parent)
    , Output(new QTextEdit(this))
    , LevelFilter(new QComboBox(this))
    , MinLevel(LogLevel::Debug)
{
    auto* Layout = new QVBoxLayout(this);
    Layout->setContentsMargins(0, 0, 0, 0);
    Layout->setSpacing(2);

    auto* ToolbarLayout = new QHBoxLayout();
    ToolbarLayout->setContentsMargins(4, 2, 4, 2);

    LevelFilter->addItem("Debug", static_cast<int>(LogLevel::Debug));
    LevelFilter->addItem("Info", static_cast<int>(LogLevel::Info));
    LevelFilter->addItem("Warning", static_cast<int>(LogLevel::Warning));
    LevelFilter->addItem("Error", static_cast<int>(LogLevel::Error));
    LevelFilter->setCurrentIndex(0);
    ToolbarLayout->addWidget(LevelFilter);

    auto* ClearBtn = new QPushButton("Clear", this);
    ClearBtn->setFixedWidth(60);
    ToolbarLayout->addStretch();
    ToolbarLayout->addWidget(ClearBtn);

    Layout->addLayout(ToolbarLayout);

    Output->setReadOnly(true);
    Output->setFont(QFont("Consolas", 9));
    Output->setLineWrapMode(QTextEdit::NoWrap);
    Layout->addWidget(Output);

    connect(ClearBtn, &QPushButton::clicked, this, &LogWidget::Clear);
    connect(LevelFilter, QOverload<int>::of(&QComboBox::currentIndexChanged), [this](int Index) {
        MinLevel = static_cast<LogLevel>(LevelFilter->itemData(Index).toInt());
    });
}

void LogWidget::AppendMessage(const QString& Message, LogLevel Level) {
    if (Level < MinLevel) return;

    QString Timestamp = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    QString LevelStr;
    QString Color;

    switch (Level) {
        case LogLevel::Debug:   LevelStr = "DBG"; Color = "#888888"; break;
        case LogLevel::Info:    LevelStr = "INF"; Color = "#cccccc"; break;
        case LogLevel::Warning: LevelStr = "WRN"; Color = "#e6a817"; break;
        case LogLevel::Error:   LevelStr = "ERR"; Color = "#e63946"; break;
    }

    Output->append(QString("<span style='color:#666'>%1</span> <span style='color:%2'>[%3]</span> %4")
        .arg(Timestamp, Color, LevelStr, Message.toHtmlEscaped()));

    auto* ScrollBar = Output->verticalScrollBar();
    ScrollBar->setValue(ScrollBar->maximum());
}

void LogWidget::Clear() {
    Output->clear();
}

}
