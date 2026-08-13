#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QComboBox>

namespace Fidra {

class LogWidget : public QWidget {
    Q_OBJECT

public:
    explicit LogWidget(QWidget* Parent = nullptr);
    void AppendMessage(const QString& Message, LogLevel Level);
    void Clear();

private:
    QTextEdit* Output;
    QComboBox* LevelFilter;
    LogLevel MinLevel;
};

}
