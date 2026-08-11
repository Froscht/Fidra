#pragma once

#include "DebugEngine.h"
#include <QWidget>
#include <QSplitter>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QLabel>

namespace Fidra {

class StackWidget : public QWidget {
    Q_OBJECT

public:
    explicit StackWidget(QWidget* Parent = nullptr);
    ~StackWidget() override = default;

    void SetEngine(DebugEngine* Engine);

public slots:
    void UpdateStack();
    void OnStateChanged(DebugState NewState);

private:
    void SetupCallStackTable();
    void SetupRawStackTable();
    void UpdateCallStack();
    void UpdateRawStack();
    void ClearAll();

    DebugEngine* EngineRef;
    QVBoxLayout* Layout;
    QSplitter* Splitter;

    QWidget* CallStackContainer;
    QVBoxLayout* CallStackLayout;
    QLabel* CallStackLabel;
    QTableWidget* CallStackTable;

    QWidget* RawStackContainer;
    QVBoxLayout* RawStackLayout;
    QLabel* RawStackLabel;
    QTableWidget* RawStackTable;

    static constexpr int RawStackBytes = 512;
};

}
