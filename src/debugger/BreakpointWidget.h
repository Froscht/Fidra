#pragma once

#include "DebugEngine.h"
#include <QWidget>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QToolBar>

namespace Fidra {

class BreakpointWidget : public QWidget {
    Q_OBJECT

public:
    explicit BreakpointWidget(QWidget* Parent = nullptr);
    ~BreakpointWidget() override = default;

    void SetEngine(DebugEngine* Engine);

public slots:
    void UpdateBreakpoints();

private:
    void SetupToolBar();
    void SetupTable();
    void SetupContextMenu();

    void OnAddBreakpoint();
    void OnRemoveBreakpoint();
    void OnEnableAll();
    void OnDisableAll();
    void OnClearAll();
    void OnEditCondition();
    void OnToggleSelected();
    void OnContextMenu(const QPoint& Pos);

    DebugEngine* EngineRef;
    QVBoxLayout* Layout;
    QToolBar* ToolBar;
    QTableWidget* Table;
};

}
