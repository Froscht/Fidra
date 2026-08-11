#pragma once

#include "DebugEngine.h"
#include <QWidget>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>
#include <QMap>

namespace Fidra {

class RegisterWidget : public QWidget {
    Q_OBJECT

public:
    explicit RegisterWidget(QWidget* Parent = nullptr);
    ~RegisterWidget() override = default;

    void SetEngine(DebugEngine* Engine);

public slots:
    void UpdateRegisters();
    void OnStateChanged(DebugState NewState);

private:
    void BuildTree();
    void SetRegisterValue(QTreeWidgetItem* Item, const QString& Name, uint64_t Value, uint64_t PrevValue, bool Is16Bit = false);
    void UpdateFlagBits(QTreeWidgetItem* FlagsItem, uint64_t Rflags, uint64_t PrevRflags);
    void ClearAll();

    void OnItemDoubleClicked(QTreeWidgetItem* Item, int Column);

    DebugEngine* EngineRef;
    QVBoxLayout* Layout;
    QTreeWidget* Tree;

    QTreeWidgetItem* GpGroup;
    QTreeWidgetItem* FlagsGroup;
    QTreeWidgetItem* SegmentGroup;
    QTreeWidgetItem* XmmGroup;

    QMap<QString, QTreeWidgetItem*> RegisterItems;
    RegisterSet PreviousRegisters;
    bool HasPrevious;
};

}
