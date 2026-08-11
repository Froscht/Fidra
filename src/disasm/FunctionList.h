#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QTreeWidget>
#include <QLineEdit>
#include <QList>

namespace Fidra {

class ICore;
class Disassembler;
class AnalysisDatabase;

struct FunctionEntry {
    Address StartAddress;
    Address EndAddress;
    QString Name;
    size_t Size;
};

class FunctionList : public QWidget {
    Q_OBJECT

public:
    explicit FunctionList(QWidget* Parent = nullptr);
    ~FunctionList() override;

    void SetCore(ICore* Core);
    void OnProcessAttached(const ProcessInfo& Info);
    void OnProcessDetached();
    void AnalyzeFunctions(Address StartAddr, size_t Size);
    void LoadFromAnalysisDatabase(AnalysisDatabase* Db);

signals:
    void FunctionSelected(Address Addr);

private slots:
    void OnItemDoubleClicked(QTreeWidgetItem* Item, int Column);
    void OnFilterChanged(const QString& Text);

private:
    void PopulateList();
    void DetectFunctions(const QByteArray& Data, Address BaseAddr);

    ICore* CorePtr;
    QTreeWidget* TreeWidget;
    QLineEdit* FilterInput;
    QList<FunctionEntry> Functions;
};

}
