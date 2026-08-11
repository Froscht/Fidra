#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QTreeView>
#include <QLineEdit>
#include <QList>
#include <QAbstractTableModel>
#include <QSortFilterProxyModel>

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

class FunctionTableModel : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column { ColName = 0, ColAddress, ColSize, ColEndAddress, ColCount };

    explicit FunctionTableModel(QObject* Parent = nullptr);

    int rowCount(const QModelIndex& Parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& Parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& Index, int Role = Qt::DisplayRole) const override;
    QVariant headerData(int Section, Qt::Orientation Orientation, int Role = Qt::DisplayRole) const override;

    void SetFunctions(QList<FunctionEntry>&& Funcs);
    void Clear();
    Address AddressAt(int Row) const;

private:
    QList<FunctionEntry> Functions;
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
    void OnItemDoubleClicked(const QModelIndex& Index);
    void OnFilterChanged(const QString& Text);

private:
    void DetectFunctions(const QByteArray& Data, Address BaseAddr);

    ICore* CorePtr;
    QTreeView* TreeView;
    QLineEdit* FilterInput;
    FunctionTableModel* Model;
    QSortFilterProxyModel* ProxyModel;
    QList<FunctionEntry> Functions;
};

}
