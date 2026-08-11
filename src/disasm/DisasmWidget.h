#pragma once

#include <fidra/Types.h>
#include <fidra/ICore.h>
#include <QWidget>
#include <QTreeView>
#include <QAbstractTableModel>
#include <QStyledItemDelegate>
#include <QLineEdit>
#include <QPushButton>
#include <QList>
#include <QMap>
#include <QMenu>

namespace Fidra {

class Disassembler;
class AnalysisDatabase;

enum class OperandFormat {
    Default,
    Hex,
    Decimal,
    Octal,
    Binary,
    Char,
    Offset
};

class DisasmModel : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        ColAddress = 0,
        ColBytes,
        ColMnemonic,
        ColOperands,
        ColComment,
        ColCount
    };

    explicit DisasmModel(QObject* Parent = nullptr);

    int rowCount(const QModelIndex& Parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& Parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& Index, int Role = Qt::DisplayRole) const override;
    QVariant headerData(int Section, Qt::Orientation Orientation, int Role = Qt::DisplayRole) const override;

    void SetInstructions(const QList<DisasmInstruction>& NewInstructions);
    void Clear();
    DisasmInstruction GetInstruction(int Row) const;

    void SetFormatMap(const QMap<Address, QMap<int, OperandFormat>>* Map);
    void SetStackVarMap(const QMap<Address, QMap<int, QString>>* Map, Address CurrentFunc);

private:
    QString ApplyOperandFormats(Address Addr, const QString& OriginalOperands) const;
    QString ApplyStackVarSubstitution(Address InstrAddr, const QString& Operands) const;

    QList<DisasmInstruction> Instructions;
    const QMap<Address, QMap<int, OperandFormat>>* Formats = nullptr;
    const QMap<Address, QMap<int, QString>>* StackVars = nullptr;
    Address CurrentStackVarFunc = 0;
};

class DisasmHighlightDelegate : public QStyledItemDelegate {
    Q_OBJECT

public:
    explicit DisasmHighlightDelegate(QObject* Parent = nullptr);

    void paint(QPainter* Painter, const QStyleOptionViewItem& Option,
               const QModelIndex& Index) const override;

private:
    void PaintMnemonic(QPainter* Painter, const QStyleOptionViewItem& Option,
                       const QString& Text) const;
    void PaintOperands(QPainter* Painter, const QStyleOptionViewItem& Option,
                       const QString& Text) const;
    bool IsRegister(const QString& Token) const;
    bool IsHexNumber(const QString& Token) const;

    QColor ColorRegister;
    QColor ColorImmediate;
    QColor ColorMemory;
    QColor ColorJumpCall;
    QColor ColorRetNop;
    QColor ColorDefault;
    QSet<QString> RegisterNames;
};

class DisasmWidget : public QWidget {
    Q_OBJECT

public:
    explicit DisasmWidget(QWidget* Parent = nullptr);
    ~DisasmWidget() override;

    void SetCore(ICore* Core);
    void SetAnalysisDatabase(AnalysisDatabase* Db);
    void NavigateTo(Address Addr);
    void GoBack();
    void GoForward();
    void Refresh();

    void OnProcessAttached(const ProcessInfo& Info);
    void OnProcessDetached();

    void SetOperandFormat(Address Addr, int OperandIdx, OperandFormat Fmt);
    QString FormatImmediate(int64_t Value, OperandFormat Fmt) const;

    void ResolveStackVariables(Address FuncAddr);
    QString SubstituteStackVars(const QString& Operands, Address InstrAddr) const;

private:
    void DisassembleAt(Address Addr, size_t NumBytes = 4096);
    void DisassembleFromDatabase(Address Addr, size_t NumInsns = 500);
    void OnItemDoubleClicked(const QModelIndex& Index);
    void OnGoClicked();
    void ShowContextMenu(const QPoint& Pos);
    void BuildNumberFormatMenu(QMenu* ParentMenu, Address Addr, int OperandIdx);
    int DetectOperandIndexAtColumn(const QModelIndex& Index, const QPoint& Pos) const;

    QTreeView* TreeView;
    DisasmModel* Model;
    DisasmHighlightDelegate* HighlightDelegate;
    Disassembler* Engine;
    ICore* CorePtr;
    AnalysisDatabase* AnalysisDb;

    QLineEdit* AddressInput;
    QPushButton* GoButton;
    QPushButton* BackButton;
    QPushButton* ForwardButton;

    QList<Address> HistoryBack;
    QList<Address> HistoryForward;
    Address CurrentAddress;

    QMap<Address, QMap<int, OperandFormat>> OperandFormats;
    QMap<Address, QMap<int, QString>> StackVarNames;
};

}
