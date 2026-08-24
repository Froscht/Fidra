#pragma once

#include <QObject>
#include <QUndoStack>
#include <QUndoCommand>
#include <fidra/Types.h>
#include "../analysis/AnalysisTypes.h"

namespace Fidra {

class AnalysisDatabase;
class UndoManager;

class RenameCommand : public QUndoCommand {
public:
    RenameCommand(UndoManager* Manager, AnalysisDatabase* Db, Address Addr,
                  const QString& OldName, const QString& NewName);
    void undo() override;
    void redo() override;

private:
    UndoManager* Mgr;
    AnalysisDatabase* Database;
    Address TargetAddr;
    QString PreviousName;
    QString NextName;
};

class CommentCommand : public QUndoCommand {
public:
    CommentCommand(UndoManager* Manager, AnalysisDatabase* Db, Address Addr,
                   const QString& OldComment, const QString& NewComment);
    void undo() override;
    void redo() override;

private:
    UndoManager* Mgr;
    AnalysisDatabase* Database;
    Address TargetAddr;
    QString PreviousComment;
    QString NextComment;
};

class TypeChangeCommand : public QUndoCommand {
public:
    TypeChangeCommand(UndoManager* Manager, AnalysisDatabase* Db, Address Addr,
                      ItemType OldType, ItemType NewType);
    void undo() override;
    void redo() override;

private:
    UndoManager* Mgr;
    AnalysisDatabase* Database;
    Address TargetAddr;
    ItemType PreviousType;
    ItemType NextType;
};

class PatchCommand : public QUndoCommand {
public:
    PatchCommand(UndoManager* Manager, AnalysisDatabase* Db, Address Addr,
                 const QByteArray& OldBytes, const QByteArray& NewBytes);
    void undo() override;
    void redo() override;

private:
    void WriteSegmentBytes(const QByteArray& Bytes);

    UndoManager* Mgr;
    AnalysisDatabase* Database;
    Address TargetAddr;
    QByteArray PreviousBytes;
    QByteArray NextBytes;
};

class FunctionBoundaryCommand : public QUndoCommand {
public:
    FunctionBoundaryCommand(UndoManager* Manager, AnalysisDatabase* Db, Address Addr,
                            Address OldEnd, Address NewEnd);
    void undo() override;
    void redo() override;

private:
    void SetFunctionEnd(Address EndAddr);

    UndoManager* Mgr;
    AnalysisDatabase* Database;
    Address TargetAddr;
    Address PreviousEnd;
    Address NextEnd;
};

class UndoManager : public QObject {
    Q_OBJECT

public:
    explicit UndoManager(QObject* Parent = nullptr);

    QUndoStack* Stack() const;

    void PushRename(AnalysisDatabase* Db, Address Addr, const QString& OldName, const QString& NewName);
    void PushComment(AnalysisDatabase* Db, Address Addr, const QString& OldComment, const QString& NewComment);
    void PushTypeChange(AnalysisDatabase* Db, Address Addr, ItemType OldType, ItemType NewType);
    void PushPatch(AnalysisDatabase* Db, Address Addr, const QByteArray& OldBytes, const QByteArray& NewBytes);
    void PushFunctionBoundary(AnalysisDatabase* Db, Address Addr, Address OldEnd, Address NewEnd);

    void Undo();
    void Redo();
    bool CanUndo() const;
    bool CanRedo() const;
    QString UndoText() const;
    QString RedoText() const;

    void Clear();
    int Count() const;

    void EmitDatabaseModified(Address Addr);

signals:
    void UndoRedoChanged();
    void DatabaseModified(Address Addr);

private:
    QUndoStack* UndoStack;
};

}
