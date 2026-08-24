#include "UndoManager.h"
#include "../analysis/AnalysisDatabase.h"

namespace Fidra {

RenameCommand::RenameCommand(UndoManager* Manager, AnalysisDatabase* Db, Address Addr,
                             const QString& OldName, const QString& NewName)
    : QUndoCommand(QString("Rename 0x%1 to %2").arg(Addr, 0, 16).arg(NewName))
    , Mgr(Manager)
    , Database(Db)
    , TargetAddr(Addr)
    , PreviousName(OldName)
    , NextName(NewName) {
}

void RenameCommand::undo() {
    Database->SetName(TargetAddr, PreviousName);
    Mgr->EmitDatabaseModified(TargetAddr);
}

void RenameCommand::redo() {
    Database->SetName(TargetAddr, NextName);
    Mgr->EmitDatabaseModified(TargetAddr);
}

CommentCommand::CommentCommand(UndoManager* Manager, AnalysisDatabase* Db, Address Addr,
                               const QString& OldComment, const QString& NewComment)
    : QUndoCommand(QString("Comment at 0x%1").arg(Addr, 0, 16))
    , Mgr(Manager)
    , Database(Db)
    , TargetAddr(Addr)
    , PreviousComment(OldComment)
    , NextComment(NewComment) {
}

void CommentCommand::undo() {
    Database->SetComment(TargetAddr, PreviousComment);
    Mgr->EmitDatabaseModified(TargetAddr);
}

void CommentCommand::redo() {
    Database->SetComment(TargetAddr, NextComment);
    Mgr->EmitDatabaseModified(TargetAddr);
}

TypeChangeCommand::TypeChangeCommand(UndoManager* Manager, AnalysisDatabase* Db, Address Addr,
                                     ItemType OldType, ItemType NewType)
    : QUndoCommand(QString("Change type at 0x%1").arg(Addr, 0, 16))
    , Mgr(Manager)
    , Database(Db)
    , TargetAddr(Addr)
    , PreviousType(OldType)
    , NextType(NewType) {
}

void TypeChangeCommand::undo() {
    Database->SetItemType(TargetAddr, PreviousType);
    Mgr->EmitDatabaseModified(TargetAddr);
}

void TypeChangeCommand::redo() {
    Database->SetItemType(TargetAddr, NextType);
    Mgr->EmitDatabaseModified(TargetAddr);
}

PatchCommand::PatchCommand(UndoManager* Manager, AnalysisDatabase* Db, Address Addr,
                           const QByteArray& OldBytes, const QByteArray& NewBytes)
    : QUndoCommand(QString("Patch %1 bytes at 0x%2").arg(NewBytes.size()).arg(Addr, 0, 16))
    , Mgr(Manager)
    , Database(Db)
    , TargetAddr(Addr)
    , PreviousBytes(OldBytes)
    , NextBytes(NewBytes) {
}

void PatchCommand::undo() {
    WriteSegmentBytes(PreviousBytes);
    Mgr->EmitDatabaseModified(TargetAddr);
}

void PatchCommand::redo() {
    WriteSegmentBytes(NextBytes);
    Mgr->EmitDatabaseModified(TargetAddr);
}

void PatchCommand::WriteSegmentBytes(const QByteArray& Bytes) {
    BinaryInfo Info = Database->GetBinaryInfo();
    for (int I = 0; I < Info.Segments.size(); ++I) {
        Segment& Seg = Info.Segments[I];
        if (TargetAddr >= Seg.VirtualAddress &&
            TargetAddr + static_cast<Address>(Bytes.size()) <= Seg.VirtualAddress + Seg.VirtualSize) {
            size_t SegOffset = static_cast<size_t>(TargetAddr - Seg.VirtualAddress);
            if (static_cast<int>(SegOffset + Bytes.size()) <= Seg.Data.size()) {
                memcpy(Seg.Data.data() + SegOffset, Bytes.constData(), Bytes.size());
                Database->SetBinaryInfo(Info);
            }
            return;
        }
    }
}

FunctionBoundaryCommand::FunctionBoundaryCommand(UndoManager* Manager, AnalysisDatabase* Db,
                                                 Address Addr, Address OldEnd, Address NewEnd)
    : QUndoCommand(QString("Resize function at 0x%1").arg(Addr, 0, 16))
    , Mgr(Manager)
    , Database(Db)
    , TargetAddr(Addr)
    , PreviousEnd(OldEnd)
    , NextEnd(NewEnd) {
}

void FunctionBoundaryCommand::undo() {
    SetFunctionEnd(PreviousEnd);
    Mgr->EmitDatabaseModified(TargetAddr);
}

void FunctionBoundaryCommand::redo() {
    SetFunctionEnd(NextEnd);
    Mgr->EmitDatabaseModified(TargetAddr);
}

void FunctionBoundaryCommand::SetFunctionEnd(Address EndAddr) {
    AnalyzedFunction Func = Database->GetFunction(TargetAddr);
    if (Func.Start == TargetAddr) {
        Func.End = EndAddr;
        Func.Size = static_cast<size_t>(EndAddr - TargetAddr);
        Database->UpdateFunction(TargetAddr, Func);
    }
}

UndoManager::UndoManager(QObject* Parent)
    : QObject(Parent)
    , UndoStack(new QUndoStack(this)) {
    connect(UndoStack, &QUndoStack::canUndoChanged, this, &UndoManager::UndoRedoChanged);
    connect(UndoStack, &QUndoStack::canRedoChanged, this, &UndoManager::UndoRedoChanged);
    connect(UndoStack, &QUndoStack::indexChanged, this, &UndoManager::UndoRedoChanged);
}

QUndoStack* UndoManager::Stack() const {
    return UndoStack;
}

void UndoManager::PushRename(AnalysisDatabase* Db, Address Addr,
                             const QString& OldName, const QString& NewName) {
    UndoStack->push(new RenameCommand(this, Db, Addr, OldName, NewName));
}

void UndoManager::PushComment(AnalysisDatabase* Db, Address Addr,
                              const QString& OldComment, const QString& NewComment) {
    UndoStack->push(new CommentCommand(this, Db, Addr, OldComment, NewComment));
}

void UndoManager::PushTypeChange(AnalysisDatabase* Db, Address Addr,
                                 ItemType OldType, ItemType NewType) {
    UndoStack->push(new TypeChangeCommand(this, Db, Addr, OldType, NewType));
}

void UndoManager::PushPatch(AnalysisDatabase* Db, Address Addr,
                            const QByteArray& OldBytes, const QByteArray& NewBytes) {
    UndoStack->push(new PatchCommand(this, Db, Addr, OldBytes, NewBytes));
}

void UndoManager::PushFunctionBoundary(AnalysisDatabase* Db, Address Addr,
                                       Address OldEnd, Address NewEnd) {
    UndoStack->push(new FunctionBoundaryCommand(this, Db, Addr, OldEnd, NewEnd));
}

void UndoManager::Undo() {
    if (UndoStack->canUndo()) {
        UndoStack->undo();
    }
}

void UndoManager::Redo() {
    if (UndoStack->canRedo()) {
        UndoStack->redo();
    }
}

bool UndoManager::CanUndo() const {
    return UndoStack->canUndo();
}

bool UndoManager::CanRedo() const {
    return UndoStack->canRedo();
}

QString UndoManager::UndoText() const {
    return UndoStack->undoText();
}

QString UndoManager::RedoText() const {
    return UndoStack->redoText();
}

void UndoManager::Clear() {
    UndoStack->clear();
}

int UndoManager::Count() const {
    return UndoStack->count();
}

void UndoManager::EmitDatabaseModified(Address Addr) {
    emit DatabaseModified(Addr);
}

}
