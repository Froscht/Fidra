#pragma once

#include <fidra/Types.h>
#include <QByteArray>
#include <QList>
#include <capstone/capstone.h>

namespace Fidra {

class Disassembler {
public:
    Disassembler();
    ~Disassembler();

    bool SetArchitecture(Architecture Arch);
    Architecture GetArchitecture() const;

    QList<DisasmInstruction> Disassemble(const QByteArray& Data, Address StartAddress, size_t MaxInstructions = 0);
    QList<DisasmInstruction> DisassembleOne(const QByteArray& Data, Address StartAddress);

    bool IsOpen() const;
    QString LastError() const;

private:
    void Close();

    csh Handle;
    bool HandleOpen;
    Architecture CurrentArch;
    QString ErrorMsg;
};

}
