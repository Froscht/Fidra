#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QTableWidget>
#include <QToolButton>
#include <QByteArray>
#include <QFont>

namespace Fidra {

class AnalysisDatabase;

class DataInspector : public QWidget {
    Q_OBJECT

public:
    explicit DataInspector(QWidget* Parent = nullptr);
    ~DataInspector() override;

    void InspectAddress(AnalysisDatabase* Db, Address Addr);
    void SetEndianness(bool BigEndian);
    bool IsBigEndian() const;

signals:
    void BytesModified(Address Addr, const QByteArray& NewBytes);

private slots:
    void OnCellChanged(int Row, int Column);
    void OnToggleEndianness();

private:
    enum RowIndex {
        RowInt8 = 0,
        RowUInt8,
        RowInt16LE,
        RowUInt16LE,
        RowInt16BE,
        RowUInt16BE,
        RowInt32LE,
        RowUInt32LE,
        RowInt32BE,
        RowUInt32BE,
        RowInt64LE,
        RowUInt64LE,
        RowInt64BE,
        RowUInt64BE,
        RowFloatLE,
        RowFloatBE,
        RowDoubleLE,
        RowDoubleBE,
        RowAscii,
        RowUtf8,
        RowUtf16LE,
        RowUtf16BE,
        RowBinary,
        RowOctal,
        RowUnixTime32,
        RowUnixTime64,
        RowFileTime,
        RowDosDateTime,
        RowGuid,
        RowIpv4,
        RowRgb,
        RowPointer64,
        RowCount
    };

    void PopulateTable();
    void UpdateValues();
    QString FormatInt8() const;
    QString FormatUInt8() const;
    QString FormatInt16(bool BigEndian) const;
    QString FormatUInt16(bool BigEndian) const;
    QString FormatInt32(bool BigEndian) const;
    QString FormatUInt32(bool BigEndian) const;
    QString FormatInt64(bool BigEndian) const;
    QString FormatUInt64(bool BigEndian) const;
    QString FormatFloat(bool BigEndian) const;
    QString FormatDouble(bool BigEndian) const;
    QString FormatAscii() const;
    QString FormatUtf8() const;
    QString FormatUtf16(bool BigEndian) const;
    QString FormatBinary() const;
    QString FormatOctal() const;
    QString FormatUnixTime32(bool BigEndian) const;
    QString FormatUnixTime64(bool BigEndian) const;
    QString FormatFileTime() const;
    QString FormatDosDateTime() const;
    QString FormatGuid() const;
    QString FormatIpv4() const;
    QString FormatRgb() const;
    QString FormatPointer64(bool BigEndian) const;

    uint16_t ReadU16(const uint8_t* Data, bool BigEndian) const;
    uint32_t ReadU32(const uint8_t* Data, bool BigEndian) const;
    uint64_t ReadU64(const uint8_t* Data, bool BigEndian) const;

    bool TryParseAndWrite(int Row, const QString& Text);

    QTableWidget* Table;
    QToolButton* EndianButton;
    QByteArray RawBytes;
    Address CurrentAddress;
    AnalysisDatabase* CurrentDb;
    bool BigEndianMode;
    bool UpdatingValues;
    QFont MonoFont;
};

}
