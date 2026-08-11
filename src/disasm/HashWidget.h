#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QTableWidget>
#include <QToolButton>
#include <QPushButton>
#include <QComboBox>
#include <QByteArray>
#include <QFont>

namespace Fidra {

class AnalysisDatabase;

class ByteHistogramWidget : public QWidget {
    Q_OBJECT

public:
    explicit ByteHistogramWidget(QWidget* Parent = nullptr);
    ~ByteHistogramWidget() override;

    void SetData(const QByteArray& Data);
    void Clear();

protected:
    void paintEvent(QPaintEvent* Event) override;
    QSize minimumSizeHint() const override;

private:
    uint64_t Frequencies[256];
    uint64_t MaxFrequency;
    int TotalBytes;
};

class HashWidget : public QWidget {
    Q_OBJECT

public:
    explicit HashWidget(QWidget* Parent = nullptr);
    ~HashWidget() override;

    void HashRange(AnalysisDatabase* Db, Address Start, Address End);
    void HashSegment(AnalysisDatabase* Db, const QString& SegmentName);
    void SetDatabase(AnalysisDatabase* Db);

signals:
    void NavigateToAddress(Address Addr);

private slots:
    void OnCopyValue(int Row);
    void OnCopyAll();
    void OnHashSelection();
    void OnHashSegment();

private:
    enum RowIndex {
        RowCrc32 = 0,
        RowAdler32,
        RowMd5,
        RowSha1,
        RowSha256,
        RowSha512,
        RowXxHash32,
        RowXxHash64,
        RowSize,
        RowEntropy,
        RowCount
    };

    void PopulateTable();
    void UpdateHashes(const QByteArray& Data);
    void PopulateSegmentDropdown();

    uint32_t CalculateCrc32(const QByteArray& Data) const;
    uint32_t CalculateAdler32(const QByteArray& Data) const;
    uint32_t CalculateXxHash32(const QByteArray& Data, uint32_t Seed = 0) const;
    uint64_t CalculateXxHash64(const QByteArray& Data, uint64_t Seed = 0) const;
    double CalculateEntropy(const QByteArray& Data) const;

    QString FormatHash(const QByteArray& Hash) const;
    QString FormatSize(qint64 Size) const;

    QTableWidget* Table;
    QPushButton* CopyAllButton;
    QToolButton* HashSelectionButton;
    QComboBox* SegmentCombo;
    QToolButton* HashSegmentButton;
    ByteHistogramWidget* Histogram;
    AnalysisDatabase* CurrentDb;
    Address RangeStart;
    Address RangeEnd;
    QFont MonoFont;
};

}
