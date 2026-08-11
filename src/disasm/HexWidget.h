#pragma once

#include <fidra/Types.h>
#include <QAbstractScrollArea>
#include <QByteArray>
#include <QFont>

namespace Fidra {

class ICore;

class HexWidget : public QAbstractScrollArea {
    Q_OBJECT

public:
    explicit HexWidget(QWidget* Parent = nullptr);
    ~HexWidget() override;

    void SetCore(ICore* Core);
    void SetData(const QByteArray& Data, Address BaseAddr);
    void NavigateTo(Address Addr);
    void Refresh();

    void OnProcessAttached(const ProcessInfo& Info);
    void OnProcessDetached();

    void SetEntropyOverlay(bool Enabled);
    bool IsEntropyOverlayEnabled() const;
    void SetEntropyBlockSize(int Bytes);

signals:
    void AddressChanged(Address Addr);

protected:
    void paintEvent(QPaintEvent* Event) override;
    void resizeEvent(QResizeEvent* Event) override;
    void mousePressEvent(QMouseEvent* Event) override;
    void keyPressEvent(QKeyEvent* Event) override;

private:
    void UpdateScrollBar();
    void ReadFromProcess(Address Addr, size_t Size);
    void RecalculateEntropy();
    double CalculateBlockEntropy(const uint8_t* Data, int Size) const;
    QColor EntropyToColor(double Entropy) const;
    int GetCharWidth() const;
    int GetLineHeight() const;
    int GetAddressWidth() const;
    int GetEntropyBarWidth() const;
    int GetHexColumnX() const;
    int GetAsciiColumnX() const;
    int PositionToOffset(const QPoint& Pos) const;

    ICore* CorePtr;
    QByteArray HexBuffer;
    Address BaseAddress;
    int BytesPerLine;
    int SelectionStart;
    int SelectionEnd;
    bool HasSelection;
    QFont MonoFont;
    bool EntropyOverlayEnabled;
    int EntropyBlockSize;
    QVector<double> EntropyValues;
};

}
