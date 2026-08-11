#pragma once

#include <QWidget>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>

namespace Fidra {

class DecoderWidget : public QWidget {
    Q_OBJECT

public:
    explicit DecoderWidget(QWidget* Parent = nullptr);
    ~DecoderWidget() override;

private slots:
    void OnTransform();
    void OnSmartDecode();
    void OnSwapInputOutput();
    void OnClearAll();

private:
    QByteArray Base64Encode(const QByteArray& Input);
    QByteArray Base64Decode(const QByteArray& Input);
    QByteArray UrlEncode(const QByteArray& Input);
    QByteArray UrlDecode(const QByteArray& Input);
    QByteArray HtmlEncode(const QByteArray& Input);
    QByteArray HtmlDecode(const QByteArray& Input);
    QByteArray HexEncode(const QByteArray& Input);
    QByteArray HexDecode(const QByteArray& Input);
    QByteArray ComputeMd5(const QByteArray& Input);
    QByteArray ComputeSha1(const QByteArray& Input);
    QByteArray ComputeSha256(const QByteArray& Input);
    QString DetectEncoding(const QByteArray& Input);

    QPlainTextEdit* InputEditor;
    QPlainTextEdit* OutputEditor;
    QComboBox* TransformCombo;
    QPushButton* TransformButton;
    QPushButton* SmartDecodeButton;
    QPushButton* SwapButton;
    QPushButton* ClearButton;
    QLabel* InfoLabel;
};

}
