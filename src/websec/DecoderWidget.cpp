#include "DecoderWidget.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFont>
#include <QCryptographicHash>
#include <QUrl>
#include <QRegularExpression>

namespace Fidra {

DecoderWidget::DecoderWidget(QWidget* Parent)
    : QWidget(Parent)
    , InputEditor(nullptr)
    , OutputEditor(nullptr)
    , TransformCombo(nullptr)
    , TransformButton(nullptr)
    , SmartDecodeButton(nullptr)
    , SwapButton(nullptr)
    , ClearButton(nullptr)
    , InfoLabel(nullptr) {

    QFont MonoFont(QStringLiteral("Consolas"), 10);

    QVBoxLayout* MainLayout = new QVBoxLayout(this);
    MainLayout->setContentsMargins(4, 4, 4, 4);
    MainLayout->setSpacing(8);

    QGroupBox* InputGroup = new QGroupBox(QStringLiteral("Input"), this);
    QVBoxLayout* InputLayout = new QVBoxLayout(InputGroup);
    InputEditor = new QPlainTextEdit(this);
    InputEditor->setFont(MonoFont);
    InputEditor->setPlaceholderText(QStringLiteral("Enter text to encode/decode..."));
    InputEditor->setMinimumHeight(120);
    InputLayout->addWidget(InputEditor);
    MainLayout->addWidget(InputGroup, 1);

    QHBoxLayout* ControlLayout = new QHBoxLayout();

    TransformCombo = new QComboBox(this);
    TransformCombo->addItem(QStringLiteral("Base64 Encode"));
    TransformCombo->addItem(QStringLiteral("Base64 Decode"));
    TransformCombo->addItem(QStringLiteral("URL Encode"));
    TransformCombo->addItem(QStringLiteral("URL Decode"));
    TransformCombo->addItem(QStringLiteral("HTML Encode"));
    TransformCombo->addItem(QStringLiteral("HTML Decode"));
    TransformCombo->addItem(QStringLiteral("Hex Encode"));
    TransformCombo->addItem(QStringLiteral("Hex Decode"));
    TransformCombo->addItem(QStringLiteral("MD5 Hash"));
    TransformCombo->addItem(QStringLiteral("SHA1 Hash"));
    TransformCombo->addItem(QStringLiteral("SHA256 Hash"));
    TransformCombo->setMinimumWidth(160);

    TransformButton = new QPushButton(QStringLiteral("Transform"), this);
    TransformButton->setStyleSheet(QStringLiteral("QPushButton { background-color: #e8530e; color: white; font-weight: bold; padding: 6px 16px; border-radius: 3px; } QPushButton:hover { background-color: #ff6b2b; }"));

    SmartDecodeButton = new QPushButton(QStringLiteral("Smart Decode"), this);
    SwapButton = new QPushButton(QStringLiteral("Swap"), this);
    ClearButton = new QPushButton(QStringLiteral("Clear"), this);

    ControlLayout->addWidget(TransformCombo);
    ControlLayout->addWidget(TransformButton);
    ControlLayout->addSpacing(16);
    ControlLayout->addWidget(SmartDecodeButton);
    ControlLayout->addWidget(SwapButton);
    ControlLayout->addWidget(ClearButton);
    ControlLayout->addStretch();

    InfoLabel = new QLabel(this);
    InfoLabel->setFont(MonoFont);
    ControlLayout->addWidget(InfoLabel);

    MainLayout->addLayout(ControlLayout);

    QGroupBox* OutputGroup = new QGroupBox(QStringLiteral("Output"), this);
    QVBoxLayout* OutputLayout = new QVBoxLayout(OutputGroup);
    OutputEditor = new QPlainTextEdit(this);
    OutputEditor->setFont(MonoFont);
    OutputEditor->setReadOnly(true);
    OutputEditor->setPlaceholderText(QStringLiteral("Result will appear here..."));
    OutputEditor->setMinimumHeight(120);
    OutputLayout->addWidget(OutputEditor);
    MainLayout->addWidget(OutputGroup, 1);

    connect(TransformButton, &QPushButton::clicked, this, &DecoderWidget::OnTransform);
    connect(SmartDecodeButton, &QPushButton::clicked, this, &DecoderWidget::OnSmartDecode);
    connect(SwapButton, &QPushButton::clicked, this, &DecoderWidget::OnSwapInputOutput);
    connect(ClearButton, &QPushButton::clicked, this, &DecoderWidget::OnClearAll);
}

DecoderWidget::~DecoderWidget() {
}

void DecoderWidget::OnTransform() {
    QByteArray Input = InputEditor->toPlainText().toUtf8();
    if (Input.isEmpty()) return;

    QByteArray Result;
    int Index = TransformCombo->currentIndex();

    switch (Index) {
    case 0: Result = Base64Encode(Input); break;
    case 1: Result = Base64Decode(Input); break;
    case 2: Result = UrlEncode(Input); break;
    case 3: Result = UrlDecode(Input); break;
    case 4: Result = HtmlEncode(Input); break;
    case 5: Result = HtmlDecode(Input); break;
    case 6: Result = HexEncode(Input); break;
    case 7: Result = HexDecode(Input); break;
    case 8: Result = ComputeMd5(Input); break;
    case 9: Result = ComputeSha1(Input); break;
    case 10: Result = ComputeSha256(Input); break;
    }

    OutputEditor->setPlainText(QString::fromUtf8(Result));
    InfoLabel->setText(QStringLiteral("Input: %1 bytes | Output: %2 bytes").arg(Input.size()).arg(Result.size()));
}

void DecoderWidget::OnSmartDecode() {
    QByteArray Input = InputEditor->toPlainText().toUtf8();
    if (Input.isEmpty()) return;

    QString Detected = DetectEncoding(Input);
    QByteArray Result;
    QString Method;

    if (Detected == "base64") {
        Result = Base64Decode(Input);
        Method = QStringLiteral("Base64 Decode");
    } else if (Detected == "url") {
        Result = UrlDecode(Input);
        Method = QStringLiteral("URL Decode");
    } else if (Detected == "html") {
        Result = HtmlDecode(Input);
        Method = QStringLiteral("HTML Decode");
    } else if (Detected == "hex") {
        Result = HexDecode(Input);
        Method = QStringLiteral("Hex Decode");
    } else {
        Result = Input;
        Method = QStringLiteral("No encoding detected");
    }

    OutputEditor->setPlainText(QString::fromUtf8(Result));
    InfoLabel->setText(QStringLiteral("Detected: %1 | Input: %2 bytes | Output: %3 bytes").arg(Method).arg(Input.size()).arg(Result.size()));
}

void DecoderWidget::OnSwapInputOutput() {
    QString OutputText = OutputEditor->toPlainText();
    InputEditor->setPlainText(OutputText);
    OutputEditor->clear();
    InfoLabel->clear();
}

void DecoderWidget::OnClearAll() {
    InputEditor->clear();
    OutputEditor->clear();
    InfoLabel->clear();
}

QByteArray DecoderWidget::Base64Encode(const QByteArray& Input) {
    return Input.toBase64();
}

QByteArray DecoderWidget::Base64Decode(const QByteArray& Input) {
    return QByteArray::fromBase64(Input.trimmed());
}

QByteArray DecoderWidget::UrlEncode(const QByteArray& Input) {
    return QUrl::toPercentEncoding(QString::fromUtf8(Input));
}

QByteArray DecoderWidget::UrlDecode(const QByteArray& Input) {
    return QByteArray::fromPercentEncoding(Input);
}

QByteArray DecoderWidget::HtmlEncode(const QByteArray& Input) {
    QString Text = QString::fromUtf8(Input);
    QString Result;
    Result.reserve(Text.size() * 2);

    for (const QChar& Ch : Text) {
        if (Ch == '<') Result += "&lt;";
        else if (Ch == '>') Result += "&gt;";
        else if (Ch == '&') Result += "&amp;";
        else if (Ch == '"') Result += "&quot;";
        else if (Ch == '\'') Result += "&#39;";
        else if (Ch.unicode() > 127) Result += QString("&#%1;").arg(Ch.unicode());
        else Result += Ch;
    }

    return Result.toUtf8();
}

QByteArray DecoderWidget::HtmlDecode(const QByteArray& Input) {
    QString Text = QString::fromUtf8(Input);
    Text.replace("&lt;", "<");
    Text.replace("&gt;", ">");
    Text.replace("&amp;", "&");
    Text.replace("&quot;", "\"");
    Text.replace("&#39;", "'");
    Text.replace("&apos;", "'");
    Text.replace("&nbsp;", " ");

    QRegularExpression NumericEntity("&#(\\d+);");
    QRegularExpressionMatchIterator It = NumericEntity.globalMatch(Text);
    while (It.hasNext()) {
        QRegularExpressionMatch Match = It.next();
        int CodePoint = Match.captured(1).toInt();
        Text.replace(Match.captured(0), QChar(CodePoint));
    }

    QRegularExpression HexEntity("&#x([0-9a-fA-F]+);");
    It = HexEntity.globalMatch(Text);
    while (It.hasNext()) {
        QRegularExpressionMatch Match = It.next();
        bool Ok;
        int CodePoint = Match.captured(1).toInt(&Ok, 16);
        if (Ok) {
            Text.replace(Match.captured(0), QChar(CodePoint));
        }
    }

    return Text.toUtf8();
}

QByteArray DecoderWidget::HexEncode(const QByteArray& Input) {
    return Input.toHex(' ');
}

QByteArray DecoderWidget::HexDecode(const QByteArray& Input) {
    QString Cleaned = QString::fromUtf8(Input);
    Cleaned.remove(' ');
    Cleaned.remove('\n');
    Cleaned.remove('\r');
    Cleaned.remove('\t');
    if (Cleaned.startsWith("0x", Qt::CaseInsensitive)) {
        Cleaned = Cleaned.mid(2);
    }
    return QByteArray::fromHex(Cleaned.toUtf8());
}

QByteArray DecoderWidget::ComputeMd5(const QByteArray& Input) {
    return QCryptographicHash::hash(Input, QCryptographicHash::Md5).toHex();
}

QByteArray DecoderWidget::ComputeSha1(const QByteArray& Input) {
    return QCryptographicHash::hash(Input, QCryptographicHash::Sha1).toHex();
}

QByteArray DecoderWidget::ComputeSha256(const QByteArray& Input) {
    return QCryptographicHash::hash(Input, QCryptographicHash::Sha256).toHex();
}

QString DecoderWidget::DetectEncoding(const QByteArray& Input) {
    QString Text = QString::fromUtf8(Input).trimmed();

    if (Text.contains("&lt;") || Text.contains("&gt;") || Text.contains("&amp;") ||
        Text.contains("&quot;") || Text.contains("&#")) {
        return QStringLiteral("html");
    }

    if (Text.contains('%')) {
        QRegularExpression UrlPattern("%[0-9a-fA-F]{2}");
        QRegularExpressionMatchIterator It = UrlPattern.globalMatch(Text);
        int MatchCount = 0;
        while (It.hasNext()) { It.next(); ++MatchCount; }
        if (MatchCount > 0) {
            return QStringLiteral("url");
        }
    }

    QRegularExpression HexPattern("^([0-9a-fA-F]{2}[\\s]*)+$");
    if (HexPattern.match(Text).hasMatch() && Text.size() >= 4) {
        return QStringLiteral("hex");
    }

    QRegularExpression Base64Pattern("^[A-Za-z0-9+/]+=*$");
    QString NoWhitespace = Text;
    NoWhitespace.remove(QRegularExpression("\\s"));
    if (Base64Pattern.match(NoWhitespace).hasMatch() && NoWhitespace.size() >= 4 && NoWhitespace.size() % 4 == 0) {
        QByteArray Decoded = QByteArray::fromBase64(NoWhitespace.toUtf8());
        if (!Decoded.isEmpty()) {
            bool AllPrintable = true;
            for (char C : Decoded) {
                if (C < 0x09 || (C > 0x0D && C < 0x20) || C == 0x7F) {
                    AllPrintable = false;
                    break;
                }
            }
            if (AllPrintable || Decoded.size() > 2) {
                return QStringLiteral("base64");
            }
        }
    }

    return QStringLiteral("unknown");
}

}
