#include "McpToolRegistry.h"
#include "McpSchemaBuilder.h"
#include <QCryptographicHash>
#include <QByteArray>
#include <QJsonDocument>
#include <cstring>

namespace Fidra {

static uint32_t Crc32Table[256];
static bool Crc32TableInitialized = false;

static void InitCrc32Table() {
    if (Crc32TableInitialized) return;
    for (uint32_t I = 0; I < 256; ++I) {
        uint32_t Crc = I;
        for (int J = 0; J < 8; ++J) {
            if (Crc & 1)
                Crc = 0xEDB88320 ^ (Crc >> 1);
            else
                Crc >>= 1;
        }
        Crc32Table[I] = Crc;
    }
    Crc32TableInitialized = true;
}

static uint32_t CalcCrc32(const QByteArray& Data) {
    InitCrc32Table();
    uint32_t Crc = 0xFFFFFFFF;
    for (int I = 0; I < Data.size(); ++I) {
        uint8_t Byte = static_cast<uint8_t>(Data[I]);
        Crc = Crc32Table[(Crc ^ Byte) & 0xFF] ^ (Crc >> 8);
    }
    return Crc ^ 0xFFFFFFFF;
}

static int CountPrintable(const QByteArray& Data) {
    int Count = 0;
    for (int I = 0; I < Data.size(); ++I) {
        uint8_t B = static_cast<uint8_t>(Data[I]);
        if (B >= 0x20 && B <= 0x7E) ++Count;
    }
    return Count;
}

static QByteArray Rc4Process(const QByteArray& Data, const QByteArray& Key) {
    if (Key.isEmpty()) return Data;
    uint8_t S[256];
    for (int I = 0; I < 256; ++I) S[I] = static_cast<uint8_t>(I);
    int J = 0;
    for (int I = 0; I < 256; ++I) {
        J = (J + S[I] + static_cast<uint8_t>(Key[I % Key.size()])) & 0xFF;
        uint8_t Tmp = S[I]; S[I] = S[J]; S[J] = Tmp;
    }
    QByteArray Output(Data.size(), '\0');
    int Si = 0, Sj = 0;
    for (int K = 0; K < Data.size(); ++K) {
        Si = (Si + 1) & 0xFF;
        Sj = (Sj + S[Si]) & 0xFF;
        uint8_t Tmp = S[Si]; S[Si] = S[Sj]; S[Sj] = Tmp;
        uint8_t Keystream = S[(S[Si] + S[Sj]) & 0xFF];
        Output[K] = static_cast<char>(static_cast<uint8_t>(Data[K]) ^ Keystream);
    }
    return Output;
}

void McpToolRegistry::RegisterEncodingTools() {

    RegisterTool(QStringLiteral("encode_base64"),
        QStringLiteral("Base64 encode a string."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("String to encode"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QByteArray Encoded = Data.toUtf8().toBase64();
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("output")] = QString::fromLatin1(Encoded);
            return R;
        });

    RegisterTool(QStringLiteral("decode_base64"),
        QStringLiteral("Base64 decode a string. Returns decoded text and hex representation."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("Base64 encoded string"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QByteArray Decoded = QByteArray::fromBase64(Data.toLatin1());
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("output")] = QString::fromUtf8(Decoded);
            R[QStringLiteral("hex")] = QString::fromLatin1(Decoded.toHex(' '));
            R[QStringLiteral("size")] = Decoded.size();
            return R;
        });

    RegisterTool(QStringLiteral("encode_base64url"),
        QStringLiteral("Base64url encode (URL-safe, no padding)."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("String to encode"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QByteArray Encoded = Data.toUtf8().toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("output")] = QString::fromLatin1(Encoded);
            return R;
        });

    RegisterTool(QStringLiteral("decode_base64url"),
        QStringLiteral("Decode base64url encoded string."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("Base64url encoded string"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QByteArray Decoded = QByteArray::fromBase64(Data.toLatin1(), QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
            if (Decoded.isEmpty() && !Data.isEmpty()) {
                Decoded = QByteArray::fromBase64(Data.toLatin1(), QByteArray::Base64UrlEncoding);
            }
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("output")] = QString::fromUtf8(Decoded);
            R[QStringLiteral("hex")] = QString::fromLatin1(Decoded.toHex(' '));
            R[QStringLiteral("size")] = Decoded.size();
            return R;
        });

    RegisterTool(QStringLiteral("encode_hex"),
        QStringLiteral("Hex encode a string."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("String to hex encode"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QByteArray Hex = Data.toUtf8().toHex();
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("output")] = QString::fromLatin1(Hex);
            return R;
        });

    RegisterTool(QStringLiteral("decode_hex"),
        QStringLiteral("Decode hex string to text."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("Hex string (e.g. 48656c6c6f)"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString().remove(' ');
            QByteArray Decoded = QByteArray::fromHex(Data.toLatin1());
            QJsonObject R;
            R[QStringLiteral("input")] = A.value(QStringLiteral("data")).toString();
            R[QStringLiteral("output")] = QString::fromUtf8(Decoded);
            R[QStringLiteral("size")] = Decoded.size();
            return R;
        });

    RegisterTool(QStringLiteral("encode_url"),
        QStringLiteral("URL-encode (percent encode) a string."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("String to URL encode"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QByteArray Encoded = Data.toUtf8().toPercentEncoding();
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("output")] = QString::fromLatin1(Encoded);
            return R;
        });

    RegisterTool(QStringLiteral("decode_url"),
        QStringLiteral("URL-decode (percent decode) a string."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("URL encoded string"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QByteArray Decoded = QByteArray::fromPercentEncoding(Data.toUtf8());
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("output")] = QString::fromUtf8(Decoded);
            return R;
        });

    RegisterTool(QStringLiteral("encode_html"),
        QStringLiteral("HTML entity encode special characters."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("String to HTML encode"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QString Encoded;
            Encoded.reserve(Data.size() * 2);
            for (const QChar& Ch : Data) {
                if (Ch == QLatin1Char('&')) Encoded += QStringLiteral("&amp;");
                else if (Ch == QLatin1Char('<')) Encoded += QStringLiteral("&lt;");
                else if (Ch == QLatin1Char('>')) Encoded += QStringLiteral("&gt;");
                else if (Ch == QLatin1Char('"')) Encoded += QStringLiteral("&quot;");
                else if (Ch == QLatin1Char('\'')) Encoded += QStringLiteral("&#39;");
                else Encoded += Ch;
            }
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("output")] = Encoded;
            return R;
        });

    RegisterTool(QStringLiteral("decode_html"),
        QStringLiteral("Decode HTML entities."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("HTML encoded string"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QString Decoded = Data;
            Decoded.replace(QStringLiteral("&amp;"), QStringLiteral("&"));
            Decoded.replace(QStringLiteral("&lt;"), QStringLiteral("<"));
            Decoded.replace(QStringLiteral("&gt;"), QStringLiteral(">"));
            Decoded.replace(QStringLiteral("&quot;"), QStringLiteral("\""));
            Decoded.replace(QStringLiteral("&#39;"), QStringLiteral("'"));
            Decoded.replace(QStringLiteral("&#x27;"), QStringLiteral("'"));
            Decoded.replace(QStringLiteral("&apos;"), QStringLiteral("'"));
            Decoded.replace(QStringLiteral("&#10;"), QStringLiteral("\n"));
            Decoded.replace(QStringLiteral("&#13;"), QStringLiteral("\r"));
            Decoded.replace(QStringLiteral("&#9;"), QStringLiteral("\t"));
            Decoded.replace(QStringLiteral("&nbsp;"), QStringLiteral(" "));
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("output")] = Decoded;
            return R;
        });

    RegisterTool(QStringLiteral("hash_md5"),
        QStringLiteral("Calculate MD5 hash of input string."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("String to hash"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QByteArray Hash = QCryptographicHash::hash(Data.toUtf8(), QCryptographicHash::Md5);
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("algorithm")] = QStringLiteral("MD5");
            R[QStringLiteral("hash")] = QString::fromLatin1(Hash.toHex());
            return R;
        });

    RegisterTool(QStringLiteral("hash_sha1"),
        QStringLiteral("Calculate SHA1 hash of input string."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("String to hash"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QByteArray Hash = QCryptographicHash::hash(Data.toUtf8(), QCryptographicHash::Sha1);
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("algorithm")] = QStringLiteral("SHA1");
            R[QStringLiteral("hash")] = QString::fromLatin1(Hash.toHex());
            return R;
        });

    RegisterTool(QStringLiteral("hash_sha256"),
        QStringLiteral("Calculate SHA256 hash of input string."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("String to hash"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QByteArray Hash = QCryptographicHash::hash(Data.toUtf8(), QCryptographicHash::Sha256);
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("algorithm")] = QStringLiteral("SHA256");
            R[QStringLiteral("hash")] = QString::fromLatin1(Hash.toHex());
            return R;
        });

    RegisterTool(QStringLiteral("hash_sha512"),
        QStringLiteral("Calculate SHA512 hash of input string."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("String to hash"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QByteArray Hash = QCryptographicHash::hash(Data.toUtf8(), QCryptographicHash::Sha512);
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("algorithm")] = QStringLiteral("SHA512");
            R[QStringLiteral("hash")] = QString::fromLatin1(Hash.toHex());
            return R;
        });

    RegisterTool(QStringLiteral("hash_crc32"),
        QStringLiteral("Calculate CRC32 checksum of input string."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("String to hash"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            uint32_t Crc = CalcCrc32(Data.toUtf8());
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("algorithm")] = QStringLiteral("CRC32");
            R[QStringLiteral("hash")] = QString::number(Crc, 16).toUpper().rightJustified(8, '0');
            R[QStringLiteral("decimal")] = static_cast<qint64>(Crc);
            return R;
        });

    RegisterTool(QStringLiteral("hash_all"),
        QStringLiteral("Calculate all supported hashes (MD5, SHA1, SHA256, SHA512, CRC32) at once."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("String to hash"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QByteArray Utf8 = Data.toUtf8();
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("md5")] = QString::fromLatin1(QCryptographicHash::hash(Utf8, QCryptographicHash::Md5).toHex());
            R[QStringLiteral("sha1")] = QString::fromLatin1(QCryptographicHash::hash(Utf8, QCryptographicHash::Sha1).toHex());
            R[QStringLiteral("sha256")] = QString::fromLatin1(QCryptographicHash::hash(Utf8, QCryptographicHash::Sha256).toHex());
            R[QStringLiteral("sha512")] = QString::fromLatin1(QCryptographicHash::hash(Utf8, QCryptographicHash::Sha512).toHex());
            uint32_t Crc = CalcCrc32(Utf8);
            R[QStringLiteral("crc32")] = QString::number(Crc, 16).toUpper().rightJustified(8, '0');
            return R;
        });

    RegisterTool(QStringLiteral("xor_encrypt"),
        QStringLiteral("XOR data with a repeating key. Both inputs as hex strings."),
        Schema::Build({
            {QStringLiteral("hex_data"), Schema::String(QStringLiteral("Hex encoded data"))},
            {QStringLiteral("hex_key"), Schema::String(QStringLiteral("Hex encoded key"))}
        }, {QStringLiteral("hex_data"), QStringLiteral("hex_key")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QByteArray Data = QByteArray::fromHex(A.value(QStringLiteral("hex_data")).toString().remove(' ').toLatin1());
            QByteArray Key = QByteArray::fromHex(A.value(QStringLiteral("hex_key")).toString().remove(' ').toLatin1());
            if (Key.isEmpty()) return Schema::Err(QStringLiteral("Key cannot be empty"));
            QByteArray Result(Data.size(), '\0');
            for (int I = 0; I < Data.size(); ++I) {
                Result[I] = static_cast<char>(static_cast<uint8_t>(Data[I]) ^ static_cast<uint8_t>(Key[I % Key.size()]));
            }
            QJsonObject R;
            R[QStringLiteral("input_hex")] = QString::fromLatin1(Data.toHex(' '));
            R[QStringLiteral("key_hex")] = QString::fromLatin1(Key.toHex(' '));
            R[QStringLiteral("output_hex")] = QString::fromLatin1(Result.toHex(' '));
            R[QStringLiteral("output_text")] = QString::fromUtf8(Result);
            R[QStringLiteral("size")] = Result.size();
            return R;
        });

    RegisterTool(QStringLiteral("xor_single_byte"),
        QStringLiteral("XOR all bytes of hex data with a single byte key."),
        Schema::Build({
            {QStringLiteral("hex_data"), Schema::String(QStringLiteral("Hex encoded data"))},
            {QStringLiteral("key"), Schema::Integer(QStringLiteral("Single byte key value (0-255)"), 0, 255)}
        }, {QStringLiteral("hex_data"), QStringLiteral("key")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QByteArray Data = QByteArray::fromHex(A.value(QStringLiteral("hex_data")).toString().remove(' ').toLatin1());
            uint8_t Key = static_cast<uint8_t>(A.value(QStringLiteral("key")).toInt());
            QByteArray Result(Data.size(), '\0');
            for (int I = 0; I < Data.size(); ++I) {
                Result[I] = static_cast<char>(static_cast<uint8_t>(Data[I]) ^ Key);
            }
            QJsonObject R;
            R[QStringLiteral("input_hex")] = QString::fromLatin1(Data.toHex(' '));
            R[QStringLiteral("key")] = Key;
            R[QStringLiteral("output_hex")] = QString::fromLatin1(Result.toHex(' '));
            R[QStringLiteral("output_text")] = QString::fromUtf8(Result);
            return R;
        });

    RegisterTool(QStringLiteral("xor_bruteforce"),
        QStringLiteral("Bruteforce single-byte XOR. Returns top 10 keys producing most printable ASCII."),
        Schema::Build({
            {QStringLiteral("hex_data"), Schema::String(QStringLiteral("Hex encoded data"))}
        }, {QStringLiteral("hex_data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QByteArray Data = QByteArray::fromHex(A.value(QStringLiteral("hex_data")).toString().remove(' ').toLatin1());
            if (Data.isEmpty()) return Schema::Err(QStringLiteral("Empty data"));

            struct KeyResult {
                uint8_t Key;
                int PrintableCount;
                QByteArray Decoded;
            };
            QVector<KeyResult> Results;
            Results.reserve(256);
            for (int K = 0; K < 256; ++K) {
                QByteArray Decoded(Data.size(), '\0');
                for (int I = 0; I < Data.size(); ++I) {
                    Decoded[I] = static_cast<char>(static_cast<uint8_t>(Data[I]) ^ static_cast<uint8_t>(K));
                }
                int Printable = CountPrintable(Decoded);
                Results.append({static_cast<uint8_t>(K), Printable, Decoded});
            }
            std::sort(Results.begin(), Results.end(), [](const KeyResult& Left, const KeyResult& Right) {
                return Left.PrintableCount > Right.PrintableCount;
            });

            QJsonArray Top;
            int Limit = std::min(10, static_cast<int>(Results.size()));
            for (int I = 0; I < Limit; ++I) {
                QJsonObject Entry;
                Entry[QStringLiteral("key")] = Results[I].Key;
                Entry[QStringLiteral("key_hex")] = QString::number(Results[I].Key, 16).toUpper().rightJustified(2, '0');
                Entry[QStringLiteral("printable_ratio")] = static_cast<double>(Results[I].PrintableCount) / Data.size();
                Entry[QStringLiteral("decoded_text")] = QString::fromUtf8(Results[I].Decoded);
                Entry[QStringLiteral("decoded_hex")] = QString::fromLatin1(Results[I].Decoded.toHex(' '));
                Top.append(Entry);
            }
            QJsonObject R;
            R[QStringLiteral("data_size")] = Data.size();
            R[QStringLiteral("results")] = Top;
            return R;
        });

    RegisterTool(QStringLiteral("rot13"),
        QStringLiteral("ROT13 encode/decode a string (self-inverse)."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("String to ROT13"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QString Result;
            Result.reserve(Data.size());
            for (const QChar& Ch : Data) {
                if (Ch >= 'a' && Ch <= 'z')
                    Result += QChar('a' + (Ch.toLatin1() - 'a' + 13) % 26);
                else if (Ch >= 'A' && Ch <= 'Z')
                    Result += QChar('A' + (Ch.toLatin1() - 'A' + 13) % 26);
                else
                    Result += Ch;
            }
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("output")] = Result;
            return R;
        });

    RegisterTool(QStringLiteral("rot_n"),
        QStringLiteral("ROT-N cipher with configurable shift. Alpha characters only."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("String to rotate"))},
            {QStringLiteral("shift"), Schema::Integer(QStringLiteral("Rotation amount (1-25)"), 1, 25)}
        }, {QStringLiteral("data"), QStringLiteral("shift")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            int Shift = A.value(QStringLiteral("shift")).toInt(13);
            QString Result;
            Result.reserve(Data.size());
            for (const QChar& Ch : Data) {
                if (Ch >= 'a' && Ch <= 'z')
                    Result += QChar('a' + (Ch.toLatin1() - 'a' + Shift) % 26);
                else if (Ch >= 'A' && Ch <= 'Z')
                    Result += QChar('A' + (Ch.toLatin1() - 'A' + Shift) % 26);
                else
                    Result += Ch;
            }
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("shift")] = Shift;
            R[QStringLiteral("output")] = Result;
            return R;
        });

    RegisterTool(QStringLiteral("caesar_bruteforce"),
        QStringLiteral("Try all 26 Caesar cipher shifts on a string."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("Ciphertext to bruteforce"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QString Data = A.value(QStringLiteral("data")).toString();
            QJsonArray Shifts;
            for (int Shift = 0; Shift < 26; ++Shift) {
                QString Decoded;
                Decoded.reserve(Data.size());
                for (const QChar& Ch : Data) {
                    if (Ch >= 'a' && Ch <= 'z')
                        Decoded += QChar('a' + (Ch.toLatin1() - 'a' + Shift) % 26);
                    else if (Ch >= 'A' && Ch <= 'Z')
                        Decoded += QChar('A' + (Ch.toLatin1() - 'A' + Shift) % 26);
                    else
                        Decoded += Ch;
                }
                QJsonObject Entry;
                Entry[QStringLiteral("shift")] = Shift;
                Entry[QStringLiteral("result")] = Decoded;
                Shifts.append(Entry);
            }
            QJsonObject R;
            R[QStringLiteral("input")] = Data;
            R[QStringLiteral("results")] = Shifts;
            return R;
        });

    RegisterTool(QStringLiteral("rc4_crypt"),
        QStringLiteral("RC4 encrypt/decrypt. RC4 is symmetric so encryption and decryption are the same operation."),
        Schema::Build({
            {QStringLiteral("hex_data"), Schema::String(QStringLiteral("Hex encoded data"))},
            {QStringLiteral("hex_key"), Schema::String(QStringLiteral("Hex encoded key"))}
        }, {QStringLiteral("hex_data"), QStringLiteral("hex_key")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QByteArray Data = QByteArray::fromHex(A.value(QStringLiteral("hex_data")).toString().remove(' ').toLatin1());
            QByteArray Key = QByteArray::fromHex(A.value(QStringLiteral("hex_key")).toString().remove(' ').toLatin1());
            if (Key.isEmpty()) return Schema::Err(QStringLiteral("Key cannot be empty"));
            if (Data.isEmpty()) return Schema::Err(QStringLiteral("Data cannot be empty"));
            QByteArray Result = Rc4Process(Data, Key);
            QJsonObject R;
            R[QStringLiteral("input_hex")] = QString::fromLatin1(Data.toHex(' '));
            R[QStringLiteral("key_hex")] = QString::fromLatin1(Key.toHex(' '));
            R[QStringLiteral("output_hex")] = QString::fromLatin1(Result.toHex(' '));
            R[QStringLiteral("output_text")] = QString::fromUtf8(Result);
            R[QStringLiteral("size")] = Result.size();
            return R;
        });

    RegisterTool(QStringLiteral("convert_endian"),
        QStringLiteral("Swap byte order (reverse bytes) of hex data."),
        Schema::Build({
            {QStringLiteral("hex_data"), Schema::String(QStringLiteral("Hex string to reverse byte order (e.g. 01020304 -> 04030201)"))}
        }, {QStringLiteral("hex_data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QByteArray Data = QByteArray::fromHex(A.value(QStringLiteral("hex_data")).toString().remove(' ').toLatin1());
            if (Data.isEmpty()) return Schema::Err(QStringLiteral("Empty data"));
            QByteArray Reversed(Data.size(), '\0');
            for (int I = 0; I < Data.size(); ++I) {
                Reversed[I] = Data[Data.size() - 1 - I];
            }
            QJsonObject R;
            R[QStringLiteral("input")] = QString::fromLatin1(Data.toHex(' '));
            R[QStringLiteral("output")] = QString::fromLatin1(Reversed.toHex(' '));
            return R;
        });

    RegisterTool(QStringLiteral("int_to_float"),
        QStringLiteral("Reinterpret 4-byte hex as IEEE 754 float."),
        Schema::Build({
            {QStringLiteral("hex_data"), Schema::String(QStringLiteral("4-byte hex (e.g. 40490FDB for PI)"))}
        }, {QStringLiteral("hex_data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QByteArray Data = QByteArray::fromHex(A.value(QStringLiteral("hex_data")).toString().remove(' ').toLatin1());
            if (Data.size() != 4) return Schema::Err(QStringLiteral("Need exactly 4 bytes for float"));
            float Value;
            std::memcpy(&Value, Data.constData(), 4);
            QJsonObject R;
            R[QStringLiteral("hex")] = QString::fromLatin1(Data.toHex(' '));
            R[QStringLiteral("float")] = static_cast<double>(Value);
            return R;
        });

    RegisterTool(QStringLiteral("float_to_int"),
        QStringLiteral("Convert float value to its 4-byte hex representation."),
        Schema::Build({
            {QStringLiteral("value"), Schema::Number(QStringLiteral("Float value"))}
        }, {QStringLiteral("value")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            float Value = static_cast<float>(A.value(QStringLiteral("value")).toDouble());
            QByteArray Bytes(4, '\0');
            std::memcpy(Bytes.data(), &Value, 4);
            QJsonObject R;
            R[QStringLiteral("float")] = static_cast<double>(Value);
            R[QStringLiteral("hex")] = QString::fromLatin1(Bytes.toHex(' '));
            R[QStringLiteral("hex_le")] = QString::fromLatin1(Bytes.toHex(' '));
            QByteArray BytesBe(4, '\0');
            for (int I = 0; I < 4; ++I) BytesBe[I] = Bytes[3 - I];
            R[QStringLiteral("hex_be")] = QString::fromLatin1(BytesBe.toHex(' '));
            return R;
        });

    RegisterTool(QStringLiteral("int_to_double"),
        QStringLiteral("Reinterpret 8-byte hex as IEEE 754 double."),
        Schema::Build({
            {QStringLiteral("hex_data"), Schema::String(QStringLiteral("8-byte hex (e.g. 400921FB54442D18 for PI)"))}
        }, {QStringLiteral("hex_data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            QByteArray Data = QByteArray::fromHex(A.value(QStringLiteral("hex_data")).toString().remove(' ').toLatin1());
            if (Data.size() != 8) return Schema::Err(QStringLiteral("Need exactly 8 bytes for double"));
            double Value;
            std::memcpy(&Value, Data.constData(), 8);
            QJsonObject R;
            R[QStringLiteral("hex")] = QString::fromLatin1(Data.toHex(' '));
            R[QStringLiteral("double")] = Value;
            return R;
        });

    RegisterTool(QStringLiteral("double_to_int"),
        QStringLiteral("Convert double value to its 8-byte hex representation."),
        Schema::Build({
            {QStringLiteral("value"), Schema::Number(QStringLiteral("Double value"))}
        }, {QStringLiteral("value")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            double Value = A.value(QStringLiteral("value")).toDouble();
            QByteArray Bytes(8, '\0');
            std::memcpy(Bytes.data(), &Value, 8);
            QJsonObject R;
            R[QStringLiteral("double")] = Value;
            R[QStringLiteral("hex")] = QString::fromLatin1(Bytes.toHex(' '));
            R[QStringLiteral("hex_le")] = QString::fromLatin1(Bytes.toHex(' '));
            QByteArray BytesBe(8, '\0');
            for (int I = 0; I < 8; ++I) BytesBe[I] = Bytes[7 - I];
            R[QStringLiteral("hex_be")] = QString::fromLatin1(BytesBe.toHex(' '));
            return R;
        });
}

}
