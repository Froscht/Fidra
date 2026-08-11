#include "McpToolRegistry.h"
#include "McpSchemaBuilder.h"
#include <QUrl>
#include <QUrlQuery>
#include <QJsonDocument>
#include <QJsonArray>
#include <QNetworkInterface>
#include <QHostInfo>
#include <QCryptographicHash>
#include <QRegularExpression>
#include <QRandomGenerator>
#include <QFile>
#include <QTextStream>

namespace Fidra {

void McpToolRegistry::RegisterNetworkTools() {

    RegisterTool(QStringLiteral("get_network_interfaces"),
        QStringLiteral("List all network interfaces with name, MAC address, IP addresses, and flags."),
        Schema::Empty(),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(A);
            QJsonArray Interfaces;
            for (const QNetworkInterface& Iface : QNetworkInterface::allInterfaces()) {
                QJsonObject Obj;
                Obj[QStringLiteral("name")] = Iface.name();
                Obj[QStringLiteral("human_name")] = Iface.humanReadableName();
                Obj[QStringLiteral("mac")] = Iface.hardwareAddress();
                Obj[QStringLiteral("index")] = Iface.index();
                QJsonArray Flags;
                if (Iface.flags() & QNetworkInterface::IsUp) Flags.append(QStringLiteral("Up"));
                if (Iface.flags() & QNetworkInterface::IsRunning) Flags.append(QStringLiteral("Running"));
                if (Iface.flags() & QNetworkInterface::IsLoopBack) Flags.append(QStringLiteral("Loopback"));
                if (Iface.flags() & QNetworkInterface::CanBroadcast) Flags.append(QStringLiteral("Broadcast"));
                if (Iface.flags() & QNetworkInterface::CanMulticast) Flags.append(QStringLiteral("Multicast"));
                Obj[QStringLiteral("flags")] = Flags;
                QJsonArray Addrs;
                for (const QNetworkAddressEntry& Entry : Iface.addressEntries()) {
                    QJsonObject AddrObj;
                    AddrObj[QStringLiteral("ip")] = Entry.ip().toString();
                    AddrObj[QStringLiteral("netmask")] = Entry.netmask().toString();
                    AddrObj[QStringLiteral("broadcast")] = Entry.broadcast().toString();
                    AddrObj[QStringLiteral("prefix_length")] = Entry.prefixLength();
                    Addrs.append(AddrObj);
                }
                Obj[QStringLiteral("addresses")] = Addrs;
                Interfaces.append(Obj);
            }
            QJsonObject Result;
            Result[QStringLiteral("count")] = Interfaces.size();
            Result[QStringLiteral("interfaces")] = Interfaces;
            return Result;
        });

    RegisterTool(QStringLiteral("get_connections"),
        QStringLiteral("List active TCP connections by parsing /proc/net/tcp (Linux). Shows local/remote address, state."),
        Schema::Empty(),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(A);
#ifdef _WIN32
            return Schema::Err(QStringLiteral("get_connections requires Linux /proc/net/tcp"));
#else
            QJsonArray Connections;
            auto ParseProcNet = [&](const QString& Path, const QString& Proto) {
                QFile File(Path);
                if (!File.open(QIODevice::ReadOnly | QIODevice::Text)) return;
                QTextStream Stream(&File);
                Stream.readLine();
                while (!Stream.atEnd()) {
                    QString Line = Stream.readLine().trimmed();
                    QStringList Parts = Line.split(QRegularExpression(QStringLiteral("\\s+")));
                    if (Parts.size() < 4) continue;
                    auto ParseAddr = [](const QString& Hex) -> QPair<QString, int> {
                        QStringList Halves = Hex.split(':');
                        if (Halves.size() != 2) return {QString(), 0};
                        bool Ok1 = false, Ok2 = false;
                        uint32_t IpNum = Halves[0].toUInt(&Ok1, 16);
                        int Port = Halves[1].toInt(&Ok2, 16);
                        if (!Ok1 || !Ok2) return {QString(), 0};
                        QString Ip = QString::number(IpNum & 0xFF) + QStringLiteral(".") +
                                     QString::number((IpNum >> 8) & 0xFF) + QStringLiteral(".") +
                                     QString::number((IpNum >> 16) & 0xFF) + QStringLiteral(".") +
                                     QString::number((IpNum >> 24) & 0xFF);
                        return {Ip, Port};
                    };
                    auto [LocalIp, LocalPort] = ParseAddr(Parts[1]);
                    auto [RemoteIp, RemotePort] = ParseAddr(Parts[2]);
                    bool StateOk = false;
                    int StateNum = Parts[3].toInt(&StateOk, 16);
                    QStringList StateNames = {
                        QStringLiteral(""), QStringLiteral("ESTABLISHED"), QStringLiteral("SYN_SENT"),
                        QStringLiteral("SYN_RECV"), QStringLiteral("FIN_WAIT1"), QStringLiteral("FIN_WAIT2"),
                        QStringLiteral("TIME_WAIT"), QStringLiteral("CLOSE"), QStringLiteral("CLOSE_WAIT"),
                        QStringLiteral("LAST_ACK"), QStringLiteral("LISTEN"), QStringLiteral("CLOSING")
                    };
                    QString StateName = (StateNum >= 0 && StateNum < StateNames.size()) ? StateNames[StateNum] : QString::number(StateNum);
                    QJsonObject Conn;
                    Conn[QStringLiteral("protocol")] = Proto;
                    Conn[QStringLiteral("local_address")] = LocalIp + QStringLiteral(":") + QString::number(LocalPort);
                    Conn[QStringLiteral("remote_address")] = RemoteIp + QStringLiteral(":") + QString::number(RemotePort);
                    Conn[QStringLiteral("state")] = StateName;
                    Connections.append(Conn);
                }
                File.close();
            };
            ParseProcNet(QStringLiteral("/proc/net/tcp"), QStringLiteral("tcp"));
            ParseProcNet(QStringLiteral("/proc/net/tcp6"), QStringLiteral("tcp6"));
            QJsonObject Result;
            Result[QStringLiteral("count")] = Connections.size();
            Result[QStringLiteral("connections")] = Connections;
            return Result;
#endif
        });

    RegisterTool(QStringLiteral("resolve_hostname"),
        QStringLiteral("Resolve a hostname to IP addresses via DNS."),
        Schema::Build({
            {QStringLiteral("hostname"), Schema::String(QStringLiteral("Hostname to resolve"))}
        }, {QStringLiteral("hostname")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Hostname = A.value(QStringLiteral("hostname")).toString();
            if (Hostname.isEmpty()) return Schema::Err(QStringLiteral("Empty hostname"));
            QHostInfo Info = QHostInfo::fromName(Hostname);
            if (Info.error() != QHostInfo::NoError) {
                return Schema::Err(QStringLiteral("DNS resolution failed: ") + Info.errorString());
            }
            QJsonArray Addrs;
            for (const QHostAddress& Addr : Info.addresses()) {
                Addrs.append(Addr.toString());
            }
            QJsonObject Result;
            Result[QStringLiteral("hostname")] = Hostname;
            Result[QStringLiteral("addresses")] = Addrs;
            Result[QStringLiteral("count")] = Addrs.size();
            return Result;
        });

    RegisterTool(QStringLiteral("decode_jwt"),
        QStringLiteral("Decode a JWT token. Splits by '.', base64url-decodes header and payload, returns parsed JSON."),
        Schema::Build({
            {QStringLiteral("token"), Schema::String(QStringLiteral("JWT token string"))}
        }, {QStringLiteral("token")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Token = A.value(QStringLiteral("token")).toString().trimmed();
            QStringList Parts = Token.split('.');
            if (Parts.size() != 3) {
                return Schema::Err(QStringLiteral("Invalid JWT: expected 3 parts separated by '.', got ") + QString::number(Parts.size()));
            }
            auto Base64UrlDecode = [](const QString& Input) -> QByteArray {
                QString Padded = Input;
                Padded.replace('-', '+');
                Padded.replace('_', '/');
                while (Padded.size() % 4 != 0) Padded.append('=');
                return QByteArray::fromBase64(Padded.toLatin1());
            };
            QByteArray HeaderBytes = Base64UrlDecode(Parts[0]);
            QByteArray PayloadBytes = Base64UrlDecode(Parts[1]);
            QJsonParseError HeaderErr, PayloadErr;
            QJsonDocument HeaderDoc = QJsonDocument::fromJson(HeaderBytes, &HeaderErr);
            QJsonDocument PayloadDoc = QJsonDocument::fromJson(PayloadBytes, &PayloadErr);
            QJsonObject Result;
            if (HeaderErr.error == QJsonParseError::NoError) {
                Result[QStringLiteral("header")] = HeaderDoc.object();
            } else {
                Result[QStringLiteral("header_raw")] = QString::fromUtf8(HeaderBytes);
                Result[QStringLiteral("header_error")] = HeaderErr.errorString();
            }
            if (PayloadErr.error == QJsonParseError::NoError) {
                Result[QStringLiteral("payload")] = PayloadDoc.object();
            } else {
                Result[QStringLiteral("payload_raw")] = QString::fromUtf8(PayloadBytes);
                Result[QStringLiteral("payload_error")] = PayloadErr.errorString();
            }
            Result[QStringLiteral("signature")] = Parts[2];
            return Result;
        });

    RegisterTool(QStringLiteral("encode_jwt"),
        QStringLiteral("Encode a JWT token (unsigned). Takes header and payload JSON, base64url-encodes and joins with '.'."),
        Schema::Build({
            {QStringLiteral("header"), Schema::String(QStringLiteral("Header JSON string"))},
            {QStringLiteral("payload"), Schema::String(QStringLiteral("Payload JSON string"))}
        }, {QStringLiteral("header"), QStringLiteral("payload")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString HeaderStr = A.value(QStringLiteral("header")).toString();
            QString PayloadStr = A.value(QStringLiteral("payload")).toString();
            QJsonParseError Err;
            QJsonDocument::fromJson(HeaderStr.toUtf8(), &Err);
            if (Err.error != QJsonParseError::NoError) {
                return Schema::Err(QStringLiteral("Invalid header JSON: ") + Err.errorString());
            }
            QJsonDocument::fromJson(PayloadStr.toUtf8(), &Err);
            if (Err.error != QJsonParseError::NoError) {
                return Schema::Err(QStringLiteral("Invalid payload JSON: ") + Err.errorString());
            }
            auto Base64UrlEncode = [](const QByteArray& Input) -> QString {
                QString Encoded = QString::fromLatin1(Input.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
                return Encoded;
            };
            QString HeaderB64 = Base64UrlEncode(HeaderStr.toUtf8());
            QString PayloadB64 = Base64UrlEncode(PayloadStr.toUtf8());
            QString Token = HeaderB64 + QStringLiteral(".") + PayloadB64 + QStringLiteral(".");
            QJsonObject Result;
            Result[QStringLiteral("token")] = Token;
            Result[QStringLiteral("note")] = QStringLiteral("Unsigned JWT (no signature)");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_curl"),
        QStringLiteral("Generate a curl command from method, URL, headers, and body."),
        Schema::Build({
            {QStringLiteral("method"), Schema::StringEnum(QStringLiteral("HTTP method"), {QStringLiteral("GET"), QStringLiteral("POST"), QStringLiteral("PUT"), QStringLiteral("DELETE"), QStringLiteral("PATCH"), QStringLiteral("HEAD"), QStringLiteral("OPTIONS")})},
            {QStringLiteral("url"), Schema::String(QStringLiteral("Target URL"))},
            {QStringLiteral("headers"), Schema::Object(QStringLiteral("Key-value headers object"))},
            {QStringLiteral("body"), Schema::String(QStringLiteral("Request body"))}
        }, {QStringLiteral("url")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Method = A.value(QStringLiteral("method")).toString(QStringLiteral("GET"));
            QString Url = A.value(QStringLiteral("url")).toString();
            QJsonObject Headers = A.value(QStringLiteral("headers")).toObject();
            QString Body = A.value(QStringLiteral("body")).toString();
            QString Cmd = QStringLiteral("curl");
            if (Method != QStringLiteral("GET")) {
                Cmd += QStringLiteral(" -X ") + Method;
            }
            for (auto It = Headers.constBegin(); It != Headers.constEnd(); ++It) {
                Cmd += QStringLiteral(" -H '") + It.key() + QStringLiteral(": ") + It.value().toString() + QStringLiteral("'");
            }
            if (!Body.isEmpty()) {
                QString Escaped = Body;
                Escaped.replace('\'', QStringLiteral("'\\''"));
                Cmd += QStringLiteral(" -d '") + Escaped + QStringLiteral("'");
            }
            Cmd += QStringLiteral(" '") + Url + QStringLiteral("'");
            QJsonObject Result;
            Result[QStringLiteral("command")] = Cmd;
            return Result;
        });

    RegisterTool(QStringLiteral("generate_wget"),
        QStringLiteral("Generate a wget command from method, URL, headers, and body."),
        Schema::Build({
            {QStringLiteral("method"), Schema::String(QStringLiteral("HTTP method (default GET)"))},
            {QStringLiteral("url"), Schema::String(QStringLiteral("Target URL"))},
            {QStringLiteral("headers"), Schema::Object(QStringLiteral("Key-value headers object"))},
            {QStringLiteral("body"), Schema::String(QStringLiteral("Request body"))},
            {QStringLiteral("output"), Schema::String(QStringLiteral("Output filename (optional)"))}
        }, {QStringLiteral("url")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Method = A.value(QStringLiteral("method")).toString(QStringLiteral("GET"));
            QString Url = A.value(QStringLiteral("url")).toString();
            QJsonObject Headers = A.value(QStringLiteral("headers")).toObject();
            QString Body = A.value(QStringLiteral("body")).toString();
            QString Output = A.value(QStringLiteral("output")).toString();
            QString Cmd = QStringLiteral("wget");
            if (Method != QStringLiteral("GET")) {
                Cmd += QStringLiteral(" --method=") + Method;
            }
            for (auto It = Headers.constBegin(); It != Headers.constEnd(); ++It) {
                Cmd += QStringLiteral(" --header='") + It.key() + QStringLiteral(": ") + It.value().toString() + QStringLiteral("'");
            }
            if (!Body.isEmpty()) {
                QString Escaped = Body;
                Escaped.replace('\'', QStringLiteral("'\\''"));
                Cmd += QStringLiteral(" --body-data='") + Escaped + QStringLiteral("'");
            }
            if (!Output.isEmpty()) {
                Cmd += QStringLiteral(" -O '") + Output + QStringLiteral("'");
            }
            Cmd += QStringLiteral(" '") + Url + QStringLiteral("'");
            QJsonObject Result;
            Result[QStringLiteral("command")] = Cmd;
            return Result;
        });

    RegisterTool(QStringLiteral("parse_url"),
        QStringLiteral("Parse a URL into its components: scheme, host, port, path, query parameters, fragment."),
        Schema::Build({
            {QStringLiteral("url"), Schema::String(QStringLiteral("URL to parse"))}
        }, {QStringLiteral("url")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString UrlStr = A.value(QStringLiteral("url")).toString();
            QUrl Url(UrlStr);
            if (!Url.isValid()) {
                return Schema::Err(QStringLiteral("Invalid URL: ") + Url.errorString());
            }
            QJsonObject Result;
            Result[QStringLiteral("scheme")] = Url.scheme();
            Result[QStringLiteral("host")] = Url.host();
            Result[QStringLiteral("port")] = Url.port(-1);
            Result[QStringLiteral("path")] = Url.path();
            Result[QStringLiteral("fragment")] = Url.fragment();
            Result[QStringLiteral("username")] = Url.userName();
            Result[QStringLiteral("password")] = Url.password();
            QUrlQuery Query(Url);
            QJsonObject Params;
            for (const auto& Pair : Query.queryItems()) {
                Params[Pair.first] = Pair.second;
            }
            Result[QStringLiteral("query_params")] = Params;
            Result[QStringLiteral("query_string")] = Url.query();
            return Result;
        });

    RegisterTool(QStringLiteral("build_url"),
        QStringLiteral("Build a URL from components: scheme, host, port, path, query params."),
        Schema::Build({
            {QStringLiteral("scheme"), Schema::String(QStringLiteral("URL scheme (http, https, etc)"))},
            {QStringLiteral("host"), Schema::String(QStringLiteral("Hostname"))},
            {QStringLiteral("port"), Schema::Integer(QStringLiteral("Port number"), 1, 65535)},
            {QStringLiteral("path"), Schema::String(QStringLiteral("URL path"))},
            {QStringLiteral("query_params"), Schema::Object(QStringLiteral("Query parameters as key-value object"))},
            {QStringLiteral("fragment"), Schema::String(QStringLiteral("URL fragment"))}
        }, {QStringLiteral("host")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QUrl Url;
            Url.setScheme(A.value(QStringLiteral("scheme")).toString(QStringLiteral("https")));
            Url.setHost(A.value(QStringLiteral("host")).toString());
            int Port = A.value(QStringLiteral("port")).toInt(-1);
            if (Port > 0) Url.setPort(Port);
            Url.setPath(A.value(QStringLiteral("path")).toString());
            if (A.contains(QStringLiteral("fragment"))) {
                Url.setFragment(A.value(QStringLiteral("fragment")).toString());
            }
            if (A.contains(QStringLiteral("query_params"))) {
                QUrlQuery Query;
                QJsonObject Params = A.value(QStringLiteral("query_params")).toObject();
                for (auto It = Params.constBegin(); It != Params.constEnd(); ++It) {
                    Query.addQueryItem(It.key(), It.value().toString());
                }
                Url.setQuery(Query);
            }
            QJsonObject Result;
            Result[QStringLiteral("url")] = Url.toString();
            return Result;
        });

    RegisterTool(QStringLiteral("decode_base64_payload"),
        QStringLiteral("Detect and decode base64-encoded strings within text data."),
        Schema::Build({
            {QStringLiteral("data"), Schema::String(QStringLiteral("Text data to scan for base64 content"))}
        }, {QStringLiteral("data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Data = A.value(QStringLiteral("data")).toString();
            QRegularExpression Re(QStringLiteral("(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})"));
            QRegularExpressionMatchIterator It = Re.globalMatch(Data);
            QJsonArray Matches;
            while (It.hasNext()) {
                QRegularExpressionMatch Match = It.next();
                QString Encoded = Match.captured(0);
                QByteArray Decoded = QByteArray::fromBase64(Encoded.toLatin1());
                bool IsPrintable = true;
                for (int I = 0; I < Decoded.size(); ++I) {
                    unsigned char C = static_cast<unsigned char>(Decoded[I]);
                    if (C < 0x20 && C != '\n' && C != '\r' && C != '\t') {
                        IsPrintable = false;
                        break;
                    }
                }
                QJsonObject MatchObj;
                MatchObj[QStringLiteral("encoded")] = Encoded;
                MatchObj[QStringLiteral("offset")] = Match.capturedStart();
                MatchObj[QStringLiteral("length")] = Encoded.length();
                if (IsPrintable) {
                    MatchObj[QStringLiteral("decoded_text")] = QString::fromUtf8(Decoded);
                }
                MatchObj[QStringLiteral("decoded_hex")] = QString::fromLatin1(Decoded.toHex(' '));
                MatchObj[QStringLiteral("decoded_size")] = Decoded.size();
                Matches.append(MatchObj);
            }
            QJsonObject Result;
            Result[QStringLiteral("count")] = Matches.size();
            Result[QStringLiteral("matches")] = Matches;
            return Result;
        });

    RegisterTool(QStringLiteral("extract_urls"),
        QStringLiteral("Extract all URLs from text using regex."),
        Schema::Build({
            {QStringLiteral("text"), Schema::String(QStringLiteral("Text to search for URLs"))}
        }, {QStringLiteral("text")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Text = A.value(QStringLiteral("text")).toString();
            QRegularExpression Re(QStringLiteral("https?://[^\\s<>\"'\\)\\]]+"));
            QRegularExpressionMatchIterator It = Re.globalMatch(Text);
            QJsonArray Urls;
            while (It.hasNext()) {
                QRegularExpressionMatch Match = It.next();
                QJsonObject Obj;
                Obj[QStringLiteral("url")] = Match.captured(0);
                Obj[QStringLiteral("offset")] = Match.capturedStart();
                Urls.append(Obj);
            }
            QJsonObject Result;
            Result[QStringLiteral("count")] = Urls.size();
            Result[QStringLiteral("urls")] = Urls;
            return Result;
        });

    RegisterTool(QStringLiteral("extract_emails"),
        QStringLiteral("Extract all email addresses from text using regex."),
        Schema::Build({
            {QStringLiteral("text"), Schema::String(QStringLiteral("Text to search for email addresses"))}
        }, {QStringLiteral("text")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Text = A.value(QStringLiteral("text")).toString();
            QRegularExpression Re(QStringLiteral("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"));
            QRegularExpressionMatchIterator It = Re.globalMatch(Text);
            QJsonArray Emails;
            while (It.hasNext()) {
                QRegularExpressionMatch Match = It.next();
                QJsonObject Obj;
                Obj[QStringLiteral("email")] = Match.captured(0);
                Obj[QStringLiteral("offset")] = Match.capturedStart();
                Emails.append(Obj);
            }
            QJsonObject Result;
            Result[QStringLiteral("count")] = Emails.size();
            Result[QStringLiteral("emails")] = Emails;
            return Result;
        });

    RegisterTool(QStringLiteral("extract_ip_addresses"),
        QStringLiteral("Extract all IPv4 and IPv6 addresses from text using regex."),
        Schema::Build({
            {QStringLiteral("text"), Schema::String(QStringLiteral("Text to search for IP addresses"))}
        }, {QStringLiteral("text")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Text = A.value(QStringLiteral("text")).toString();
            QRegularExpression Ipv4Re(QStringLiteral("\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"));
            QRegularExpression Ipv6Re(QStringLiteral("(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"));
            QJsonArray Addresses;
            QRegularExpressionMatchIterator It4 = Ipv4Re.globalMatch(Text);
            while (It4.hasNext()) {
                QRegularExpressionMatch Match = It4.next();
                QJsonObject Obj;
                Obj[QStringLiteral("address")] = Match.captured(0);
                Obj[QStringLiteral("type")] = QStringLiteral("IPv4");
                Obj[QStringLiteral("offset")] = Match.capturedStart();
                Addresses.append(Obj);
            }
            QRegularExpressionMatchIterator It6 = Ipv6Re.globalMatch(Text);
            while (It6.hasNext()) {
                QRegularExpressionMatch Match = It6.next();
                QJsonObject Obj;
                Obj[QStringLiteral("address")] = Match.captured(0);
                Obj[QStringLiteral("type")] = QStringLiteral("IPv6");
                Obj[QStringLiteral("offset")] = Match.capturedStart();
                Addresses.append(Obj);
            }
            QJsonObject Result;
            Result[QStringLiteral("count")] = Addresses.size();
            Result[QStringLiteral("addresses")] = Addresses;
            return Result;
        });

    RegisterTool(QStringLiteral("parse_http_request"),
        QStringLiteral("Parse a raw HTTP request string into method, path, version, headers, and body."),
        Schema::Build({
            {QStringLiteral("raw_request"), Schema::String(QStringLiteral("Raw HTTP request text"))}
        }, {QStringLiteral("raw_request")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Raw = A.value(QStringLiteral("raw_request")).toString();
            int HeaderEnd = Raw.indexOf(QStringLiteral("\r\n\r\n"));
            if (HeaderEnd < 0) HeaderEnd = Raw.indexOf(QStringLiteral("\n\n"));
            QString HeaderPart = (HeaderEnd >= 0) ? Raw.left(HeaderEnd) : Raw;
            QString Body = (HeaderEnd >= 0) ? Raw.mid(HeaderEnd).trimmed() : QString();
            QString Sep = HeaderPart.contains(QStringLiteral("\r\n")) ? QStringLiteral("\r\n") : QStringLiteral("\n");
            QStringList Lines = HeaderPart.split(Sep);
            if (Lines.isEmpty()) return Schema::Err(QStringLiteral("Empty request"));
            QStringList RequestLine = Lines[0].split(' ');
            if (RequestLine.size() < 2) return Schema::Err(QStringLiteral("Invalid request line"));
            QJsonObject Result;
            Result[QStringLiteral("method")] = RequestLine[0];
            Result[QStringLiteral("path")] = RequestLine[1];
            Result[QStringLiteral("version")] = (RequestLine.size() >= 3) ? RequestLine[2] : QStringLiteral("HTTP/1.1");
            QJsonObject Headers;
            for (int I = 1; I < Lines.size(); ++I) {
                int ColonPos = Lines[I].indexOf(':');
                if (ColonPos > 0) {
                    QString Key = Lines[I].left(ColonPos).trimmed();
                    QString Value = Lines[I].mid(ColonPos + 1).trimmed();
                    Headers[Key] = Value;
                }
            }
            Result[QStringLiteral("headers")] = Headers;
            Result[QStringLiteral("body")] = Body;
            Result[QStringLiteral("header_count")] = Headers.size();
            return Result;
        });

    RegisterTool(QStringLiteral("parse_http_response"),
        QStringLiteral("Parse a raw HTTP response into status code, reason, headers, and body."),
        Schema::Build({
            {QStringLiteral("raw_response"), Schema::String(QStringLiteral("Raw HTTP response text"))}
        }, {QStringLiteral("raw_response")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Raw = A.value(QStringLiteral("raw_response")).toString();
            int HeaderEnd = Raw.indexOf(QStringLiteral("\r\n\r\n"));
            if (HeaderEnd < 0) HeaderEnd = Raw.indexOf(QStringLiteral("\n\n"));
            QString HeaderPart = (HeaderEnd >= 0) ? Raw.left(HeaderEnd) : Raw;
            QString Body = (HeaderEnd >= 0) ? Raw.mid(HeaderEnd).trimmed() : QString();
            QString Sep = HeaderPart.contains(QStringLiteral("\r\n")) ? QStringLiteral("\r\n") : QStringLiteral("\n");
            QStringList Lines = HeaderPart.split(Sep);
            if (Lines.isEmpty()) return Schema::Err(QStringLiteral("Empty response"));
            QStringList StatusLine = Lines[0].split(' ');
            if (StatusLine.size() < 2) return Schema::Err(QStringLiteral("Invalid status line"));
            QJsonObject Result;
            Result[QStringLiteral("version")] = StatusLine[0];
            Result[QStringLiteral("status_code")] = StatusLine[1].toInt();
            Result[QStringLiteral("reason")] = (StatusLine.size() >= 3) ? QStringList(StatusLine.mid(2)).join(' ') : QString();
            QJsonObject Headers;
            for (int I = 1; I < Lines.size(); ++I) {
                int ColonPos = Lines[I].indexOf(':');
                if (ColonPos > 0) {
                    QString Key = Lines[I].left(ColonPos).trimmed();
                    QString Value = Lines[I].mid(ColonPos + 1).trimmed();
                    Headers[Key] = Value;
                }
            }
            Result[QStringLiteral("headers")] = Headers;
            Result[QStringLiteral("body")] = Body;
            Result[QStringLiteral("body_length")] = Body.length();
            return Result;
        });

    RegisterTool(QStringLiteral("build_http_request"),
        QStringLiteral("Build a raw HTTP request string from method, path, headers, and body."),
        Schema::Build({
            {QStringLiteral("method"), Schema::String(QStringLiteral("HTTP method"))},
            {QStringLiteral("path"), Schema::String(QStringLiteral("Request path"))},
            {QStringLiteral("version"), Schema::String(QStringLiteral("HTTP version (default HTTP/1.1)"))},
            {QStringLiteral("headers"), Schema::Object(QStringLiteral("Headers as key-value object"))},
            {QStringLiteral("body"), Schema::String(QStringLiteral("Request body"))}
        }, {QStringLiteral("method"), QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Method = A.value(QStringLiteral("method")).toString();
            QString Path = A.value(QStringLiteral("path")).toString();
            QString Version = A.value(QStringLiteral("version")).toString(QStringLiteral("HTTP/1.1"));
            QJsonObject Headers = A.value(QStringLiteral("headers")).toObject();
            QString Body = A.value(QStringLiteral("body")).toString();
            QString Request = Method + QStringLiteral(" ") + Path + QStringLiteral(" ") + Version + QStringLiteral("\r\n");
            for (auto It = Headers.constBegin(); It != Headers.constEnd(); ++It) {
                Request += It.key() + QStringLiteral(": ") + It.value().toString() + QStringLiteral("\r\n");
            }
            Request += QStringLiteral("\r\n");
            if (!Body.isEmpty()) Request += Body;
            QJsonObject Result;
            Result[QStringLiteral("raw_request")] = Request;
            Result[QStringLiteral("length")] = Request.length();
            return Result;
        });

    RegisterTool(QStringLiteral("build_http_response"),
        QStringLiteral("Build a raw HTTP response string from status code, reason, headers, and body."),
        Schema::Build({
            {QStringLiteral("status_code"), Schema::Integer(QStringLiteral("HTTP status code"), 100, 599)},
            {QStringLiteral("reason"), Schema::String(QStringLiteral("Reason phrase"))},
            {QStringLiteral("version"), Schema::String(QStringLiteral("HTTP version (default HTTP/1.1)"))},
            {QStringLiteral("headers"), Schema::Object(QStringLiteral("Headers as key-value object"))},
            {QStringLiteral("body"), Schema::String(QStringLiteral("Response body"))}
        }, {QStringLiteral("status_code")}),
        [this](const QJsonObject& A) -> QJsonValue {
            int StatusCode = A.value(QStringLiteral("status_code")).toInt();
            QString Reason = A.value(QStringLiteral("reason")).toString(QStringLiteral("OK"));
            QString Version = A.value(QStringLiteral("version")).toString(QStringLiteral("HTTP/1.1"));
            QJsonObject Headers = A.value(QStringLiteral("headers")).toObject();
            QString Body = A.value(QStringLiteral("body")).toString();
            QString Response = Version + QStringLiteral(" ") + QString::number(StatusCode) + QStringLiteral(" ") + Reason + QStringLiteral("\r\n");
            for (auto It = Headers.constBegin(); It != Headers.constEnd(); ++It) {
                Response += It.key() + QStringLiteral(": ") + It.value().toString() + QStringLiteral("\r\n");
            }
            Response += QStringLiteral("\r\n");
            if (!Body.isEmpty()) Response += Body;
            QJsonObject Result;
            Result[QStringLiteral("raw_response")] = Response;
            Result[QStringLiteral("length")] = Response.length();
            return Result;
        });

    RegisterTool(QStringLiteral("analyze_headers"),
        QStringLiteral("Analyze HTTP response headers for security issues (missing CSP, HSTS, X-Frame-Options, etc)."),
        Schema::Build({
            {QStringLiteral("headers"), Schema::Object(QStringLiteral("HTTP response headers as key-value object"))}
        }, {QStringLiteral("headers")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QJsonObject Headers = A.value(QStringLiteral("headers")).toObject();
            QJsonArray Issues;
            QJsonArray Good;
            auto Check = [&](const QString& Header, const QString& Desc) {
                bool Found = false;
                for (auto It = Headers.constBegin(); It != Headers.constEnd(); ++It) {
                    if (It.key().compare(Header, Qt::CaseInsensitive) == 0) {
                        Found = true;
                        QJsonObject G;
                        G[QStringLiteral("header")] = Header;
                        G[QStringLiteral("value")] = It.value().toString();
                        G[QStringLiteral("status")] = QStringLiteral("present");
                        Good.append(G);
                        break;
                    }
                }
                if (!Found) {
                    QJsonObject Issue;
                    Issue[QStringLiteral("header")] = Header;
                    Issue[QStringLiteral("severity")] = QStringLiteral("medium");
                    Issue[QStringLiteral("description")] = Desc;
                    Issues.append(Issue);
                }
            };
            Check(QStringLiteral("Content-Security-Policy"), QStringLiteral("Missing CSP header. XSS protection not enforced."));
            Check(QStringLiteral("Strict-Transport-Security"), QStringLiteral("Missing HSTS header. Downgrade attacks possible."));
            Check(QStringLiteral("X-Frame-Options"), QStringLiteral("Missing X-Frame-Options. Clickjacking possible."));
            Check(QStringLiteral("X-Content-Type-Options"), QStringLiteral("Missing X-Content-Type-Options. MIME sniffing possible."));
            Check(QStringLiteral("X-XSS-Protection"), QStringLiteral("Missing X-XSS-Protection header."));
            Check(QStringLiteral("Referrer-Policy"), QStringLiteral("Missing Referrer-Policy. Referrer leakage possible."));
            Check(QStringLiteral("Permissions-Policy"), QStringLiteral("Missing Permissions-Policy header."));
            for (auto It = Headers.constBegin(); It != Headers.constEnd(); ++It) {
                if (It.key().compare(QStringLiteral("Server"), Qt::CaseInsensitive) == 0) {
                    QJsonObject Issue;
                    Issue[QStringLiteral("header")] = QStringLiteral("Server");
                    Issue[QStringLiteral("severity")] = QStringLiteral("low");
                    Issue[QStringLiteral("description")] = QStringLiteral("Server header exposes server software: ") + It.value().toString();
                    Issues.append(Issue);
                }
                if (It.key().compare(QStringLiteral("X-Powered-By"), Qt::CaseInsensitive) == 0) {
                    QJsonObject Issue;
                    Issue[QStringLiteral("header")] = QStringLiteral("X-Powered-By");
                    Issue[QStringLiteral("severity")] = QStringLiteral("low");
                    Issue[QStringLiteral("description")] = QStringLiteral("X-Powered-By exposes technology: ") + It.value().toString();
                    Issues.append(Issue);
                }
            }
            QJsonObject Result;
            Result[QStringLiteral("issues")] = Issues;
            Result[QStringLiteral("issue_count")] = Issues.size();
            Result[QStringLiteral("good")] = Good;
            Result[QStringLiteral("good_count")] = Good.size();
            return Result;
        });

    RegisterTool(QStringLiteral("detect_waf"),
        QStringLiteral("Detect WAF (Web Application Firewall) from HTTP response headers."),
        Schema::Build({
            {QStringLiteral("headers"), Schema::Object(QStringLiteral("HTTP response headers as key-value object"))}
        }, {QStringLiteral("headers")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QJsonObject Headers = A.value(QStringLiteral("headers")).toObject();
            QJsonArray Detected;
            struct WafSignature {
                QString Header;
                QString Pattern;
                QString Name;
            };
            QList<WafSignature> Signatures = {
                {QStringLiteral("Server"), QStringLiteral("cloudflare"), QStringLiteral("Cloudflare")},
                {QStringLiteral("cf-ray"), QString(), QStringLiteral("Cloudflare")},
                {QStringLiteral("cf-cache-status"), QString(), QStringLiteral("Cloudflare")},
                {QStringLiteral("Server"), QStringLiteral("AkamaiGHost"), QStringLiteral("Akamai")},
                {QStringLiteral("X-Akamai-Transformed"), QString(), QStringLiteral("Akamai")},
                {QStringLiteral("Server"), QStringLiteral("AWS"), QStringLiteral("AWS WAF")},
                {QStringLiteral("x-amzn-RequestId"), QString(), QStringLiteral("AWS")},
                {QStringLiteral("X-Sucuri-ID"), QString(), QStringLiteral("Sucuri")},
                {QStringLiteral("Server"), QStringLiteral("Sucuri"), QStringLiteral("Sucuri")},
                {QStringLiteral("X-CDN"), QStringLiteral("Incapsula"), QStringLiteral("Imperva Incapsula")},
                {QStringLiteral("X-Iinfo"), QString(), QStringLiteral("Imperva Incapsula")},
                {QStringLiteral("Server"), QStringLiteral("nginx"), QStringLiteral("Nginx")},
                {QStringLiteral("Server"), QStringLiteral("Apache"), QStringLiteral("Apache")},
                {QStringLiteral("X-Powered-By-Plesk"), QString(), QStringLiteral("Plesk")},
                {QStringLiteral("Server"), QStringLiteral("F5"), QStringLiteral("F5 BIG-IP")},
                {QStringLiteral("X-Fw-Serve"), QString(), QStringLiteral("Fortinet FortiWeb")},
                {QStringLiteral("Server"), QStringLiteral("Barracuda"), QStringLiteral("Barracuda WAF")},
            };
            QSet<QString> Found;
            for (const auto& Sig : Signatures) {
                for (auto It = Headers.constBegin(); It != Headers.constEnd(); ++It) {
                    if (It.key().compare(Sig.Header, Qt::CaseInsensitive) == 0) {
                        if (Sig.Pattern.isEmpty() || It.value().toString().contains(Sig.Pattern, Qt::CaseInsensitive)) {
                            if (!Found.contains(Sig.Name)) {
                                Found.insert(Sig.Name);
                                QJsonObject Det;
                                Det[QStringLiteral("waf")] = Sig.Name;
                                Det[QStringLiteral("detected_via")] = It.key() + QStringLiteral(": ") + It.value().toString();
                                Detected.append(Det);
                            }
                        }
                    }
                }
            }
            QJsonObject Result;
            Result[QStringLiteral("detected")] = Detected;
            Result[QStringLiteral("count")] = Detected.size();
            Result[QStringLiteral("has_waf")] = Detected.size() > 0;
            return Result;
        });

    RegisterTool(QStringLiteral("parse_cookie"),
        QStringLiteral("Parse a Set-Cookie header into name, value, domain, path, flags."),
        Schema::Build({
            {QStringLiteral("set_cookie"), Schema::String(QStringLiteral("Set-Cookie header value"))}
        }, {QStringLiteral("set_cookie")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Cookie = A.value(QStringLiteral("set_cookie")).toString();
            QStringList Parts = Cookie.split(';');
            if (Parts.isEmpty()) return Schema::Err(QStringLiteral("Empty cookie"));
            QJsonObject Result;
            QString NameVal = Parts[0].trimmed();
            int EqPos = NameVal.indexOf('=');
            if (EqPos > 0) {
                Result[QStringLiteral("name")] = NameVal.left(EqPos);
                Result[QStringLiteral("value")] = NameVal.mid(EqPos + 1);
            } else {
                Result[QStringLiteral("name")] = NameVal;
                Result[QStringLiteral("value")] = QString();
            }
            QJsonArray Flags;
            for (int I = 1; I < Parts.size(); ++I) {
                QString Attr = Parts[I].trimmed();
                QString AttrLower = Attr.toLower();
                if (AttrLower.startsWith(QStringLiteral("domain="))) {
                    Result[QStringLiteral("domain")] = Attr.mid(7);
                } else if (AttrLower.startsWith(QStringLiteral("path="))) {
                    Result[QStringLiteral("path")] = Attr.mid(5);
                } else if (AttrLower.startsWith(QStringLiteral("expires="))) {
                    Result[QStringLiteral("expires")] = Attr.mid(8);
                } else if (AttrLower.startsWith(QStringLiteral("max-age="))) {
                    Result[QStringLiteral("max_age")] = Attr.mid(8).toInt();
                } else if (AttrLower.startsWith(QStringLiteral("samesite="))) {
                    Result[QStringLiteral("samesite")] = Attr.mid(9);
                } else if (AttrLower == QStringLiteral("secure")) {
                    Flags.append(QStringLiteral("Secure"));
                } else if (AttrLower == QStringLiteral("httponly")) {
                    Flags.append(QStringLiteral("HttpOnly"));
                } else {
                    Flags.append(Attr);
                }
            }
            Result[QStringLiteral("flags")] = Flags;
            return Result;
        });

    RegisterTool(QStringLiteral("build_cookie"),
        QStringLiteral("Build a Cookie header from name-value pairs."),
        Schema::Build({
            {QStringLiteral("cookies"), Schema::Object(QStringLiteral("Cookie name-value pairs as object"))}
        }, {QStringLiteral("cookies")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QJsonObject Cookies = A.value(QStringLiteral("cookies")).toObject();
            QStringList Parts;
            for (auto It = Cookies.constBegin(); It != Cookies.constEnd(); ++It) {
                Parts.append(It.key() + QStringLiteral("=") + It.value().toString());
            }
            QJsonObject Result;
            Result[QStringLiteral("cookie_header")] = Parts.join(QStringLiteral("; "));
            Result[QStringLiteral("count")] = Cookies.size();
            return Result;
        });

    RegisterTool(QStringLiteral("calculate_content_length"),
        QStringLiteral("Calculate the byte length of a request/response body."),
        Schema::Build({
            {QStringLiteral("body"), Schema::String(QStringLiteral("Body text to measure"))},
            {QStringLiteral("encoding"), Schema::StringEnum(QStringLiteral("Text encoding"), {QStringLiteral("utf-8"), QStringLiteral("ascii"), QStringLiteral("latin1")})}
        }, {QStringLiteral("body")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Body = A.value(QStringLiteral("body")).toString();
            QString Encoding = A.value(QStringLiteral("encoding")).toString(QStringLiteral("utf-8"));
            QByteArray Bytes;
            if (Encoding == QStringLiteral("latin1")) {
                Bytes = Body.toLatin1();
            } else {
                Bytes = Body.toUtf8();
            }
            QJsonObject Result;
            Result[QStringLiteral("content_length")] = Bytes.size();
            Result[QStringLiteral("encoding")] = Encoding;
            return Result;
        });

    RegisterTool(QStringLiteral("url_encode_params"),
        QStringLiteral("URL-encode a set of key-value parameters into a query string."),
        Schema::Build({
            {QStringLiteral("params"), Schema::Object(QStringLiteral("Key-value parameters to URL-encode"))}
        }, {QStringLiteral("params")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QJsonObject Params = A.value(QStringLiteral("params")).toObject();
            QUrlQuery Query;
            for (auto It = Params.constBegin(); It != Params.constEnd(); ++It) {
                Query.addQueryItem(It.key(), It.value().toString());
            }
            QJsonObject Result;
            Result[QStringLiteral("encoded")] = Query.toString(QUrl::FullyEncoded);
            Result[QStringLiteral("param_count")] = Params.size();
            return Result;
        });

    RegisterTool(QStringLiteral("url_decode_params"),
        QStringLiteral("URL-decode a query string into key-value pairs."),
        Schema::Build({
            {QStringLiteral("query_string"), Schema::String(QStringLiteral("URL-encoded query string"))}
        }, {QStringLiteral("query_string")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Qs = A.value(QStringLiteral("query_string")).toString();
            if (Qs.startsWith('?')) Qs = Qs.mid(1);
            QUrlQuery Query(Qs);
            QJsonObject Params;
            QJsonArray ParamsArr;
            for (const auto& Pair : Query.queryItems(QUrl::FullyDecoded)) {
                Params[Pair.first] = Pair.second;
                QJsonObject P;
                P[QStringLiteral("key")] = Pair.first;
                P[QStringLiteral("value")] = Pair.second;
                ParamsArr.append(P);
            }
            QJsonObject Result;
            Result[QStringLiteral("params")] = Params;
            Result[QStringLiteral("params_list")] = ParamsArr;
            Result[QStringLiteral("count")] = ParamsArr.size();
            return Result;
        });

    RegisterTool(QStringLiteral("parse_multipart"),
        QStringLiteral("Parse a multipart/form-data body into its parts."),
        Schema::Build({
            {QStringLiteral("body"), Schema::String(QStringLiteral("Multipart body content"))},
            {QStringLiteral("boundary"), Schema::String(QStringLiteral("Multipart boundary string"))}
        }, {QStringLiteral("body"), QStringLiteral("boundary")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Body = A.value(QStringLiteral("body")).toString();
            QString Boundary = A.value(QStringLiteral("boundary")).toString();
            QString Delimiter = QStringLiteral("--") + Boundary;
            QStringList Sections = Body.split(Delimiter);
            QJsonArray Parts;
            for (int I = 1; I < Sections.size(); ++I) {
                QString Section = Sections[I];
                if (Section.trimmed() == QStringLiteral("--") || Section.trimmed().isEmpty()) continue;
                if (Section.startsWith(QStringLiteral("\r\n"))) Section = Section.mid(2);
                else if (Section.startsWith('\n')) Section = Section.mid(1);
                int BodyStart = Section.indexOf(QStringLiteral("\r\n\r\n"));
                if (BodyStart < 0) BodyStart = Section.indexOf(QStringLiteral("\n\n"));
                if (BodyStart < 0) continue;
                QString HeaderSection = Section.left(BodyStart);
                QString PartBody = Section.mid(BodyStart).trimmed();
                if (PartBody.endsWith(QStringLiteral("\r\n"))) PartBody.chop(2);
                else if (PartBody.endsWith('\n')) PartBody.chop(1);
                QJsonObject Part;
                QJsonObject PartHeaders;
                QString HeaderSep = HeaderSection.contains(QStringLiteral("\r\n")) ? QStringLiteral("\r\n") : QStringLiteral("\n");
                for (const QString& Line : HeaderSection.split(HeaderSep)) {
                    int ColonPos = Line.indexOf(':');
                    if (ColonPos > 0) {
                        PartHeaders[Line.left(ColonPos).trimmed()] = Line.mid(ColonPos + 1).trimmed();
                    }
                }
                Part[QStringLiteral("headers")] = PartHeaders;
                Part[QStringLiteral("body")] = PartBody;
                Part[QStringLiteral("body_length")] = PartBody.length();
                QString Disposition = PartHeaders.value(QStringLiteral("Content-Disposition")).toString();
                QRegularExpression NameRe(QStringLiteral("name=\"([^\"]+)\""));
                QRegularExpressionMatch NameMatch = NameRe.match(Disposition);
                if (NameMatch.hasMatch()) Part[QStringLiteral("name")] = NameMatch.captured(1);
                QRegularExpression FileRe(QStringLiteral("filename=\"([^\"]+)\""));
                QRegularExpressionMatch FileMatch = FileRe.match(Disposition);
                if (FileMatch.hasMatch()) Part[QStringLiteral("filename")] = FileMatch.captured(1);
                Parts.append(Part);
            }
            QJsonObject Result;
            Result[QStringLiteral("parts")] = Parts;
            Result[QStringLiteral("count")] = Parts.size();
            return Result;
        });

    RegisterTool(QStringLiteral("generate_boundary"),
        QStringLiteral("Generate a random multipart boundary string."),
        Schema::Empty(),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(A);
            QString Chars = QStringLiteral("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
            QString Boundary = QStringLiteral("----FidraBoundary");
            for (int I = 0; I < 24; ++I) {
                Boundary += Chars[QRandomGenerator::global()->bounded(Chars.length())];
            }
            QJsonObject Result;
            Result[QStringLiteral("boundary")] = Boundary;
            Result[QStringLiteral("content_type")] = QStringLiteral("multipart/form-data; boundary=") + Boundary;
            return Result;
        });

    RegisterTool(QStringLiteral("format_json"),
        QStringLiteral("Pretty-print a JSON string with indentation."),
        Schema::Build({
            {QStringLiteral("json"), Schema::String(QStringLiteral("JSON string to format"))}
        }, {QStringLiteral("json")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Input = A.value(QStringLiteral("json")).toString();
            QJsonParseError Err;
            QJsonDocument Doc = QJsonDocument::fromJson(Input.toUtf8(), &Err);
            if (Err.error != QJsonParseError::NoError) {
                return Schema::Err(QStringLiteral("Invalid JSON: ") + Err.errorString() + QStringLiteral(" at offset ") + QString::number(Err.offset));
            }
            QJsonObject Result;
            Result[QStringLiteral("formatted")] = QString::fromUtf8(Doc.toJson(QJsonDocument::Indented));
            return Result;
        });

    RegisterTool(QStringLiteral("minify_json"),
        QStringLiteral("Minify/compact a JSON string by removing whitespace."),
        Schema::Build({
            {QStringLiteral("json"), Schema::String(QStringLiteral("JSON string to minify"))}
        }, {QStringLiteral("json")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Input = A.value(QStringLiteral("json")).toString();
            QJsonParseError Err;
            QJsonDocument Doc = QJsonDocument::fromJson(Input.toUtf8(), &Err);
            if (Err.error != QJsonParseError::NoError) {
                return Schema::Err(QStringLiteral("Invalid JSON: ") + Err.errorString() + QStringLiteral(" at offset ") + QString::number(Err.offset));
            }
            QJsonObject Result;
            Result[QStringLiteral("minified")] = QString::fromUtf8(Doc.toJson(QJsonDocument::Compact));
            Result[QStringLiteral("original_length")] = Input.length();
            Result[QStringLiteral("minified_length")] = static_cast<int>(Doc.toJson(QJsonDocument::Compact).size());
            return Result;
        });

    RegisterTool(QStringLiteral("validate_json"),
        QStringLiteral("Validate a JSON string. Returns whether it is valid and any parse error."),
        Schema::Build({
            {QStringLiteral("json"), Schema::String(QStringLiteral("JSON string to validate"))}
        }, {QStringLiteral("json")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Input = A.value(QStringLiteral("json")).toString();
            QJsonParseError Err;
            QJsonDocument Doc = QJsonDocument::fromJson(Input.toUtf8(), &Err);
            QJsonObject Result;
            Result[QStringLiteral("valid")] = (Err.error == QJsonParseError::NoError);
            if (Err.error != QJsonParseError::NoError) {
                Result[QStringLiteral("error")] = Err.errorString();
                Result[QStringLiteral("offset")] = Err.offset;
            } else {
                Result[QStringLiteral("type")] = Doc.isObject() ? QStringLiteral("object") : (Doc.isArray() ? QStringLiteral("array") : QStringLiteral("other"));
                if (Doc.isObject()) Result[QStringLiteral("key_count")] = Doc.object().size();
                if (Doc.isArray()) Result[QStringLiteral("element_count")] = Doc.array().size();
            }
            Q_UNUSED(Doc);
            return Result;
        });

    RegisterTool(QStringLiteral("compare_json"),
        QStringLiteral("Compare two JSON objects and return differences (added, removed, changed keys)."),
        Schema::Build({
            {QStringLiteral("json_a"), Schema::String(QStringLiteral("First JSON string"))},
            {QStringLiteral("json_b"), Schema::String(QStringLiteral("Second JSON string"))}
        }, {QStringLiteral("json_a"), QStringLiteral("json_b")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QJsonParseError Err1, Err2;
            QJsonDocument DocA = QJsonDocument::fromJson(A.value(QStringLiteral("json_a")).toString().toUtf8(), &Err1);
            QJsonDocument DocB = QJsonDocument::fromJson(A.value(QStringLiteral("json_b")).toString().toUtf8(), &Err2);
            if (Err1.error != QJsonParseError::NoError) return Schema::Err(QStringLiteral("Invalid JSON A: ") + Err1.errorString());
            if (Err2.error != QJsonParseError::NoError) return Schema::Err(QStringLiteral("Invalid JSON B: ") + Err2.errorString());
            if (!DocA.isObject() || !DocB.isObject()) {
                QJsonObject Result;
                Result[QStringLiteral("identical")] = (DocA == DocB);
                Result[QStringLiteral("note")] = QStringLiteral("Detailed diff only available for JSON objects");
                return Result;
            }
            QJsonObject ObjA = DocA.object();
            QJsonObject ObjB = DocB.object();
            QJsonArray Added;
            QJsonArray Removed;
            QJsonArray Changed;
            QJsonArray Unchanged;
            for (auto It = ObjA.constBegin(); It != ObjA.constEnd(); ++It) {
                if (!ObjB.contains(It.key())) {
                    QJsonObject Entry;
                    Entry[QStringLiteral("key")] = It.key();
                    Entry[QStringLiteral("value")] = It.value();
                    Removed.append(Entry);
                } else if (ObjB.value(It.key()) != It.value()) {
                    QJsonObject Entry;
                    Entry[QStringLiteral("key")] = It.key();
                    Entry[QStringLiteral("old_value")] = It.value();
                    Entry[QStringLiteral("new_value")] = ObjB.value(It.key());
                    Changed.append(Entry);
                } else {
                    Unchanged.append(It.key());
                }
            }
            for (auto It = ObjB.constBegin(); It != ObjB.constEnd(); ++It) {
                if (!ObjA.contains(It.key())) {
                    QJsonObject Entry;
                    Entry[QStringLiteral("key")] = It.key();
                    Entry[QStringLiteral("value")] = It.value();
                    Added.append(Entry);
                }
            }
            QJsonObject Result;
            Result[QStringLiteral("identical")] = (Added.isEmpty() && Removed.isEmpty() && Changed.isEmpty());
            Result[QStringLiteral("added")] = Added;
            Result[QStringLiteral("removed")] = Removed;
            Result[QStringLiteral("changed")] = Changed;
            Result[QStringLiteral("unchanged_keys")] = Unchanged;
            Result[QStringLiteral("added_count")] = Added.size();
            Result[QStringLiteral("removed_count")] = Removed.size();
            Result[QStringLiteral("changed_count")] = Changed.size();
            Result[QStringLiteral("unchanged_count")] = Unchanged.size();
            return Result;
        });
}

}
