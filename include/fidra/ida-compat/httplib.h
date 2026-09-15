#pragma once
// Minimal cpp-httplib stub — matches enough API surface for graphrag's
// EmbeddingClient. Real remote calls become no-ops; embedding path will fall
// back to LocalVectorizer. Replace with real cpp-httplib if remote embeddings
// are needed at runtime.

#include <string>
#include <memory>
#include <map>
#include <functional>

namespace httplib {

struct Response {
    int status = 0;
    std::string body;
    std::map<std::string, std::string> headers;
    bool operator!() const { return status < 200 || status >= 300; }
    explicit operator bool() const { return status >= 200 && status < 300; }
};

struct Result {
    std::shared_ptr<Response> resp;
    int error_code = -1;
    Result() = default;
    bool operator!() const { return !resp || !*resp; }
    explicit operator bool() const { return !!*this; }
    Response* operator->() const { return resp.get(); }
    Response& operator*() const { return *resp; }
    int error() const { return error_code; }
};

using Headers = std::map<std::string, std::string>;

class Client {
public:
    explicit Client(const std::string& host) : m_host(host) {}
    Client(const std::string& host, int port) : m_host(host), m_port(port) {}

    void set_read_timeout(int /*sec*/, int /*usec*/ = 0) {}
    void set_write_timeout(int /*sec*/, int /*usec*/ = 0) {}
    void set_connection_timeout(int /*sec*/, int /*usec*/ = 0) {}
    void set_follow_location(bool /*b*/) {}
    void set_default_headers(const Headers& /*h*/) {}
    void enable_server_certificate_verification(bool /*b*/) {}
    void set_tcp_nodelay(bool /*b*/) {}
    void set_keep_alive(bool /*b*/) {}
    void set_decompress(bool /*b*/) {}
    void set_compress(bool /*b*/) {}
    void set_bearer_token_auth(const std::string& /*t*/) {}
    void set_basic_auth(const std::string& /*u*/, const std::string& /*p*/) {}

    Result Get(const std::string& /*path*/) { return {}; }
    Result Get(const std::string& /*path*/, const Headers& /*h*/) { return {}; }
    Result Post(const std::string& /*path*/, const std::string& /*body*/, const std::string& /*ct*/) { return {}; }
    Result Post(const std::string& /*path*/, const Headers& /*h*/, const std::string& /*body*/, const std::string& /*ct*/) { return {}; }
    Result Post(const std::string& /*path*/, const char* /*body*/, size_t /*len*/, const std::string& /*ct*/) { return {}; }
    Result Post(const std::string& /*path*/, const Headers& /*h*/, const char* /*body*/, size_t /*len*/, const std::string& /*ct*/) { return {}; }

private:
    std::string m_host;
    int m_port = 80;
};

class SSLClient : public Client { public: using Client::Client; };

}
