#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace PacketUtils
{
inline constexpr uint8_t VERSION = 1;
inline constexpr size_t HEADER_SIZE = 23;
inline constexpr uint32_t MAX_PAYLOAD_SIZE = 0xFFFFFFFF;
inline constexpr uint64_t MAX_PACKET_SIZE =
    HEADER_SIZE + static_cast<uint64_t>(MAX_PAYLOAD_SIZE);

enum FIELD_SIZE
{
    CLIENT_ID_SIZE = 16,
    VERSION_SIZE = 1,
    OP_SIZE = 2,
    PAYLOAD_SIZE = 4,
    NAME = 255
};

enum RequestOp
{
    OP_SIGN_UP = 1025,
    OP_GET_KEY,
    OP_SIGN_IN,
    OP_CRC_VERIFYING,
    OP_CRC_SUCCESS,
    OP_CRC_RETRY,
    OP_CRC_FAILURE
};

class ClientName
{
public:
    explicit ClientName(const std::string &name) : name_(name) {}

    std::string get() const { return name_; }

private:
    std::string name_;
};

class FileName
{
public:
    explicit FileName(const std::string &name) : name_(name) {}

    std::string get() const { return name_; }

private:
    std::string name_;
};

class FileContent
{
public:
    explicit FileContent(const std::string &content) : content_(content) {}

    std::string get() const { return content_; }

private:
    std::string content_;
};

class ClientID
{
public:
    explicit ClientID(const std::array<unsigned char, CLIENT_ID_SIZE> &id)
        : id_(id)
    {
    }

    std::array<unsigned char, CLIENT_ID_SIZE> get() const { return id_; }

private:
    std::array<unsigned char, CLIENT_ID_SIZE> id_;
};

class PublicKey
{
public:
    explicit PublicKey(const std::string &key) : key_(key) {}

    std::string get() const { return key_; }

private:
    std::string key_;
};

// ==============================================

// Base class for all packets
class Packet
{
public:
    // All packets have a client id, operation code and payload size
    Packet() = delete;
    virtual ~Packet() = default;
    virtual void print() const = 0;
    virtual std::vector<uint8_t> pack() const = 0;
    const std::string getOp() const;

protected:
    // should be called through the derrived class + the factory method
    Packet(const std::array<unsigned char, CLIENT_ID_SIZE> &client_id,
           uint16_t op, uint32_t payload_size);

    virtual const std::string prepareLog() const;

    std::array<unsigned char, CLIENT_ID_SIZE> client_id_;
    uint8_t version_;
    uint16_t op_;
    uint32_t payload_size_;
};

// ==================== PacketWithClientName ====================

class PacketWithClientName : public Packet
{
public:
    static std::unique_ptr<Packet> createUnique(const ClientID &clientID,
                                                const RequestOp op,
                                                const ClientName &clientName);

protected:
    PacketWithClientName(
        const std::array<unsigned char, CLIENT_ID_SIZE> &client_id, uint16_t op,
        const std::string &client_name);
    void print() const override;
    std::vector<uint8_t> pack() const override;

    std::array<char, FIELD_SIZE::NAME> client_name_;
};

// ==================== PacketWithPublicKey ====================
class PacketWithPublicKey : public PacketWithClientName
{
public:
    static std::unique_ptr<Packet> createUnique(const ClientID &clientID,
                                                const ClientName &clientName,
                                                const PublicKey &publicKey);

    void print() const override;
    std::vector<uint8_t> pack() const override;

private:
    PacketWithPublicKey(
        const std::array<unsigned char, CLIENT_ID_SIZE> &client_id,
        const std::string &client_name, const std::string &public_key);

    std::string public_key_;
};

// ==================== PacketWithFileName ====================
class PacketWithFileName : public Packet
{
public:
    static std::unique_ptr<Packet> createUnique(const ClientID &clientID,
                                                const RequestOp op,
                                                const FileName &fileName);

    void print() const override;
    std::vector<uint8_t> pack() const override;

protected:
    PacketWithFileName(
        const std::array<unsigned char, CLIENT_ID_SIZE> &client_id, uint16_t op,
        const std::string &file_name);
    const std::string prepareLog() const override;

    std::array<char, FIELD_SIZE::NAME> file_name_;
};

// ==================== PacketWithFile ====================
class PacketWithFile : public PacketWithFileName
{
public:
    static std::unique_ptr<Packet> createUnique(const ClientID &clientID,
                                                const FileName &fileName,
                                                const FileContent &fileContent);

    void print() const override;
    std::vector<uint8_t> pack() const override;

private:
    PacketWithFile(const std::array<unsigned char, CLIENT_ID_SIZE> &client_id,
                   const std::string &file_name, const std::string &file);

    std::vector<char> file_content_;
};

}  // namespace PacketUtils