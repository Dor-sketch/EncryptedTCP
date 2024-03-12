#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

enum ResponseStatus
{
    STATUS_SIGN_UP_SUCCESS = 2100,
    STATUS_SIGN_UP_FAILURE = 2101,
    STATUS_AES_KEY_RECIEVED = 2102,
    STATUS_FILE_RECIEVED = 2103,
    STATUS_ACKNOWLEDGEMENT = 2104,
    STATUS_SIGN_IN_SUCCESS = 2105,
    STATUS_SIGN_IN_FAILURE = 2106,
    STATUS_GENERAL_FAILURE = 2107,
};

std::string StatusCodeToString(
    ResponseStatus status);  // typo correction: "StatosCose" to "StatusCose"

class Response
{
public:
    static constexpr uint32_t MAX_PAYLOAD_SIZE = 10 * 1024 * 1024;  // 10MB
    static constexpr size_t HEADER_SIZE = 7;
    explicit Response(const std::vector<unsigned char> &buffer);
    virtual ~Response() = default;

    uint16_t getStatusCode() const;
    const std::string getStatusCodeString() const;
    uint32_t getPayloadSize() const;

    void parseHeader();
    virtual std::string print() const;

private:
    std::vector<unsigned char> buffer_;
    uint8_t version_;
    uint16_t status_code_;
    uint32_t payload_size_;
};

class ResponseWithUUID : public Response
{
public:
    explicit ResponseWithUUID(const std::vector<unsigned char> &buffer);

    static constexpr size_t UUID_SIZE = 16;
    const std::string &getUUIDString() const;
    const std::vector<unsigned char> &getPayload() const;
    std::string print() const override;

private:
    void checkUUIDPacket() const;
    void parseUUID(const std::vector<unsigned char> &buffer);

    std::array<unsigned char, UUID_SIZE> uuidBinary_;
    std::string uuidString_;
    std::vector<unsigned char> uuid_payload_;
};

class ResponseWithAESKey : public ResponseWithUUID
{
public:
    explicit ResponseWithAESKey(const std::vector<unsigned char> &buffer);
    const std::string getEncryptedAESString() const;
    std::string print() const override;

private:
    std::vector<unsigned char> encrypted_aes_key_;
};

class ResponseWithCRC : public ResponseWithUUID
{
public:
    explicit ResponseWithCRC(const std::vector<unsigned char> &buffer);
    uint32_t getCRCValue() const;
    std::string print() const override;

private:
    static constexpr size_t FILE_CONTENT_SIZE_LENGTH = 4;
    static constexpr size_t FILE_NAME_SIZE = 255;
    static constexpr size_t CRC_SIZE = 4;

    void extractFileContentSize(const std::vector<unsigned char> &buffer);
    void extractFileName(const std::vector<unsigned char> &buffer);
    void extractCRC(const std::vector<unsigned char> &buffer);

    uint32_t file_content_size_;
    std::string file_name_;
    uint32_t crc_value_;
};

std::unique_ptr<Response> ResponseFactory(
    const std::vector<unsigned char> &buffer);
