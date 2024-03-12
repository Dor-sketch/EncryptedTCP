#include "Response.hpp"

#include <iomanip>  // for std::setw and std::setfill
#include <iostream>
#include <map>
#include <stdexcept>

#include "LoggerModule.hpp"

std::string StatusCodeToString(ResponseStatus status)
{
    static const std::map<ResponseStatus, std::string> status_map = {
        {STATUS_SIGN_UP_FAILURE, "STATUS_SIGN_UP_FAILURE"},
        {STATUS_SIGN_IN_FAILURE, "STATUS_SIGN_IN_FAILURE"},
        {STATUS_AES_KEY_RECIEVED, "STATUS_AES_KEY_RECIEVED"},
        {STATUS_SIGN_UP_SUCCESS, "STATUS_SIGN_UP_SUCCESS"},
        {STATUS_FILE_RECIEVED, "STATUS_FILE_RECIEVED"},
        {STATUS_ACKNOWLEDGEMENT, "STATUS_ACKNOWLEDGEMENT"},
        {STATUS_GENERAL_FAILURE, "STATUS_GENERAL_FAILURE"},
        {STATUS_SIGN_IN_SUCCESS, "STATUS_SIGN_IN_SUCCESS"}};

    auto it = status_map.find(status);
    if (it != status_map.end())
    {
        return it->second;
    }
    else
    {
        return "Unknown status code";
    }
}

// ==================== Response ====================

Response::Response(const std::vector<unsigned char> &buffer)
    : buffer_(buffer), version_(0), status_code_(0), payload_size_(0)
{
    parseHeader();
}

const std::string Response::getStatusCodeString() const
{
    return StatusCodeToString(static_cast<ResponseStatus>(getStatusCode()));
}

uint16_t Response::getStatusCode() const { return status_code_; }

uint32_t Response::getPayloadSize() const { return payload_size_; }

void Response::parseHeader()
{
    if (buffer_.size() < HEADER_SIZE)  // minimum size with header
        throw std::runtime_error("Invalid buffer size for server response");
    version_ = buffer_[0];
    status_code_ = buffer_[1] | (buffer_[2] << 8);
    payload_size_ = buffer_[3] | (buffer_[4] << 8) | (buffer_[5] << 16) |
                    (buffer_[6] << 24);
    if (buffer_.size() != HEADER_SIZE + payload_size_)
        throw std::runtime_error(
            "Mismatch between payload size and buffer size");
}

std::string Response::print() const
{
    std::stringstream ss;
    ss << AnsiColorCodes::BOLD << AnsiColorCodes::BLUE
       << "========================" << AnsiColorCodes::RESET << std::endl;
    ss << AnsiColorCodes::GREEN << "Response header:" << AnsiColorCodes::RESET
       << std::endl;
    ss << "Version: " << (int)version_ << std::endl;
    ss << "status code: ";
    ss << getStatusCodeString() << std::endl;
    ss << "payload size: ";
    ss << std::stoi(std::to_string(getPayloadSize()), nullptr, 8)
       << AnsiColorCodes::BOLD << AnsiColorCodes::BLUE
       << "\n========================" << AnsiColorCodes::RESET;

    return ss.str();
}

// ==================== ResponseWithUUID ====================

ResponseWithUUID::ResponseWithUUID(const std::vector<unsigned char> &buffer)
    : Response(buffer),
      uuidString_(""),
      uuid_payload_(buffer.begin() + HEADER_SIZE,
                    buffer.begin() + UUID_SIZE + HEADER_SIZE)
{
    checkUUIDPacket();
    parseUUID(uuid_payload_);
}

const std::string &ResponseWithUUID::getUUIDString() const
{
    return uuidString_;
}

const std::vector<unsigned char> &ResponseWithUUID::getPayload() const
{
    return uuid_payload_;
}

void ResponseWithUUID::checkUUIDPacket() const
{
    // fail status code does not have payload - all other status codes have
    // payload starting with UUID
    if (getStatusCode() == STATUS_SIGN_UP_FAILURE)
        throw std::runtime_error("Incorrect status code for SignUpResponse");

    if ((getPayload().size() != UUID_SIZE) &&
        ((getStatusCode() != STATUS_FILE_RECIEVED) &&
         (getStatusCode() != STATUS_SIGN_IN_SUCCESS)))
    {
        throw std::runtime_error("Invalid payload size for UUID only response");
    }
}

void ResponseWithUUID::parseUUID(const std::vector<unsigned char> &buffer)
{
    // if has payload - payload size is always 16 bytes
    // except for STATUS_FILE_RECIEVED and STATUS_SENDING_AES_KEY

    std::copy(buffer.begin(), buffer.begin() + UUID_SIZE, uuidBinary_.begin());
    std::stringstream ss;
    for (size_t i = 0; i < uuidBinary_.size(); ++i)
    {
        if (i == 4 || i == 6 || i == 8 || i == 10) ss << "-";
        ss << std::setw(2) << std::setfill('0') << std::hex
           << static_cast<int>(uuidBinary_[i]);
    }
    uuidString_ = ss.str();
}

std::string ResponseWithUUID::print() const
{
    std::stringstream ss;
    ss << Response::print() << std::endl;
    ss << AnsiColorCodes::MAGENTA << "UUID: " << uuidString_
       << AnsiColorCodes::RESET << std::endl;
    return ss.str();
}

// ==================== ResponseWithAESKey ====================

ResponseWithAESKey::ResponseWithAESKey(const std::vector<unsigned char> &buffer)
    : ResponseWithUUID(buffer),
      encrypted_aes_key_(buffer.begin() + HEADER_SIZE + UUID_SIZE, buffer.end())
{
}

std::string ResponseWithAESKey::print() const
{
    std::stringstream ss;
    ss << ResponseWithUUID::print();
    ss << AnsiColorCodes::YELLOW
       << "Encrypted AES key: " << AnsiColorCodes::RESET << "\n";
    for (size_t i = 0; i < encrypted_aes_key_.size(); ++i)
    {
        ss << std::setw(2) << std::setfill('0') << std::hex
           << static_cast<int>(encrypted_aes_key_[i]) << " ";
        if (((i + 1) % 16 == 0) && (i < encrypted_aes_key_.size() - 1))
            ss << std::endl;
    }
    return ss.str();
}

const std::string ResponseWithAESKey::getEncryptedAESString() const
{
    std::stringstream ss;
    for (size_t i = 0; i < encrypted_aes_key_.size(); ++i)
    {
        ss << std::setw(2) << std::setfill('0') << std::hex
           << static_cast<int>(encrypted_aes_key_[i]);
    }
    return ss.str();
}

// ==================== ResponseWithCRC ====================
ResponseWithCRC::ResponseWithCRC(const std::vector<unsigned char> &buffer)
    : ResponseWithUUID(buffer)
{
    if (buffer.size() < HEADER_SIZE + UUID_SIZE + FILE_CONTENT_SIZE_LENGTH +
                            FILE_NAME_SIZE + CRC_SIZE)
    {
        // handle error
        throw std::runtime_error(
            "Buffer size is insufficient for ResponseWithCRC");
    }

    extractFileContentSize(buffer);
    extractFileName(buffer);
    extractCRC(buffer);
}

void ResponseWithCRC::extractFileContentSize(
    const std::vector<unsigned char> &buffer)
{
    const unsigned char *file_size_start = &buffer[HEADER_SIZE + UUID_SIZE];

    std::memcpy(&file_content_size_, file_size_start, 4);

    DEBUG_LOG("File content size: {}", file_content_size_);
}

void ResponseWithCRC::extractFileName(const std::vector<unsigned char> &buffer)
{
    auto startIter =
        buffer.begin() + HEADER_SIZE + UUID_SIZE + FILE_CONTENT_SIZE_LENGTH;
    file_name_.assign(startIter, startIter + FILE_NAME_SIZE);
}

void ResponseWithCRC::extractCRC(const std::vector<unsigned char> &buffer)
{
    const unsigned char *crcStart = &buffer[buffer.size() - 4];
    std::memcpy(&crc_value_, crcStart, 4);
    DEBUG_LOG("CRC value: {}", crc_value_);
}

uint32_t ResponseWithCRC::getCRCValue() const { return crc_value_; }

std::string ResponseWithCRC::print() const
{
    std::stringstream ss;
    ss << ResponseWithUUID::print();
    ss << AnsiColorCodes::YELLOW << "File content size: " << file_content_size_
       << AnsiColorCodes::RESET << std::endl;
    ss << AnsiColorCodes::YELLOW << "File name: " << file_name_
       << AnsiColorCodes::RESET << std::endl;
    ss << AnsiColorCodes::YELLOW << "CRC: " << crc_value_
       << AnsiColorCodes::RESET;
    return ss.str();
}

// ==================== ResponseFactory ====================


std::unique_ptr<Response> ResponseFactory(
    const std::vector<unsigned char> &buffer)
{
    constexpr size_t HEADER_SIZE = 7;
    constexpr size_t UUID_SIZE = 16;
    constexpr size_t FILE_CONTENT_SIZE_LENGTH = 4;
    constexpr size_t FILE_NAME_SIZE = 255;
    constexpr size_t CRC_SIZE = 4;

    if (buffer.size() < HEADER_SIZE)
    {
        throw std::runtime_error("Insufficient buffer size");
    }

    int16_t svr_code = buffer[1] | (buffer[2] << 8);
    LOG("Retrived Response from server. Status code: [\033[1;32m{} "
        "({})\033[0m]",
        StatusCodeToString(static_cast<ResponseStatus>(svr_code)),
        std::to_string(svr_code));

    std::unique_ptr<Response> response;

    // Construct a ServerResponse object based on the response type
    switch (svr_code)
    {
        case STATUS_SIGN_UP_FAILURE:
        case STATUS_SIGN_IN_FAILURE:
        case STATUS_GENERAL_FAILURE:
        case STATUS_ACKNOWLEDGEMENT:
            if (buffer.size() < HEADER_SIZE)
            {
                throw std::runtime_error(
                    "Insufficient buffer size for response without payload");
            }
            response = std::make_unique<Response>(buffer);
            break;

        case STATUS_AES_KEY_RECIEVED:
        case STATUS_SIGN_IN_SUCCESS:
            response = std::make_unique<ResponseWithAESKey>(buffer);
            break;

        case STATUS_SIGN_UP_SUCCESS:
            response = std::make_unique<ResponseWithUUID>(buffer);
            if (buffer.size() < HEADER_SIZE + UUID_SIZE)
            {
                throw std::runtime_error(
                    "Insufficient buffer size for UUID only response");
            }
            break;

        case STATUS_FILE_RECIEVED:
            if (buffer.size() < HEADER_SIZE + UUID_SIZE +
                                    FILE_CONTENT_SIZE_LENGTH + FILE_NAME_SIZE +
                                    CRC_SIZE)
            {
                throw std::runtime_error(
                    "Insufficient buffer size for ResponseWithCRC");
            }
            response = std::make_unique<ResponseWithCRC>(buffer);
            break;

        default:
            throw std::runtime_error("Unknown server response code: " +
                                     std::to_string(svr_code));
    }

    if (!response)
    {
        throw std::runtime_error("Response was not properly initialized.");
    }
    return response;
}