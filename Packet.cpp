

#include <iomanip>  // for std::hex and std::setw

#include "PacketPrint.hpp"

const std::string ANSI_BOLD_GREEN = "\033[1;32m";
const std::string ANSI_RESET = "\033[0m";
const std::string ANSI_BOLD_BLUE = "\033[1;34m";
const std::string ANSI_BOLD = "\033[1m";
const std::string ANSI_BOLD_RED = "\033[1;31m";
const std::string ANSI_BOLD_YELLOW = "\033[1;33m";
const std::string SEPARATOR =
    ANSI_BOLD_GREEN + "-------------------------------" + ANSI_RESET;


using namespace PacketUtils;

// ==================== Packet ====================

Packet::Packet(const std::array<unsigned char, 16> &client_id, uint16_t op,
               uint32_t payload_size)
    : client_id_{client_id},
      version_{VERSION},
      op_{op},
      payload_size_{payload_size}
{
}

const std::string Packet::prepareLog() const
{
    std::ostringstream os;

    // Client ID formatting
    for (const auto &byte : client_id_)
    {
        os << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(byte);
    }
    PacketUtils::appendBoldLog(os, "client_id", os.str());
    os.str("");  // Clear the ostringstream

    PacketUtils::appendBoldLog(os, "version",
                               std::to_string(static_cast<int>(version_)));
    PacketUtils::appendBoldLog(os, "op",
                               std::to_string(op_) + " (" + getOp() + ")");
    PacketUtils::appendBoldLog(os, "payload_size",
                               std::to_string(payload_size_));

    return os.str();
}

void Packet::print() const
{
    DEBUG_LOG("{}Basic Packet:{}\n{}", ANSI_BOLD, ANSI_RESET, prepareLog());
}

std::vector<uint8_t> Packet::pack() const
{
    std::vector<uint8_t> packedData;
    packedData.insert(packedData.end(), client_id_.begin(), client_id_.end());
    // no need to convert to little endian, since it's only 1 byte
    packedData.push_back(version_);

    uint16_t opLE = toLittleEndian(op_);
    packedData.insert(packedData.end(),
                      reinterpret_cast<const uint8_t *>(&opLE),
                      reinterpret_cast<const uint8_t *>(&opLE) + sizeof(opLE));

    // pack payload size
    uint32_t payloadSizeLE = toLittleEndian(payload_size_);
    packedData.insert(packedData.end(),
                      reinterpret_cast<const uint8_t *>(&payloadSizeLE),
                      reinterpret_cast<const uint8_t *>(&payloadSizeLE) +
                          sizeof(payloadSizeLE));

    return packedData;
}

const std::string Packet::getOp() const
{
    return ANSI_BOLD_RED + RequestOpToString(static_cast<RequestOp>(op_)) +
           ANSI_RESET;
}

// ==================== PacketWithClientName ====================

std::unique_ptr<Packet> PacketWithClientName::createUnique(
    const ClientID &clientID, const RequestOp op, const ClientName &clientName)
{
    return std::unique_ptr<Packet>(new PacketWithClientName(
        clientID.get(), static_cast<uint16_t>(op), clientName.get()));
}

PacketWithClientName::PacketWithClientName(
    const std::array<unsigned char, 16> &client_id, uint16_t op,
    const std::string &client_name)
    : Packet(client_id, op, FIELD_SIZE::NAME)
{
    std::strncpy(client_name_.data(), client_name.c_str(), FIELD_SIZE::NAME);
}

void PacketWithClientName::print() const
{
    std::ostringstream colored_os;
    colored_os << ANSI_BOLD_BLUE << Packet::prepareLog() << ANSI_RESET;
    colored_os << "\n"
               << ANSI_BOLD << " - client_name:" << ANSI_RESET << " "
               << std::string(client_name_.data());
    DEBUG_LOG("\n{}\nPacket With Client Name:{}\n{}", SEPARATOR,
              colored_os.str(), SEPARATOR);
}

std::vector<uint8_t> PacketWithClientName::pack() const
{
    std::vector<uint8_t> packedData = Packet::pack();
    // Convert client_name_ to a fixed length 255 byte array
    std::array<char, 255> nameArray{};
    std::copy(client_name_.begin(), client_name_.end(), nameArray.begin());
    packedData.insert(packedData.end(), nameArray.begin(), nameArray.end());
    return packedData;
}

// ==================== PacketWithPublicKey ====================

std::unique_ptr<Packet> PacketWithPublicKey::createUnique(
    const ClientID &clientID, const ClientName &clientName,
    const PublicKey &publicKey)
{
    return std::unique_ptr<Packet>(new PacketWithPublicKey(
        clientID.get(), clientName.get(), publicKey.get()));
}

PacketWithPublicKey::PacketWithPublicKey(
    const std::array<unsigned char, 16> &client_id,
    const std::string &client_name, const std::string &public_key)
    : PacketWithClientName(client_id, RequestOp::OP_GET_KEY, client_name)
{
    public_key_ = public_key;
    payload_size_ = static_cast<size_t>(FIELD_SIZE::NAME) + 160;
}

void PacketWithPublicKey::print() const
{
    std::ostringstream colored_os;
    colored_os << ANSI_BOLD_BLUE << PacketWithClientName::prepareLog()
               << ANSI_RESET;
    colored_os << "\n" << ANSI_BOLD << "- public_key:" << ANSI_RESET << "\n";

    for (size_t i = 0; i < public_key_.size(); ++i)
    {
        colored_os << std::setw(2) << std::setfill('0') << std::hex
                   << static_cast<int>(public_key_[i]) << " ";
        if ((i + 1) % 8 == 0) colored_os << "\n";
    }

    DEBUG_LOG("{}Packet With Public Key:{}\n{}", ANSI_BOLD, ANSI_RESET,
              colored_os.str());
}

std::vector<uint8_t> PacketWithPublicKey::pack() const
{
    std::vector<uint8_t> packedData = PacketWithClientName::pack();
    std::string temp_key = public_key_;
    temp_key.erase(std::remove(temp_key.begin(), temp_key.end(), '\n'),
                   temp_key.end());
    DEBUG_LOG("temp_key :{}", temp_key);
    // Convert public_key_ to a fixed length 160 byte array - convert from base
    // 64 to binary
    for (char c : temp_key)
    {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='))
        {
            LOG("Non-base64 character found: {} ASCII: {}", c, (int)c);
        }
    }

    std::vector<unsigned char> public_key_binary = base64_decode(temp_key);
    DEBUG_LOG("public key size: {}, binary data:\n{}", public_key_binary.size(),
              public_key_binary);

    packedData.insert(packedData.end(), public_key_binary.begin(),
                      public_key_binary.end());

    return packedData;
}

// ==================== PacketWithFileName ====================

std::unique_ptr<Packet> PacketWithFileName::createUnique(
    const ClientID &clientID, const RequestOp op, const FileName &fileName)
{
    return std::unique_ptr<Packet>(new PacketWithFileName(
        clientID.get(), static_cast<uint16_t>(op), fileName.get()));
}

PacketWithFileName::PacketWithFileName(
    const std::array<unsigned char, 16> &client_id, uint16_t op,
    const std::string &file_name)
    : Packet(client_id, op, FIELD_SIZE::NAME)
{
    std::fill(file_name_.begin(), file_name_.end(), '\0');  // Padding with '\0'
    std::strncpy(
        file_name_.data(), file_name.c_str(),
        std::min(static_cast<size_t>(FIELD_SIZE::NAME), file_name.size()));
}

std::vector<uint8_t> PacketWithFileName::pack() const
{
    std::vector<uint8_t> packedData = Packet::pack();
    packedData.insert(packedData.end(), file_name_.begin(), file_name_.end());
    return packedData;
}

const std::string PacketWithFileName::prepareLog() const
{
    std::ostringstream os;
    os << Packet::prepareLog();
    os << "\n"
       << ANSI_BOLD << " - file_name:" << ANSI_RESET << " "
       << std::string(file_name_.data());
    return os.str();
}

void PacketWithFileName::print() const
{
    std::ostringstream os;
    os << ANSI_BOLD_BLUE << prepareLog() << ANSI_RESET;
    DEBUG_LOG("\n{}\nPacket With File Name (Update Checksum Results):{}\n{}",
              SEPARATOR, os.str(), SEPARATOR);
}

// ==================== PacketWithFile ====================

std::unique_ptr<Packet> PacketWithFile::createUnique(
    const ClientID &clientID, const FileName &fileName,
    const FileContent &fileContent)
{
    return std::unique_ptr<Packet>(
        new PacketWithFile(clientID.get(), fileName.get(), fileContent.get()));
}

PacketWithFile::PacketWithFile(const std::array<unsigned char, 16> &client_id,
                               const std::string &file_name,
                               const std::string &file)
    : PacketWithFileName(client_id, RequestOp::OP_CRC_VERIFYING, file_name)
{
    file_content_ = std::vector<char>(file.begin(), file.end());
}

std::vector<uint8_t> PacketWithFile::pack() const
{
    std::vector<uint8_t> packedData;
    packedData.insert(packedData.end(), client_id_.begin(), client_id_.end());
    // no need to convert to little endian, since it's only 1 byte
    packedData.push_back(version_);

    // Operation code
    uint16_t operationCode = 1028;
    packedData.push_back((operationCode >> 8) & 0xFF);  // High byte.
    packedData.push_back(operationCode & 0xFF);         // Low byte.

    auto contentSize = static_cast<uint32_t>(file_content_.size());
    uint32_t totalPayloadSize =
        4 + 255 +
        contentSize;  // 4 for file content size, 255 for padded file name

    DEBUG_LOG("contentSize: {}, totalPayloadSize: {}.", contentSize,
              totalPayloadSize);

    // Total Payload Size (little-endian)
    for (int i = 0; i < 4; i++)
    {
        packedData.push_back((totalPayloadSize >> (i * 8)) & 0xFF);
    }

    // File Content Size (little-endian)
    for (int i = 0; i < 4; i++)
    {
        packedData.push_back((contentSize >> (i * 8)) & 0xFF);
    }

    // Append file name (padded to 255 bytes)
    std::vector<uint8_t> fileNameBytes(file_name_.begin(), file_name_.end());
    fileNameBytes.resize(
        255, 0);  // Resize to 255 bytes, padding with zeroes if necessary
    packedData.insert(packedData.end(), fileNameBytes.begin(),
                      fileNameBytes.end());

    // Append file content
    packedData.insert(packedData.end(), file_content_.begin(),
                      file_content_.end());

    return packedData;
}

void PacketWithFile::print() const
{
    std::ostringstream colored_os;

    // Client ID
    std::string clientID;
    for (auto &byte : client_id_)
    {
        clientID += std::to_string(static_cast<int>(byte)) + " ";
    }
    PacketUtils::appendBoldLog(colored_os, "Client ID", clientID);

    // Version
    PacketUtils::appendBoldLog(colored_os, "Version",
                               std::to_string(static_cast<int>(version_)));

    // Operation Code
    PacketUtils::appendBoldLog(colored_os, "Operation Code", getOp());


    // Ensure the file_content_ is long enough before accessing it
    if (file_content_.size() < 281)
    {
        DEBUG_LOG("Error: Packet data is incomplete.", "");
        return;
    }

    // Total Payload Size
    uint32_t totalPayloadSize = 0;
    for (int i = 0; i < 4; ++i)
    {
        totalPayloadSize |= static_cast<uint32_t>(file_content_[18 + i])
                            << (i * 8);
    }
    PacketUtils::appendBoldLog(colored_os, "Total Payload Size",
                               std::to_string(totalPayloadSize));

    // File Content Size
    uint32_t contentSize = 0;
    for (int i = 0; i < 4; ++i)
    {
        contentSize |= static_cast<uint32_t>(file_content_[22 + i]) << (i * 8);
    }
    PacketUtils::appendBoldLog(colored_os, "File Content Size",
                               std::to_string(contentSize));

    // File Name

    PacketUtils::appendBoldLog(colored_os, "File Name", file_name_.data());

    // File Content Snippet
    std::string snippet = PacketUtils::getSnippetFromContent(file_content_);
    PacketUtils::appendBoldLog(colored_os, "File Content Snippet", snippet);

    DEBUG_LOG(
        "\n" + SEPARATOR + "\nPacket With File{}\n" + SEPARATOR, colored_os.str());
}
