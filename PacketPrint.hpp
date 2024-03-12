#pragma once

#include <algorithm>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <cctype>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "LoggerModule.hpp"
#include "Packet.hpp"

namespace PacketUtils
{

std::string getSnippetFromContent(const std::vector<char> &file_content)
{
    std::string snippet;
    size_t snippetSize = std::min(file_content.size(), static_cast<size_t>(50));

    for (size_t i = 0; i < snippetSize; ++i)
    {
        char c = file_content[i];
        if (std::isprint(c))
        {
            snippet += c;
        }
        else
        {
            std::ostringstream hexStream;
            hexStream << std::setw(2) << std::setfill('0') << std::hex
                      << static_cast<int>(c);
            snippet += "\\x" + hexStream.str();
        }
    }

    if (file_content.size() > snippetSize)
    {
        snippet += "...";
    }

    return snippet;
}

void appendBoldLog(std::ostringstream &os, const std::string &field_name,
                   const std::string &value)
{
    os << "\n"
       << " - " << AnsiColorCodes::BOLD << field_name << ": " << AnsiColorCodes ::RESET
       << value;
}

std::string RequestOpToString(PacketUtils::RequestOp op)
{
    static const std::map<PacketUtils::RequestOp, std::string> opToString = {
        {PacketUtils::RequestOp::OP_SIGN_UP, "OP_SIGN_UP"},
        {PacketUtils::RequestOp::OP_GET_KEY, "OP_GET_KEY"},
        {PacketUtils::RequestOp::OP_SIGN_IN, "OP_SIGN_IN"},
        {PacketUtils::RequestOp::OP_CRC_VERIFYING, "OP_CRC_VERIFYING"},
        {PacketUtils::RequestOp::OP_CRC_SUCCESS, "OP_CRC_SUCCESS"},
        {PacketUtils::RequestOp::OP_CRC_RETRY, "OP_CRC_RETRY"},
        {PacketUtils::RequestOp::OP_CRC_FAILURE, "OP_CRC_FAILURE"}};

    auto it = opToString.find(op);
    if (it != opToString.end())
    {
        return it->second;
    }
    return "UNKNOWN";
}
}  // namespace PacketUtils

std::vector<unsigned char> base64_decode(const std::string &encoded_string)
{
    DEBUG_LOG("base64_decode called with input: {}",
              encoded_string.substr(0, 50),
              "...");  // LOGging first 50 chars for brevity

    using namespace boost::archive::iterators;
    typedef transform_width<binary_from_base64<std::string::const_iterator>, 8,
                            6>
        ItBinaryT;

    const std::string base64_padding[] = {
        "", "==", "="};  // Depending on the number of bytes to be decoded
    size_t num_pad_chars = (3 - encoded_string.length() % 3) % 3;
    std::string base64_str = encoded_string + base64_padding[num_pad_chars];

    size_t pad_chars = std::count(base64_str.begin(), base64_str.end(), '=');
    std::replace(base64_str.begin(), base64_str.end(), '=',
                 'A');  // replace '=' by base64 encoding of '\0'
    std::vector<unsigned char> decoded_bytes(ItBinaryT(base64_str.begin()),
                                             ItBinaryT(base64_str.end()));
    decoded_bytes.erase(decoded_bytes.end() - pad_chars, decoded_bytes.end());
    return decoded_bytes;
}

bool isLittleEndian()
{
    int n = 1;
    return *(char *)&n == 1;
}

uint16_t toLittleEndian(uint16_t value)
{
    if (!isLittleEndian())
    {
        std::reverse(reinterpret_cast<uint8_t *>(&value),
                     reinterpret_cast<uint8_t *>(&value) + sizeof(uint16_t));
    }
    return value;
}
