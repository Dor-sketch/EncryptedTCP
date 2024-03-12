#include <cryptopp/aes.h>
#include <cryptopp/crc.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>

#include <bitset>
#include <fstream>
#include <sstream>

#include "FileEncryptor.hpp"
#include "LoggerModule.hpp"

namespace CRCUtils
{
uint32_t calculateCRC(const std::string &data)
{
    CryptoPP::CRC32 crc;
    crc.Update(reinterpret_cast<const CryptoPP::byte *>(data.c_str()),
               data.size());
    uint32_t crcValue = 0;
    crc.Final(reinterpret_cast<CryptoPP::byte *>(&crcValue));

    DEBUG_LOG("Computed CRC value: {}", crcValue);
    return crcValue;
}

std::string encryptToString(const std::string &plainText, const byte *key,
                            const byte *iv)
{
    std::string cipherText;

    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

    CryptoPP::StringSource ss(
        plainText, true,
        new CryptoPP::StreamTransformationFilter(
            encryptor, new CryptoPP::StringSink(cipherText)));

    std::string snippet = cipherText.substr(
        0, std::min(cipherText.size(), static_cast<size_t>(8)));
    DEBUG_LOG("Text encrypted successfully (snippet): {}", snippet);

    return cipherText;
}

std::string encryptFileToString(const std::string &inputFileName,
                                const CryptoPP::byte *key,
                                const CryptoPP::byte *iv)
{
    DEBUG_LOG("Reading \"{}\" content and converting to string for encryption.",
              inputFileName);

    std::ifstream infile(inputFileName, std::ios::binary);
    if (!infile.is_open())
    {
        ERROR_LOG("Failed to open input \"{}\". Does it exist?", inputFileName);
        return "";
    }

    std::string plainText((std::istreambuf_iterator<char>(infile)),
                          std::istreambuf_iterator<char>());

    return encryptToString(plainText, key, iv);
}

std::string decryptToString(const std::string &cipherText, const byte *key,
                            const byte *iv)
{
    std::string decryptedText;

    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

    CryptoPP::StringSource ss(
        cipherText, true,
        new CryptoPP::StreamTransformationFilter(
            decryptor, new CryptoPP::StringSink(decryptedText)));

    std::string snippet = decryptedText.substr(
        0, std::min(decryptedText.size(), static_cast<size_t>(8)));
    DEBUG_LOG("Text decrypted successfully (snippet): {}", snippet);

    return decryptedText;
}

}  // namespace CRCUtils

FileEncryptor::FileEncryptor(const std::string &keyHex,
                             const std::string &inputFileName)
    : inputFileName_(inputFileName)
{
    // Convert key from hex to byte array
    CryptoPP::StringSource ss(keyHex, true,
                              new CryptoPP::HexDecoder(new CryptoPP::ArraySink(
                                  key_, CryptoPP::AES::DEFAULT_KEYLENGTH)));
    DEBUG_LOG(
        "Initializing FileEncryptor: Converted key from hex to byte array: {}",
        keyHex);

    // Set the IV to zeros for simplicity (Not recommended for real-world
    // applications!)
    memset(iv_, 0x00, CryptoPP::AES::BLOCKSIZE);
}

void FileEncryptor::decryptToFile(const std::string &cipherText,
                                  const std::string &outputFileName)
{
    std::string decryptedText =
        CRCUtils::decryptToString(cipherText, key_, iv_);

    // Write decrypted text to file
    CryptoPP::FileSink file(outputFileName.c_str());
    file.Put(reinterpret_cast<const CryptoPP::byte *>(decryptedText.data()),
             decryptedText.size());
}

std::tuple<std::string, uint32_t> FileEncryptor::encryptAndComputeCRC()
{
    // Encrypt file content to a string
    std::string encryptedData =
        CRCUtils::encryptFileToString(inputFileName_, key_, iv_);

    // Compute CRC value
    uint32_t crcValue = CRCUtils::calculateCRC(encryptedData);

    return std::make_tuple(encryptedData, crcValue);
}
