#include "Client.hpp"

#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>

#include <boost/uuid/string_generator.hpp>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>

#include "ClientState.hpp"
#include "ConnectionManager.hpp"
#include "FileEncryptor.hpp"
#include "Keys.hpp"
#include "LoggerModule.hpp"
#include "Packet.hpp"
#include "PacketFactory.hpp"
#include "Response.hpp"
#include "SignErrors.hpp"
#include "TransferInfoManager.hpp"
using namespace PacketUtils;
using namespace ErrorsModule;

namespace ClientUtility
{
const int MAX_RETRIES = 3;
const int SUCCESS = 0;


// in case not using the defined macros in LoggerModule.hpp
const std::string ANSI_RED = "\033[1;31m";
const std::string ANSI_GREEN = "\033[1;32m";
const std::string ANSI_BLUE = "\033[1;34m";
const std::string ANSI_CYAN = "\033[1;36m";
const std::string ANSI_WHITE = "\033[1;37m";
const std::string ANSI_MAGENTA = "\033[1;35m";
const std::string ANSI_YELLOW = "\033[1;33m";
const std::string ANSI_RESET = "\033[0m";

const std::string CLIENT_INIT_LOG =
    "Client \"{}\" initialized successfully: IP: {}, Port: {}. Building Mode: "
    "{}";

const std::string RSA_KEYS_LOG =
    ANSI_BLUE + "SENSITIVE DATA: RSA keys pair:" + ANSI_RESET +
    " Public Key (snippet): {} Private Key (snippet): {}";

const std::string RETRIEVED_AES_KEY_LOG =
    "SENSITIVE DATA: Successfully retrieved and decrypted old AES key from "
    "server (partial): {}";

const std::string DECRYPTED_NEW_AES_KEY_LOG =
    "SENSITIVE DATA: Successfully decrypted new AES key from server: {}";

const std::string CLIENT_COMPLETION_LOG =
    ANSI_CYAN + "Client " + ANSI_WHITE + "\"{}\"" + ANSI_CYAN +
    " has completed its operations. Cleaning up resources and shutting down. "
    "IP: " +
    ANSI_WHITE + "{}" + ANSI_CYAN + ", Port: " + ANSI_WHITE + "{}" + ANSI_CYAN +
    ". Ran in " + ANSI_MAGENTA + "{}" + ANSI_CYAN + " mode." + ANSI_RESET;

const std::string CRC_MISMATCH_LOG =
    ANSI_RED +
    "CRC value does not match for file \"{}\": received {}, but expected {}." +
    ANSI_RESET + "\n" + "====================\n" + ANSI_YELLOW +
    "Suggestions:" + ANSI_RESET + "\n" +
    "- Make sure the server is not running in \"debug mode\".\n" +
    "- Check that the AES key was decrypted correctly.\n" +
    "- Try encrypting and decrypting with client module \"FileManager\".\n" +
    "- Compile the client in debug mode: " + ANSI_CYAN +
    "make clean + make debug + ./client_app" + ANSI_RESET + "\n" +
    "====================";

const std::string CRC_SUCCESS_LOG =
    "Successfully CRC count: " + ANSI_YELLOW + "CRC Value:" + ANSI_RESET +
    " {}. Encrypting for sending " + ANSI_YELLOW + "File:" + ANSI_RESET + " {}";

void appendPublicKey(std::ostringstream &stream, const std::string &line)
{
    stream << line << "\n";
}

boost::uuids::uuid parseUUID(const std::string &line)
{
    boost::uuids::string_generator gen;
    return gen(line);
}

bool isRegistered() { return std::filesystem::exists("me.info"); }

void closeAndExit()
{
    DEBUG_LOG("Closing client.", "");
    // exit(0);
    throw std::runtime_error("Client closed");
}

std::string toHexString(const std::string &data)
{
    std::ostringstream oss;
    for (unsigned char c : data)
    {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(c);
    }
    return oss.str();
}

void logFileStatus(const std::string &file_name, const int retries,
                   const int max_retries)
{
    if (retries == max_retries)
    {
        ERROR_LOG(
            "Failed to send file: {} on try number: {}. Updating server "
            "after {} retries and closing connection.",
            file_name, retries, max_retries);
    }
    else if (retries == SUCCESS)
    {
        LOG(ClientUtility::ANSI_GREEN + "File sent successfully: {}" +
                ClientUtility::ANSI_RESET,
            file_name);
    }
    else
    {
        ERROR_LOG(
            "Failed to send file: {} on try number: {}. Updating Server "
            "and "
            "trying {}.",
            file_name, retries,
            (max_retries - retries == 1)
                ? std::string("one last time")
                : std::to_string(max_retries - retries) + " more times");
    }
}
}  // namespace ClientUtility

// Convinience functions mainly for converting between different formats
namespace KeysUtility
{
// This utilites cause memory leaks.
// Becuse the minor memory leak is not a problem in this case, and
// also becuse it happens only once, I decided to leave it as is.
CryptoPP::RSA::PrivateKey loadPrivateKeyFromBase64(const std::string &base64Key)
{
    // Remove the PEM header and footer
    std::string keyStr = base64Key;
    keyStr.erase(remove(keyStr.begin(), keyStr.end(), '\n'), keyStr.end());
    keyStr.erase(remove(keyStr.begin(), keyStr.end(), '-'), keyStr.end());

    // Decode from Base64
    CryptoPP::StringSource ss(keyStr, true, new CryptoPP::Base64Decoder);
    CryptoPP::ByteQueue bytes;
    ss.TransferTo(bytes);
    bytes.MessageEnd();

    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.Load(bytes);

    return privateKey;
}

std::string decryptAESKey(const std::string &base64Key,
                          const std::string &encryptedKeyHex)
{
    CryptoPP::RSA::PrivateKey privateKey = loadPrivateKeyFromBase64(base64Key);
    CryptoPP::AutoSeededRandomPool rng;

    std::vector<unsigned char> encryptedKey;

    for (size_t i = 0; i < encryptedKeyHex.size(); i += 2)
    {
        std::string byteString = encryptedKeyHex.substr(i, 2);
        char byte = (char)std::strtol(byteString.c_str(), NULL, 16);
        encryptedKey.push_back(byte);
    }

    std::string decrypted;
    try
    {
        CryptoPP::RSAES_OAEP_SHA_Decryptor d(privateKey);

        CryptoPP::StringSource ss(
            encryptedKey.data(), encryptedKey.size(), true,
            new CryptoPP::PK_DecryptorFilter(
                rng, d,
                new CryptoPP::StringSink(decrypted))  // PK_DecryptorFilter
        );                                            // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        throw std::runtime_error("Failed to decrypt AES key");
    }

    return decrypted;
}
}  // namespace KeysUtility

// ========== Client ==========

Client::Client()
    : client_name_(""),
      aes_key_({0}),
      client_id_({0}),
      transfer_info_manager_ptr_(nullptr),
      connection_manager_ptr_(nullptr),
      rsa_ptr_(nullptr),
      state_(std::make_unique<InitialState>())
{
    try
    {
        init();
    }
    catch (const std::exception &e)
    {
        // Log or do something else here if necessary
        throw std::runtime_error(std::string("Initialization failed: ") +
                                 e.what());
    }

    std::string running_mode = getRunningModeString();
    LOG(ClientUtility::CLIENT_INIT_LOG, getClientName(),
        transfer_info_manager_ptr_->getIPAddress(),
        transfer_info_manager_ptr_->getPort(), running_mode);
}

const std::string Client::getRunningModeString()
{
#ifdef ENABLE_DEBUG_LOGGING
    return (ClientUtility::ANSI_YELLOW + std::string("Debug") +
            ClientUtility::ANSI_RESET)
#elif defined(CRITICAL_LOGGING_ONLY)
    return (ClientUtility::ANSI_RED + std::string("Critical") +
            ClientUtility::ANSI_RESET
#else
    return (ClientUtility::ANSI_GREEN + std::string("Release") +
            ClientUtility::ANSI_RESET);
#endif
}

Client::~Client()
{
    LOG(ClientUtility::CLIENT_COMPLETION_LOG, getClientName(),
        transfer_info_manager_ptr_->getIPAddress(),
        transfer_info_manager_ptr_->getPort(), getRunningModeString());
}

void Client::setState(std::unique_ptr<ClientState> newState)
{
    state_ = std::move(newState);
}

void Client::init()
{
    try
    {
        transfer_info_manager_ptr_ = std::make_shared<TransferInfoManager>();
        setClientName(transfer_info_manager_ptr_->getName());
        connection_manager_ptr_ =
            std::make_unique<ConnectionManager>(*transfer_info_manager_ptr_);
        DEBUG_LOG(
            "Connection and Transfer Info initialized for client: "
            "{}",
            getClientName());
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error("Failed to create client due to: " +
                                 std::string(e.what()));
    }
}

void Client::setClientID(const boost::uuids::uuid &uuid)
{
    std::copy(uuid.begin(), uuid.end(), client_id_.begin());
}

void Client::setClientName(const std::string &name)
{
    if (name.empty())
    {
        throw std::runtime_error("Client name cannot be empty");
    }
    if (client_name_ != name && !client_name_.empty())
    {
        WARN_LOG("Client name changed from \"{}\" to \"{}\"", client_name_,
                 name);
    }
    client_name_ = name;
}

void Client::signUp()
{
    // If the client is already registered, throw an exception.
    if (ClientUtility::isRegistered())
    {
        throw SignInError("Client is already registered",
                          SignInStatus::ALREADY_REGISTERED);
    }
    try
    {
        registerClient();
    }
    catch (const std::exception &e)
    {
        throw SignInError("Failed to register client: " + std::string(e.what()),
                          SignInStatus::FAILURE_NETWORK_ERROR);
    }
}

void Client::registerClient()
{
    auto response = connection_manager_ptr_->connectSendReceiveDisconnect(
        *createPacket(ClientID(getClientID()), (RequestOp::OP_SIGN_UP),
                      ClientName(getClientName())));

    if (response->getStatusCode() == ResponseStatus::STATUS_SIGN_UP_SUCCESS)
    {
        createMeInfo(dynamic_cast<ResponseWithUUID &>(*response));
        loadClientInfo();
    }
    else
    {
        ERROR_LOG("Sign up failed: {}", response->getStatusCodeString());
    }
}

const std::string &Client::getClientName() const { return client_name_; }

const std::array<unsigned char, 16> &Client::getClientID() const
{
    return client_id_;
}

std::string Base64Encode(const std::string &input)
{
    std::string output;
    CryptoPP::StringSource(input, true,
                           new CryptoPP::Base64Encoder(new CryptoPP::StringSink(
                               output))  // Base64Encoder
    );                                   // StringSource
    return output;
}

void Client::createMeInfo(const ResponseWithUUID &response)
{
    std::ofstream outfile("me.info");
    if (!outfile)
    {
        ERROR_LOG("Error opening me.info for writing: {}", strerror(errno));
        throw SignInError(
            "Failed to create me.info: Error opening me.info for writing!",
            SignInStatus::FAILURE_INFO_CREATION);
    }

    outfile << client_name_
            << std::endl;  // Write client name on the first line
    outfile << response.getUUIDString() << std::endl;

    // If rsa_ptr_ already has ownership, the previous RSAPrivateWrapper is
    // destroyed.
    try
    {
        rsa_ptr_ = std::make_unique<RSAPrivateWrapper>();
        outfile << Base64Encode(rsa_ptr_->getPublicKeyString()) << std::endl;
        outfile.close();

        std::ofstream outfile2("priv.key");
        if (!outfile2)
        {
            std::cerr << "Error opening priv.key for writing!" << std::endl;
            return;
        }
        outfile2 << Base64Encode(rsa_ptr_->getPrivateKeyString()) << std::endl;
        outfile2.close();
    }
    catch (const std::exception &e)
    {
        throw SignInError("Failed to create me.info: " + std::string(e.what()),
                          SignInStatus::FAILURE_RSA_KEY_CREATION);
    }
}

void Client::createRSA(const std::string &private_key_base64,
                       const std::string &public_key_stream)
{
    std::string public_sniipet =
        public_key_stream.substr(0, 8) + "..." +
        public_key_stream.substr(public_key_stream.size() - 8, 8);
    std::string private_sniipet =
        private_key_base64.substr(0, 8) + "..." +
        private_key_base64.substr(private_key_base64.size() - 8, 8);

    LOG(ClientUtility::RSA_KEYS_LOG, public_sniipet, private_sniipet);

    rsa_ptr_ = std::make_unique<RSAPrivateWrapper>(public_key_stream,
                                                   private_key_base64);
}

void logPartialAesKey(const std::string &aes_key_he)
{
    std::string key_hex = ClientUtility::toHexString(aes_key_he);
    std::string key_partial =
        key_hex.substr(0, 8) + "..." + key_hex.substr(key_hex.size() - 8, 8);

    LOG(ClientUtility::RETRIEVED_AES_KEY_LOG, key_partial);
}

void Client::signIn()
{
    try
    {
        loadClientInfo();
    }
    catch (const std::exception &e)
    {
        throw SignInError("Failed to load client info" + std::string(e.what()),
                          SignInStatus::FAILURE_INVALID_ME_INFO);
    }
    auto response = connection_manager_ptr_->connectSendReceiveDisconnect(
        *PacketUtils::createPacket(ClientID(getClientID()),
                                   (RequestOp::OP_SIGN_IN),
                                   ClientName(getClientName())));
    if (!response)
    {
        throw SignInError("Sign in failed: No response",
                          SignInStatus::FAILURE_NETWORK_ERROR);
    }
    if ((response->getStatusCode()) == ResponseStatus::STATUS_SIGN_IN_SUCCESS)
    {  // Proceed to retrieve the AES key.
        auto responseWithKey =
            dynamic_cast<ResponseWithAESKey *>(response.get());
        if (responseWithKey)
        {
            aes_key_ = KeysUtility::decryptAESKey(
                rsa_ptr_->getPrivateKeyString(),
                responseWithKey->getEncryptedAESString());
            logPartialAesKey(aes_key_);
        }
    }
    else
    {
        CRITICAL_LOG("Sign in failed: {}", response
                                               ? response->getStatusCodeString()
                                               : "No response");
        throw SignInError("Sign in failed: Server rejected the request: " +
                              response->getStatusCodeString(),
                          SignInStatus::FAILURE_INVALID_UUID);
    }
}

const std::string Client::requestAESKey()
{
    try
    {
        auto response = connection_manager_ptr_->connectSendReceiveDisconnect(
            *createPacket(ClientID(getClientID()), ClientName(getClientName()),
                          PublicKey(rsa_ptr_->getPublicKeyString())));

        if (response && response->getStatusCode() == STATUS_AES_KEY_RECIEVED)
        {
            auto responseWithKey =
                dynamic_cast<ResponseWithAESKey *>(response.get());
            if (responseWithKey)
            {
                return responseWithKey->getEncryptedAESString();
            }
            else
            {
                ERROR_LOG("Error: Unexpected response type received: ",
                          response->getStatusCode());
                throw SignInError(
                    "Failed to request AES key: Unexpected response type "
                    "received: " +
                        response->getStatusCodeString(),
                    SignInStatus::FAILURE_INVALID_AES);
            }
        }
    }
    catch (const std::exception &e)
    {
        throw SignInError("Failed to request AES key: " + std::string(e.what()),
                          SignInStatus::FAILURE_INVALID_AES);
    }
    return "";
}

void Client::getNewAESKey()
{
    DEBUG_LOG("Requesting AES key from server: {}", getClientName());
    aes_key_ = KeysUtility::decryptAESKey(rsa_ptr_->getPrivateKeyString(),
                                          requestAESKey());
    CRITICAL_LOG(ClientUtility::DECRYPTED_NEW_AES_KEY_LOG,
                 ClientUtility::toHexString(aes_key_));
}

void Client::loadClientInfo()
{
    Loader loader(*this);
    try
    {
        loader.load();
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error("Failed to load client info: " +
                                 std::string(e.what()));
    }
}

const std::string Client::tryGetFileToSend()
{
    std::string file_name;
    try
    {
        file_name = transfer_info_manager_ptr_->getFileName();
    }
    catch (const NoMoreFilesException &e)
    {
        WARN_LOG("Does client \"{}\" have more files to send?\n{}",
                 getClientName(), e.what());
        throw;
    }
    return file_name;
}

void Client::sendEncryptedFileAndCountCRC()
{
    std::string file_name = tryGetFileToSend();
    int retries = 1;
    RequestOp final_op = RequestOp::OP_CRC_RETRY;

    while (retries <= ClientUtility::MAX_RETRIES)
    {
        DEBUG_LOG("Sending file: {}, try number: {}", file_name, retries);
        if (sendEncryptedFile(file_name))
        {
            final_op = RequestOp::OP_CRC_SUCCESS;
            ClientUtility::logFileStatus(file_name, ClientUtility::SUCCESS,
                                         ClientUtility::MAX_RETRIES);
            break;
        }

        ClientUtility::logFileStatus(file_name, retries,
                                     ClientUtility::MAX_RETRIES);

        if (retries == ClientUtility::MAX_RETRIES)
        {
            final_op = RequestOp::OP_CRC_FAILURE;
            break;
        }

        connection_manager_ptr_->connectSendReceiveDisconnect(*createPacket(
            ClientID(getClientID()), final_op, FileName(file_name)));

        retries++;
    }

    connection_manager_ptr_->connectSendReceiveDisconnect(
        *createPacket(ClientID(getClientID()), final_op, FileName(file_name)));
}

bool Client::sendEncryptedFile(const std::string &file_name)
{
    std::ifstream input_file(file_name, std::ios::binary);

    if (!input_file.good())
    {
        ERROR_LOG("Error: Unable to open file {}", file_name);
        throw std::runtime_error("Unable to open file");
    }

    FileEncryptor encryptor(ClientUtility::toHexString(aes_key_), file_name);
    auto [encryptedContent, crcValue] = encryptor.encryptAndComputeCRC();

    LOG(ClientUtility::CRC_SUCCESS_LOG, crcValue, file_name);

    auto response = connection_manager_ptr_->connectSendReceiveDisconnect(
        *createPacket(ClientID(getClientID()), FileName(file_name),
                      FileContent(encryptedContent)));

    if (!response || response->getStatusCode() != STATUS_FILE_RECIEVED)
    {
        ERROR_LOG("Error: Unexpected status code or no response: {}",
                  response ? response->getStatusCodeString() : "No response");
        return false;
    }

    auto responseWithCRC = dynamic_cast<ResponseWithCRC *>(response.get());
    if (!responseWithCRC)
    {
        throw std::runtime_error("Unexpected response type received: " +
                                 response->getStatusCodeString());
    }

    if (responseWithCRC->getCRCValue() != crcValue)
    {
        ERROR_LOG(ClientUtility::CRC_MISMATCH_LOG, file_name,
                  responseWithCRC->getCRCValue(), crcValue);

        return false;
    }

    LOG("CRC value: " + ClientUtility::ANSI_YELLOW + "{}" +
            ClientUtility::ANSI_RESET + " matches for file: {}",
        responseWithCRC->getCRCValue(), crcValue);
    return true;
}

// ==================== LoadingHelper ====================

void Client::Loader::load()
{
    try
    {
        client_.createRSA(loadPrivateKey(), loadMeInfo());
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error("Failed to load client info: " +
                                 std::string(e.what()));
    }
}

const std::string Client::Loader::loadMeInfo()
{
    std::ifstream infile("me.info");
    if (!infile)
    {
        throw std::runtime_error("Failed to open me.info");
    }

    std::string line;
    int line_num = 0;
    std::ostringstream public_key_stream;

    while (std::getline(infile, line))
    {
        if (line_num == 0)
        {
            client_.setClientName(line);
        }
        else if (line_num == 1)
        {
            client_.setClientID(ClientUtility::parseUUID(line));
        }
        else  // public key starts with 3rd line until the end
        {
            ClientUtility::appendPublicKey(public_key_stream, line);
        }
        line_num++;
    }
    infile.close();
    if (line_num < 3)
    {
        throw std::runtime_error("me.info is corrupted: " +
                                 std::to_string(line_num) + " lines found.");
    }
    return public_key_stream.str();
}

const std::string Client::Loader::loadPrivateKey()
{
    std::string line;
    std::ifstream priv_key_file("priv.key");
    std::string private_key_base64;
    std::ostringstream oss;
    while (std::getline(priv_key_file, line))
    {
        oss << line;
    }
    private_key_base64 = oss.str();
    priv_key_file.close();
    return private_key_base64;
}
