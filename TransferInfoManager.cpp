#include "TransferInfoManager.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

#include "ErrorsModule.hpp"
#include "LoggerModule.hpp"

namespace TransferInfoManagerConstants
{
constexpr const char *DEFAULT_FILE_NAME = "transfer.info";
constexpr const char *DEFAULT_IP = "127.0.0.1";
constexpr int DEFAULT_PORT = 1234;
constexpr const char *DEFAULT_CLIENT_NAME = "Client";
}  // namespace TransferInfoManagerConstants

namespace TransferInfoValidator
{
bool isValidPort(int port)
{
    if (port == TransferInfoManagerConstants::DEFAULT_PORT)
    {
        return true;
    }
    WARN_LOG("Port number is not the default: {}", port);
    return port > 0 && port <= 65535;
}

bool isValidIPAddress(const std::string &ip)
{
    if (ip.empty())  // Check for an empty string
    {
        return false;
    }
    if (ip == TransferInfoManagerConstants::DEFAULT_IP)
    {
        return true;
    }
    WARN_LOG("IP address is not the default: {}", ip);
    std::stringstream ss(ip);
    int a, b, c, d;
    char ch;
    return (ss >> a >> ch >> b >> ch >> c >> ch >> d && a <= 255 && b <= 255 &&
            c <= 255 && d <= 255);
}


bool isValidName(const std::string &name) { return (name.length() < 100); }

static std::string extractFileName(const std::string &path)
{
    size_t pos = path.find_last_of("/\\");
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

void checkFile(const std::string &input_file_name)
{
    std::string file = extractFileName(input_file_name);
    DEBUG_LOG("Checking if file: \"{}\" is empty.", file);
    if (input_file_name.empty())
    {
        std::string errorMsg = "The provided file name string is empty.";
        throw std::runtime_error(errorMsg);
    }

    DEBUG_LOG("Checking if file: \"{}\" exists.", file);
    if (!std::filesystem::exists(input_file_name))
    {
        std::string errorMsg =
            "The specified file \"" + file + "\" does not exist.";
        throw std::runtime_error(errorMsg);
    }

    if (!std::filesystem::is_regular_file(input_file_name))
    {
        std::string errorMsg =
            "The path \"" + file + "\" does not point to a regular file.";
        throw std::runtime_error(errorMsg);
    }

    if (std::filesystem::is_empty(input_file_name))
    {
        std::string errorMsg = "The file \"" + file + "\" is empty.";
        throw std::runtime_error(errorMsg);
    }
}

void validateAndAdjustName(std::string &name)
{
    // Check for validity of name
    if (!isValidName(name))
    {
        WARN_LOG("Invalid client name: {}", name);

        // Trim name to 100 characters if it's too long
        if (name.length() > 100)
        {
            name = name.substr(0, 100);
            WARN_LOG("Trimmed client name to 100 characters: {}", name);
        }
        // Set to a default name if it's empty
        else if (name.empty())
        {
            name = "DefaultName";
            WARN_LOG("Client name is empty. Set to default: {}", name);
        }
        else
        {
            throw std::runtime_error("Invalid client name.");
        }
    }
}

}  // namespace TransferInfoValidator

using namespace TransferInfoManagerConstants;
using namespace TransferInfoValidator;

TransferInfoManager::TransferInfoManager()
    : TransferInfoManager(DEFAULT_FILE_NAME)
{
    // Constructor delegation
}

TransferInfoManager::TransferInfoManager(const std::string &input_file_name)
    : client_name_(""),
      port_number_(-1),
      ip_address_(""),
      file_names_({}),
      file_name_("")
{
    auto [ip, port, name] = readIPAndPortAndNameFromFile(input_file_name);
    setIPAndPortAndName(ip, port, name);
}

std::string TransferInfoManager::getName() const { return client_name_; }

std::string TransferInfoManager::getIPAddress() const { return ip_address_; }

int TransferInfoManager::getPort() const { return port_number_; }

std::string TransferInfoManager::getFileName()
{
    while (!file_name_.empty() || !file_names_.empty())
    {
        try
        {
            checkFile(file_name_);
            std::string current_file_name = file_name_;
            moveToNextFile();  // Updates file_name_ and file_names_
            return current_file_name;
        }
        catch (const std::exception &e)
        {
            WARN_LOG(
                "File validation failed: {}. Skipping and moving to the next "
                "file.",
                e.what());
            moveToNextFile();  // Updates file_name_ and file_names_
        }
    }
    throw ErrorsModule::NoMoreFilesException();
}

void TransferInfoManager::moveToNextFile()
{
    if (!file_names_.empty())
    {
        file_name_ = file_names_.front();
        file_names_.erase(file_names_.begin());
    }
    else
    {
        file_name_.clear();
    }
}

std::tuple<std::string, int, std::string>
TransferInfoManager::readIPAndPortAndNameFromFile(
    const std::string &input_file_name)
{
    std::string info_file_name = input_file_name;
    if (info_file_name != DEFAULT_FILE_NAME)
    {
        std::string warnMsg = "Invalid file name: " + info_file_name +
                              ". It should be " + DEFAULT_FILE_NAME +
                              ". Proceeding with "
                              "the default file name.";
        WARN_LOG("transfer.info warning: {}", warnMsg);
        info_file_name = DEFAULT_FILE_NAME;
    }
    try
    {
        checkFile(info_file_name);
    }
    catch (const std::exception &e)
    {
        std::string errorMsg =
            "File validation failed: " + std::string(e.what()) +
            " Using Defult values: " + DEFAULT_IP + ":" +
            std::to_string(DEFAULT_PORT) + ": name: " + DEFAULT_CLIENT_NAME +
            ".";
        WARN_LOG("In setting up client: {}", errorMsg);
        return {DEFAULT_IP, DEFAULT_PORT, DEFAULT_CLIENT_NAME};
    }


    std::ifstream infile(info_file_name);
    if (!infile.is_open())
    {
        std::string errorMsg = "Failed to open file: " + info_file_name +
                               ". It may not exist or may be in use.";
        WARN_LOG("Warning setting up client: {}", errorMsg);
        throw std::runtime_error(errorMsg);
    }

    std::string ip_port_str, name;

    // Read IP and Port
    if (!std::getline(infile, ip_port_str))
    {
        throw std::runtime_error("Failed to read IP and Port from file.");
    }

    // Read client name
    if (!std::getline(infile, name))
    {
        throw std::runtime_error("Failed to read Client Name from file.");
    }

    // Clear existing file names
    file_names_.clear();

    // Read file names
    std::string file_line;
    while (std::getline(infile, file_line))
    {
        file_names_.push_back(file_line);
        DEBUG_LOG("File name: {}", file_line);
        try
        {
            checkFile(file_line);
        }
        catch (const std::exception &e)
        {
            WARN_LOG("File validation failed: {}", e.what());
        }
    }

    // Update the file_name_ attribute to store the first file name (if any)
    if (!file_names_.empty())
    {
        file_name_ = file_names_.front();
        file_names_.erase(
            file_names_.begin());  // remove the first filename from the list
    }

    size_t colon_pos = ip_port_str.find(':');
    if (colon_pos != std::string::npos)
    {
        std::string ip = ip_port_str.substr(0, colon_pos);
        int port = std::stoi(ip_port_str.substr(colon_pos + 1));
        DEBUG_LOG("IP address: {} | Port number: {} | Client Name: {}", ip,
                  port, name);
        return {ip, port, name};
    }

    throw std::runtime_error("Failed to parse IP and Port from file.");
}

void TransferInfoManager::setIPAndPortAndName(const std::string &ip, int port,
                                              std::string &name)
{
    if (!isValidIPAddress(ip) || !isValidPort(port))
    {
        ERROR_LOG("Invalid IP address or port number format: {}:{}", ip, port);
        throw std::runtime_error("Invalid IP address or port number format.");
    }

    validateAndAdjustName(name);

    ip_address_ = ip;
    port_number_ = port;
    client_name_ = name;
}
