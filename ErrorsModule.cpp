#include "ErrorsModule.hpp"

#include "NetworkErrors.hpp"
#include "SignErrors.hpp"

#define SUCCESS(X) "\033[1;32m" X "\033[0m\n"  // bold green
#define WARNING(X) "\033[1;33m" X "\033[0m\n"  // bold yellow
#define HEADER(X) "\033[1;34m" X "\033[0m\n"   // bold white
#define INFO(X) "\033[1;37m" X "\033[0m\n"     // bold white
#define LIST_ITEM(X) " - " X "\n"

// mostly implementations for static members
namespace ErrorsModule
{
const std::string SEPERATOR = "-------------------------------\n";
const std::string CLOSING_SEPERATOR = "-------------------------------";
const std::string POSSIBLE_CAUSES = HEADER("Possible Causes:");
const std::string RECOMMENDED_ACTIONS = HEADER("Recommended Actions:");

// Network errors
const std::string NETWORK_ERROR_HEADER = INFO("Network Notice:");

// File errors
const std::string FILE_ERROR_HEADER = INFO("File Notice:");
const std::string FILE_ERROR_POSSIBLE_CAUSES =
    POSSIBLE_CAUSES + LIST_ITEM("File permissions.") +
    LIST_ITEM("Disk space.") + LIST_ITEM("Network connection.");
const std::string FILE_ERROR_RECOMMENDED_ACTIONS =
    RECOMMENDED_ACTIONS + LIST_ITEM("Check file permissions.") +
    LIST_ITEM("Check disk space.") + LIST_ITEM("Check network connection.") +
    LIST_ITEM("Try again later.");


const std::string GENERAL_ERROR_HEADER = HEADER("General ERROR:");
const std::string GENERAL_ERROR_RECOMMENDED_ACTIONS =
    std::string(HEADER("Recommended Actions:")) +
    LIST_ITEM("Restart the application.") + LIST_ITEM("Try again later.");

const std::string GENERAL_ERROR_NOTE =
    std::string(INFO("Note:")) +
    LIST_ITEM(
        "Frequent failures might indicate a bigger issue. "
        "Investigate accordingly.");

const std::string GENERAL_ERROR_POSSIBLE_CAUSES =
    POSSIBLE_CAUSES + LIST_ITEM("Unknown.");

const std::string UNKNOWN_ERROR_HEADER = HEADER("Unknown ERROR:");
const std::string UNKNOWN_ERROR_RECOMMENDED_ACTIONS =
    std::string(HEADER("Recommended Actions:")) +
    LIST_ITEM("Restart the application.") + LIST_ITEM("Try again later.");

const std::string UNKNOWN_ERROR_NOTE =
    std::string(HEADER("Note:")) + LIST_ITEM(
                                       "Frequent failures might "
                                       "indicate a bigger issue. "
                                       "Investigate accordingly.");

const std::string UNKNOWN_ERROR_POSSIBLE_CAUSES =
    std::string(HEADER("Possible Causes:")) + LIST_ITEM("Unknown.");

const std::string EXTRA_INFORMATION = HEADER("Extra Information:");


std::map<SendStatus, std::string> SendPacketException::SendStatusMessages = {
    {SendStatus::SUCCESS,
     std::string(SUCCESS("Packet Sent Successfully:")) + SEPERATOR +
         LIST_ITEM("Packet sent successfully.") + CLOSING_SEPERATOR},

    {SendStatus::FAILURE_NETWORK,
     std::string(WARNING("Network Notice:")) +
         WARNING("Failed to send packet to server.") + POSSIBLE_CAUSES +
         LIST_ITEM("Network issues.") + LIST_ITEM("Server down.") +
         LIST_ITEM("Server timeout.") + LIST_ITEM("Sending took too long.") +
         RECOMMENDED_ACTIONS + LIST_ITEM("Check network connection.") +
         LIST_ITEM("Check server status.") + LIST_ITEM("Try again later.") +
         GENERAL_ERROR_RECOMMENDED_ACTIONS + GENERAL_ERROR_NOTE +
         CLOSING_SEPERATOR},

    {SendStatus::OVERSIZED_PACKET,
     SEPERATOR + NETWORK_ERROR_HEADER +
         LIST_ITEM("Packet size exceeds maximum allowed size.") +
         POSSIBLE_CAUSES + LIST_ITEM("Malformed packet.") +
         LIST_ITEM("Using debug tests.") + LIST_ITEM("Network issues.") +
         RECOMMENDED_ACTIONS +
         LIST_ITEM("Check packet size valid values (see PacketUtils module)") +
         LIST_ITEM("Check that packet size field matches actual packet size.") +
         LIST_ITEM("Try again later.") + CLOSING_SEPERATOR},

    {SendStatus::UNDERSIZED_PACKET,
     SEPERATOR + NETWORK_ERROR_HEADER +
         LIST_ITEM("Packet size to small for sending.") + POSSIBLE_CAUSES +
         LIST_ITEM("Malformed packet.") + LIST_ITEM("Network issues.") +
         RECOMMENDED_ACTIONS + LIST_ITEM("Check packet size.") +
         LIST_ITEM("Check network connection.") +
         LIST_ITEM("Try again later.") + GENERAL_ERROR_RECOMMENDED_ACTIONS +
         GENERAL_ERROR_NOTE + CLOSING_SEPERATOR}};

const std::string NetworkException::getMessageForStatus(
    NetworkErrorStatus status)
{
    auto it = statusMessages.find(status);
    if (it != statusMessages.end())
    {
        return it->second;
    }
    return "Unknown Status";
}

const std::string NetworkException::getFullMessage(NetworkErrorStatus status,
                                                   const std::string& extraInfo)
{
    if (extraInfo.empty())
    {
        return getMessageForStatus(status);
    }
    std::string mainMessage = getMessageForStatus(status);
    return "\n" + mainMessage + "\n" + EXTRA_INFORMATION + extraInfo + "\n" +
           CLOSING_SEPERATOR;
}

const std::string NoMoreFilesException::predefinedMessage =
    SEPERATOR + INFO("No Files Found") + FILE_ERROR_POSSIBLE_CAUSES + "\n" +
    FILE_ERROR_RECOMMENDED_ACTIONS + SEPERATOR;

// Initialize static members
std::map<NetworkErrorStatus, std::string> NetworkException::statusMessages = {

    {NetworkErrorStatus::CONNECTOPN_CLOSED,
     SEPERATOR + NETWORK_ERROR_HEADER +
         LIST_ITEM("Connection "
                   "closed by server.") +
         POSSIBLE_CAUSES + LIST_ITEM("Server down.") +
         LIST_ITEM("Network issues.") + RECOMMENDED_ACTIONS +
         LIST_ITEM("Check server status.") +
         LIST_ITEM("Check network connection.") +
         LIST_ITEM("Try again later.") + CLOSING_SEPERATOR},

    {NetworkErrorStatus::CONNECTION_REFUSED,
     SEPERATOR + NETWORK_ERROR_HEADER + INFO("Connection refused by server.") +
         POSSIBLE_CAUSES + LIST_ITEM("Server down.") +
         LIST_ITEM("Network issues.") + RECOMMENDED_ACTIONS +
         LIST_ITEM("Check server status.") +
         LIST_ITEM("Check network connection.") +
         LIST_ITEM("Try again later.") + CLOSING_SEPERATOR},

    {NetworkErrorStatus::UNKNOWN_ERROR,
     SEPERATOR + NETWORK_ERROR_HEADER + UNKNOWN_ERROR_POSSIBLE_CAUSES + "\n" +
         UNKNOWN_ERROR_RECOMMENDED_ACTIONS + "\n" + UNKNOWN_ERROR_NOTE +
         CLOSING_SEPERATOR},

    {NetworkErrorStatus::SERVER_DOWN,
     SEPERATOR + NETWORK_ERROR_HEADER + LIST_ITEM("Server is down.") +
         POSSIBLE_CAUSES + LIST_ITEM("Server down.") +
         LIST_ITEM("Network issues.") + RECOMMENDED_ACTIONS +
         LIST_ITEM("Check server status.") +
         LIST_ITEM("Check network connection.") +
         LIST_ITEM("Try again later.") + GENERAL_ERROR_RECOMMENDED_ACTIONS +
         GENERAL_ERROR_NOTE + CLOSING_SEPERATOR},

    {NetworkErrorStatus::MAX_RETRY_REACHED,
     std::string(WARNING("Network Notice:")) +
         WARNING("Failed to send packet to server after 3 retries.") +
         POSSIBLE_CAUSES + LIST_ITEM("Network issues.") +
         LIST_ITEM("Server down.") + RECOMMENDED_ACTIONS +
         LIST_ITEM("Check network connection.") +
         LIST_ITEM("Check server status.") +
         LIST_ITEM("Make sure the server port is open and matches the "
                   "application's port.") +
         LIST_ITEM("Check configuration file (transfer.info, port.info).") +
         LIST_ITEM("Try again later.") + GENERAL_ERROR_RECOMMENDED_ACTIONS +
         GENERAL_ERROR_NOTE + CLOSING_SEPERATOR},


    {NetworkErrorStatus::SEND_PACKET_EXCEPTION,
     SEPERATOR + NETWORK_ERROR_HEADER + INFO("Failed to send packet.") +
         POSSIBLE_CAUSES + LIST_ITEM("Network issues.") +
         LIST_ITEM("Server down.") + RECOMMENDED_ACTIONS +
         LIST_ITEM("Check network connection.") +
         LIST_ITEM("Check server status.") + LIST_ITEM("Try again later.") +
         GENERAL_ERROR_RECOMMENDED_ACTIONS + "\n" + GENERAL_ERROR_NOTE +
         CLOSING_SEPERATOR},

    {NetworkErrorStatus::ENDPOINT_CREATION_ERROR,
     SEPERATOR + NETWORK_ERROR_HEADER + WARNING("Failed to create endpoint.") +
         POSSIBLE_CAUSES + LIST_ITEM("Network issues.") +
         LIST_ITEM("Server down.") + RECOMMENDED_ACTIONS +
         LIST_ITEM("Check network connection.") +
         LIST_ITEM("Check server status.") + LIST_ITEM("Try again later.") +
         GENERAL_ERROR_RECOMMENDED_ACTIONS + "\n" + GENERAL_ERROR_NOTE +
         CLOSING_SEPERATOR},

    {NetworkErrorStatus::IP_CONVERSION_ERROR,
     SEPERATOR + NETWORK_ERROR_HEADER +
         WARNING("Failed to convert IP address.") + POSSIBLE_CAUSES +
         LIST_ITEM("Network issues.") + LIST_ITEM("Server down.") +
         RECOMMENDED_ACTIONS + LIST_ITEM("Check network connection.") +
         LIST_ITEM("Check server status.") + LIST_ITEM("Try again later.") +
         GENERAL_ERROR_RECOMMENDED_ACTIONS + "\n" + GENERAL_ERROR_NOTE +
         CLOSING_SEPERATOR},

    {NetworkErrorStatus::SOCKET_CREATION_ERROR,
     SEPERATOR + NETWORK_ERROR_HEADER + WARNING("Failed to create socket.") +
         POSSIBLE_CAUSES + LIST_ITEM("Network issues.") +
         LIST_ITEM("Server down.") + RECOMMENDED_ACTIONS +
         LIST_ITEM("Check network connection.") +
         LIST_ITEM("Check server status.") + LIST_ITEM("Try again later.") +
         GENERAL_ERROR_RECOMMENDED_ACTIONS + "\n" + GENERAL_ERROR_NOTE +
         CLOSING_SEPERATOR},

    {NetworkErrorStatus::CONNECTION_ERROR,
     SEPERATOR + NETWORK_ERROR_HEADER +
         LIST_ITEM("Failed to connect to server.") + POSSIBLE_CAUSES +
         LIST_ITEM("Network issues.") + LIST_ITEM("Server down.") +
         RECOMMENDED_ACTIONS + LIST_ITEM("Check network connection.") +
         LIST_ITEM("Check server status.") + LIST_ITEM("Try again later.") +
         GENERAL_ERROR_RECOMMENDED_ACTIONS + "\n" + GENERAL_ERROR_NOTE +
         CLOSING_SEPERATOR}};

const std::map<SignInStatus, std::string> SignInError::statusMessages = {
    {SUCCESS_SIGN_IN,
     std::string(SUCCESS("Sign-in Successful:")) + SEPERATOR +
         LIST_ITEM("- You can now proceed with application functionality.") +
         CLOSING_SEPERATOR},

    {FAILURE_NETWORK_ERROR,
     HEADER("Network Failure:") + SEPERATOR +
         LIST_ITEM("Please ensure you have a stable internet connection.") +
         LIST_ITEM("Check if your firewall is blocking the application.") +
         CLOSING_SEPERATOR},

    {FAILURE_INVALID_UUID,
     HEADER("Invalid UUID:") + SEPERATOR +
         LIST_ITEM("Ensure you have signed up successfully.") +
         LIST_ITEM("Make sure your UUID is correct.") +
         LIST_ITEM("Retry the operation.") + CLOSING_SEPERATOR},

    {FAILURE_INVALID_ME_INFO,
     std::string(HEADER("Invalid 'Me' Information:")) + SEPERATOR +
         LIST_ITEM("Your personal information appears to be corrupted.") +
         LIST_ITEM("Remove corrupted files and try again.") +
         CLOSING_SEPERATOR},


    {FAILURE_GENERAL, GENERAL_ERROR_HEADER + GENERAL_ERROR_POSSIBLE_CAUSES +
                          "\n" + GENERAL_ERROR_RECOMMENDED_ACTIONS + "\n" +
                          GENERAL_ERROR_NOTE + CLOSING_SEPERATOR},

    {FAILURE_INVALID_AES, WARNING("Invalid AES Key:") + SEPERATOR +
                              LIST_ITEM("Your encryption key is invalid.") +
                              LIST_ITEM("Contact support immediately.") +
                              CLOSING_SEPERATOR},

    {ALREADY_REGISTERED,
     INFO("Already Registered:") + SEPERATOR +
         LIST_ITEM("Prior registration detected.") +
         LIST_ITEM(
             "If you've succeeded before, sign in to receive your AES key.") +
         LIST_ITEM("If you failed before, consider re-registering.") +
         CLOSING_SEPERATOR},

    {FAILURE_IN_AES_ENCRYPTION,
     INFO("AES Encryption Failure:") + SEPERATOR +
         LIST_ITEM("The AES encryption process failed.") +
         LIST_ITEM("Make sure you're using a valid AES key.") +
         LIST_ITEM("Contact support if the problem persists.") +
         CLOSING_SEPERATOR},

    {FAILURE_RSA_KEY_CREATION,
     INFO("RSA Key Creation Failure:") + SEPERATOR +
         LIST_ITEM("Unable to create RSA keys.") +
         LIST_ITEM("Check your system's encryption libraries.") +
         LIST_ITEM("Update or reinstall software if necessary.") +
         LIST_ITEM("Contact support if the problem persists.") +
         CLOSING_SEPERATOR},

    {FAILURE_INFO_CREATION,
     INFO("Me-Info Creation Failure:") + SEPERATOR +
         LIST_ITEM("Unable to create or update the 'Me.info' file.") +
         LIST_ITEM("Ensure you have adequate disk space and write "
                   "permissions.") +
         LIST_ITEM("Update or reinstall software if necessary.") +
         LIST_ITEM("Contact support if the problem persists.") +
         CLOSING_SEPERATOR}};

SignInError::SignInError(SignInStatus status)
    : std::runtime_error(getMessageForStatus(status)), status_(status)
{
}

SignInError::SignInError(const std::string& extraInfo, SignInStatus status)
    : std::runtime_error(getMessageForStatus(status)),
      status_(status),
      extraInfo_(extraInfo)
{
}

SignInStatus SignInError::getStatus() const { return status_; }

const std::string SignInError::getMessageForStatus(SignInStatus status)
{
    auto it = statusMessages.find(status);
    if (it != statusMessages.end())
    {
        return it->second;
    }
    return "Unknown status.";
}

const std::string SignInError::getFullMessage(enum SignInStatus status,
                                              const std::string& extraInfo)
{
    if (extraInfo.empty())
    {
        return getMessageForStatus(status);
    }
    std::string newLine = "\n";
    std::string mainMessage = getMessageForStatus(status);

    return newLine + mainMessage + "\n" + EXTRA_INFORMATION + extraInfo + "\n" +
           CLOSING_SEPERATOR;
}

// sendPacketException
const std::string SendPacketException::getMessageForStatus(SendStatus status)
{
    auto it = SendStatusMessages.find(status);
    if (it != SendStatusMessages.end())
    {
        return it->second;
    }
    return "Unknown status.";
}

const std::string SendPacketException::getFullMessage(
    enum SendStatus status, const std::string& extraInfo)
{
    if (extraInfo.empty())
    {
        return getMessageForStatus(status);
    }
    std::string newLine = "\n";
    std::string mainMessage = getMessageForStatus(status);

    return newLine + mainMessage + "\n" + EXTRA_INFORMATION + extraInfo + "\n" +
           CLOSING_SEPERATOR;
}

}  // namespace ErrorsModule
