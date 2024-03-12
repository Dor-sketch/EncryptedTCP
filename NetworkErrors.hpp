# pragma once

#include <map>
#include <stdexcept>
#include <string>

namespace ErrorsModule

{





enum class NetworkErrorStatus
{
    OVERSIZED_PACKET,
    CONNECTOPN_CLOSED,
    CONNECTION_REFUSED,
    UNKNOWN_ERROR,
    SERVER_DOWN,
    MAX_RETRY_REACHED,
    SEND_PACKET_EXCEPTION,
    ENDPOINT_CREATION_ERROR,
    IP_CONVERSION_ERROR,
    SOCKET_CREATION_ERROR,
    CONNECTION_ERROR
};

class NetworkException : public std::runtime_error
{
public:
    explicit NetworkException(NetworkErrorStatus status)
        : std::runtime_error(getMessageForStatus(status)), status_(status)
    {
    }

    explicit NetworkException(const std::string& customMessage)
        : std::runtime_error(customMessage),
          status_(NetworkErrorStatus::UNKNOWN_ERROR)
    {
    }

    NetworkException(const std::string& extraInfo, NetworkErrorStatus status)
        : std::runtime_error(getFullMessage(status, extraInfo)),
          status_(status),
          extraInfo_(extraInfo)
    {
    }

    virtual NetworkErrorStatus getStatus() const { return status_; }

    const std::string& getExtraInfo() const { return extraInfo_; }

    static const std::string getFullMessage(NetworkErrorStatus status,
                                            const std::string& extraInfo);

    static const std::string getMessageForStatus(NetworkErrorStatus status);

protected:
    NetworkErrorStatus status_;
    std::string extraInfo_;

    static std::map<NetworkErrorStatus, std::string> statusMessages;
};

enum class SendStatus
{
    SUCCESS,
    FAILURE_NETWORK,
    OVERSIZED_PACKET,
    UNDERSIZED_PACKET
};

// Custom Exception class
class SendPacketException : public NetworkException
{
public:
    SendPacketException(const std::string& message, SendStatus status)
        : NetworkException(message), status(status)
    {
    }
    SendStatus getSendStatus() const { return status; }
    static const std::string getMessageForStatus(SendStatus status);
    static const std::string getFullMessage(SendStatus status,
                                            const std::string& extraInfo);

private:
    SendStatus status;
    static std::map<SendStatus, std::string> SendStatusMessages;
};

}  // namespace ErrorsModule
