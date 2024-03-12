#include "ConnectionManager.hpp"
#include "LoggerModule.hpp"
#include "Response.hpp"
#include "TransferInfoManager.hpp"

constexpr unsigned short DEFAULT_PORT = 1357;
constexpr const char *DEFAULT_IP = "127.0.0.1";



// A general-purpose exception handler for logging and re-throwing
void handleException(const std::string &message, const char *what)
{
    ERROR_LOG(message + "{}", what);
    throw std::runtime_error(message + what);
}

boost::asio::ip::tcp::endpoint createEndpoint(
    const boost::asio::ip::address &ip_address, unsigned short port_number)
{
    try
    {
        return boost::asio::ip::tcp::endpoint(ip_address, port_number);
    }
    catch (const boost::system::system_error &e)
    {
        throw ErrorsModule::NetworkException(
            "Endpoint creation failed: " + std::string(e.what()),
            ErrorsModule::NetworkErrorStatus::ENDPOINT_CREATION_ERROR);
    }
}

void checkPacketDataa(const std::vector<uint8_t> &packedData)
{

    DEBUG_LOG("Checking packet data: {} bytes.", packedData.size());

    if (packedData.size() < HEADER_SIZE)
    {
        WARN_LOG("Cannot send packet: Data is undersized: {} bytes.",
                 packedData.size());
        throw ErrorsModule::SendPacketException(
            "Cannot send packet: Data is undersized.",
            ErrorsModule::SendStatus::UNDERSIZED_PACKET);
    }


    if (packedData.size() > MAX_PACKET_SIZE + 2)
    {
        ERROR_LOG("Failed to send packet: Exceeds allowable packet size: {}",
                  packedData.size());
        throw ErrorsModule::SendPacketException(
            "Failed to send packet: Exceeds allowable packet size: " +
                std::to_string(packedData.size()),
            ErrorsModule::SendStatus::OVERSIZED_PACKET);
    }
}



ConnectionManager::ConnectionManager(const TransferInfoManager &info)
    : ip_address_str_(info.getIPAddress()), port_number_(info.getPort())
{
    DEBUG_LOG("Initializing ConnectionManager with IP: {} and port: {}",
              ip_address_str_, port_number_);
    initNetworking();
}

void ConnectionManager::initNetworking()
{
    try
    {
        // It's TransferInfoManager's responsibility to validate the IP and port;
        converIPAndCreateEndpoint();
        createSocket();
    }
    catch (const std::exception &e)
    {
        ERROR_LOG("Connection manager construction failed: {}.", e.what());
        throw;
    }
}



boost::asio::ip::address ConnectionManager::convertIPAddress(
    const std::string &ip_address_str)
{
    try
    {
        return boost::asio::ip::address::from_string(ip_address_str);
    }
    catch (const boost::system::system_error &e)
    {
        throw ErrorsModule::NetworkException(
            "IP address conversion failed: " + std::string(e.what()),
            ErrorsModule::NetworkErrorStatus::IP_CONVERSION_ERROR);
    }
}

void ConnectionManager::converIPAndCreateEndpoint()
{
    auto ip_address = convertIPAddress(ip_address_str_);
    end_point_ = createEndpoint(ip_address, port_number_);
}

void ConnectionManager::createSocket()
{
    try
    {
        socket_ = std::make_shared<boost::asio::ip::tcp::socket>(io_context_);
        DEBUG_LOG("Successfully created socket: {}:{}.", ip_address_str_,
                  port_number_);
    }
    catch (const boost::system::system_error &e)
    {
        handleNetworkException(
            *this,
            ErrorsModule::NetworkException(
                "Socket creation failed: " + std::string(e.what()),
                ErrorsModule::NetworkErrorStatus::SOCKET_CREATION_ERROR));
    }
}

// only placemnet new - currently has limited use
void handleNetworkException(ConnectionManager &con,
                            const ErrorsModule::NetworkException &e)

{
    unsigned short new_port;
    switch (e.getStatus())
    {
        case ErrorsModule::NetworkErrorStatus::ENDPOINT_CREATION_ERROR:
            new_port = DEFAULT_PORT;  // for example
            break;
        case ErrorsModule::NetworkErrorStatus::IP_CONVERSION_ERROR:
            new_port = DEFAULT_PORT;
            break;
        default:
            new_port = DEFAULT_PORT;
            break;
    }
    createEndpoint(con.convertIPAddress(DEFAULT_IP), new_port);
    con.createSocket();
    LOG("Reconnected to server with IP [{}] and port [{}]", DEFAULT_IP,
        new_port);
}


ConnectionManager::~ConnectionManager()
{
    if (socket_)
    {
        disconnect();
    }
}

void ConnectionManager::closeAndExit()
{
    WARN_LOG("Exiting ConnectionManager: socket status: {}",
             socket_ && socket_->is_open() ? "Socket is open - closing socket."
                                           : "Socket is not open.");
    if (socket_ && socket_->is_open())
    {
        socket_->close();
    }
}

void ConnectionManager::connect()
{
    try
    {
        if (socket_)
        {
            socket_->connect(end_point_);
            DEBUG_LOG("Successfully connected to server: {}:{}.",
                      ip_address_str_, port_number_);
        }
    }
    catch (const boost::system::system_error &e)
    {
        std::string error_message =
            std::string(e.what()) + " on IP: " + ip_address_str_ +
            " and port: " + std::to_string(port_number_);

        switch (e.code().value())
        {
        case ECONNREFUSED:
            throw ErrorsModule::NetworkException(error_message,
                                   ErrorsModule::NetworkErrorStatus::CONNECTION_REFUSED);
        case EHOSTUNREACH:
            throw ErrorsModule::NetworkException(error_message,
                                   ErrorsModule::NetworkErrorStatus::SERVER_DOWN);
        case ECONNRESET:
            throw ErrorsModule::NetworkException(error_message,
                                   ErrorsModule::NetworkErrorStatus::CONNECTOPN_CLOSED);

        case EISCONN:
            WARN_LOG("Already connected to server: {}:{}. Has the last sending compelted?", ip_address_str_,
                     port_number_);
            break;

        default:
            throw ErrorsModule::NetworkException(error_message,
                                   ErrorsModule::NetworkErrorStatus::UNKNOWN_ERROR);
        }
    }
}

void ConnectionManager::disconnect()
{
    if (socket_ && socket_->is_open())
    {
        socket_->close();
        DEBUG_LOG("Socket successfully closed: {}:{}.", ip_address_str_,
                  port_number_);
    }
}

void ConnectionManager::sendPacket(const Packet &packet)
{
    if (sizeof(packet) < 300) packet.print();
    DEBUG_LOG("Attempting to send packet to server: [{}]", packet.getOp());

    std::vector<uint8_t> packedData(packet.pack());

    try
    {
        checkPacketDataa(packedData);
    }
    catch (const ErrorsModule::SendPacketException &e)
    {
        throw ErrorsModule::SendPacketException(
            "Failed to send packet to server: " + std::string(e.what()),
            e.getSendStatus());
    }

    try
    {
#ifdef ENABLE_DEBUG_LOGGING
        uint8_t underflow = 1;
        packedData = {underflow};
#endif
        boost::asio::write(*socket_,
                           boost::asio::buffer(packedData, packedData.size()));
        DEBUG_LOG("Successfully sent packet to server. ({} bytes)",
                  packedData.size());
    }
    catch (boost::system::system_error &e)
    {
        ERROR_LOG("Failed to send packet due to error: {} [Code: {} - {}]",
                  e.what(), e.code().value(), e.code().message());
        throw ErrorsModule::SendPacketException(
            "Network unavailable", ErrorsModule::SendStatus::FAILURE_NETWORK);
    }
}


std::unique_ptr<Response> ConnectionManager::receiveData()
{
    std::vector<unsigned char> headerBuffer(Response::HEADER_SIZE);
    try
    {
        boost::asio::read(*socket_, boost::asio::buffer(headerBuffer));

        uint32_t payloadSize = static_cast<uint32_t>(headerBuffer[3]) |
                               (static_cast<uint32_t>(headerBuffer[4]) << 8) |
                               (static_cast<uint32_t>(headerBuffer[5]) << 16) |
                               (static_cast<uint32_t>(headerBuffer[6]) << 24);

        DEBUG_LOG("Expected payload size: {} bytes.", payloadSize);
        if (payloadSize > Response::MAX_PAYLOAD_SIZE)
        {
            ERROR_LOG(
                "Received payload size ({}) exceeds the maximum allowable size "
                "({} MB).",
                payloadSize, MAX_PAYLOAD_SIZE / (1024 * 1024));
            throw std::runtime_error("Payload size exceeds the maximum limit.");
        }

        std::vector<unsigned char> payloadBuffer(payloadSize);

        if (payloadSize > 0)
        {
            boost::asio::read(*socket_, boost::asio::buffer(payloadBuffer));
            DEBUG_LOG("Successfully fetched [payload] from server ({} bytes).",
                      payloadSize);
        }

        DEBUG_LOG("Successfully fetched [header] from server ({} bytes).",
                  Response::HEADER_SIZE);
        headerBuffer.insert(headerBuffer.end(), payloadBuffer.begin(),
                            payloadBuffer.end());
    }
    catch (const boost::system::system_error &e)
    {
        if (e.code() == boost::asio::error::eof)
        {
            throw ErrorsModule::NetworkException("Connection closed by server.",
                                   ErrorsModule::NetworkErrorStatus::UNKNOWN_ERROR);
        }
        else if (e.code().value() == ECONNRESET)
        {
            throw ErrorsModule::NetworkException("Connection reset by server.",
                                   ErrorsModule::NetworkErrorStatus::CONNECTOPN_CLOSED);
        }
        else
        {
            throw ErrorsModule::NetworkException("Unknown network error.",
                                   ErrorsModule::NetworkErrorStatus::UNKNOWN_ERROR);
        }
    }
    return ResponseFactory(headerBuffer);
}

bool ConnectionManager::isFailureStatusCode(uint16_t statusCode) const
{
    return (statusCode == STATUS_SIGN_UP_FAILURE ||
            statusCode == STATUS_SIGN_IN_FAILURE ||
            statusCode == STATUS_GENERAL_FAILURE);
}

// This function contains only retry logic and calls the operation. It doesn't
// do logging or exception handling.
void ConnectionManager::handleOperationWithRetry(
    const std::function<void(std::unique_ptr<Response> &)> &operation,
    std::unique_ptr<Response> &outResponse)
{
    const int maxRetries = 3;
    for (int retryCount = 0; retryCount < maxRetries; ++retryCount)
    {
        if (executeAndCheck(operation, outResponse, retryCount))
        {
            return;  // Successfully executed and checked, return.
        }
        // each retry will wait for 1 second more than the previous retry
        std::this_thread::sleep_for(std::chrono::seconds(retryCount));
    }
    closeAndExit();
    throw ErrorsModule::NetworkException("Max retry attempts reached.",
                           ErrorsModule::NetworkErrorStatus::MAX_RETRY_REACHED);
}

// This function actually executes the operation and checks for specific errors
bool ConnectionManager::executeAndCheck(
    const std::function<void(std::unique_ptr<Response> &)> &operation,
    std::unique_ptr<Response> &outResponse, int retryCount)
{
    try
    {
        operation(outResponse);
        if (outResponse)
        {
            if (isFailureStatusCode(outResponse->getStatusCode()))
            {
                handleFailureStatus(outResponse);
            }
            return true;
        }
    }
    // swalling the exceptions only for demonstration - in real world
    // application, we should handle them appropriately
    catch (const ErrorsModule::SendPacketException &e)
    {
        WARN_LOG("On try {} of 3: SendPacket failed with error: {}, status: {}",
                 retryCount + 1, std::string(e.what()),
                 e.getFullMessage(e.getSendStatus(), e.what()));
    }
    catch (const ErrorsModule::NetworkException &e)
    {
        WARN_LOG("On try {} of 3: {}", retryCount + 1, e.what());
        // becuse the lambda is capture by reference, we cant change the
        // operation (for example, change the ip address)
    }

    return false;
}

// Only for demonstration - the connection manager should not handle the
// failure status code. It should be handled by the caller.
void ConnectionManager::handleFailureStatus(
    const std::unique_ptr<Response> &response)
{
    if (response->getStatusCode() == STATUS_SIGN_IN_FAILURE)
    {
        // not throwint SignInError() because it's note the connection manager's
        // responsibility
    }
    disconnect();
    WARN_LOG(
        "Received failure status code: {} - {}: Network operation succeeded, "
        "but server rejected request. Please handle appropriately.",
        response->getStatusCode(), response->getStatusCodeString());
}

std::unique_ptr<Response> ConnectionManager::connectSendReceiveDisconnect(
    const PacketUtils::Packet &packet)
{
    std::unique_ptr<Response> response;
    try
    {
        handleOperationWithRetry(
            [this, &packet](std::unique_ptr<Response> &outResponse)
            {
                connect();
                sendPacket(packet);
                outResponse = receiveData();
                disconnect();
            },
            response);
    }
    catch (const ErrorsModule::NetworkException &e)
    {
        if (e.getStatus() == ErrorsModule::NetworkErrorStatus::MAX_RETRY_REACHED)
            handleException("Exceeded max retry attempts: ", e.what());
    }
    catch (const std::exception &e)
    {
        handleException("Failed to send packet to server: ", e.what());
    }
    return response;
}
