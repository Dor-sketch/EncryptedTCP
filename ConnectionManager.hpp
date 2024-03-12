#pragma once

#include <boost/asio.hpp>
#include <functional>
#include <memory>
#include <thread>

#include "NetworkErrors.hpp"
#include "Packet.hpp"

using namespace PacketUtils;

class Response;
class TransferInfoManager;

class ConnectionManager;

// For more information on the following functions, see the readme.md file
void handleNetworkException(ConnectionManager &con,
                            const ErrorsModule::NetworkException &e);

class ConnectionManager
{
public:
    explicit ConnectionManager(const TransferInfoManager &info);
    ~ConnectionManager();

    std::unique_ptr<Response> connectSendReceiveDisconnect(
        const Packet &packet);

private:
    std::string ip_address_str_;
    int port_number_;
    boost::asio::ip::tcp::endpoint end_point_;
    boost::asio::io_context io_context_;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;

    // connection functions
    void initNetworking();
    boost::asio::ip::address convertIPAddress(
        const std::string &ip_address_str);
    void converIPAndCreateEndpoint();
    void createSocket();
    void handleSocketError(const boost::system::system_error &e);
    void handleConnectionError(const boost::system::system_error &e) const;
    void connect();
    void disconnect();
    void closeAndExit();

    // sending and receiving functions
    void sendPacket(const Packet &packet);
    bool executeAndCheck(
        const std::function<void(std::unique_ptr<Response> &)> &operation,
        std::unique_ptr<Response> &outResponse, int maxRetryCount);
    bool isFailureStatusCode(uint16_t statusCode) const;
    std::unique_ptr<Response> receiveData();

    // handlers
    void handleOperationWithRetry(
        const std::function<void(std::unique_ptr<Response> &)> &operation,
        std::unique_ptr<Response> &outResponse);
    void handleFailureStatus(const std::unique_ptr<Response> &response);
    friend void handleNetworkException(ConnectionManager &con,
                                       const ErrorsModule::NetworkException &e);
};
