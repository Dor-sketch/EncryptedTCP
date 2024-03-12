#pragma once

#include <boost/uuid/uuid_io.hpp>
#include <iostream>
#include <memory>

#include "ErrorsModule.hpp"

class ClientState;
class ConnectionManager;
class RSAPrivateWrapper;
class TransferInfoManager;
class ResponseWithUUID;

class Client
{
    friend class ClientState;
    friend class InitialState;
    friend class AwaitingUUIDState;
    friend class AwaitingNewAESState;
    friend class AwaitingOldAESState;
    friend class CRCVerificationState;

public:
    Client();
    ~Client();
    void handleRequest();
    const std::string &getClientName() const;
    const std::array<unsigned char, 16> &getClientID() const;

private:
    void init();  // initiate the transfer info manager and connection manager
    const std::string getRunningModeString();
    void setState(std::unique_ptr<ClientState> newState);
    void setClientID(const boost::uuids::uuid &uuid);
    void setClientName(const std::string &name);
    void setAESKey(const std::string &key);


    // registering functions
    void signUp();
    void createRSA(const std::string &private_key_base64,
                   const std::string &public_key_stream);
    void createMeInfo(const ResponseWithUUID& response);  // create me.info file
    void registerClient();
    void getNewAESKey();
    void handleSignUpError(const std::exception &e);
    void reset();

    // signing functions
    const std::string tryGetFileToSend();
    void loadClientInfo();
    void signIn();
    const std::string requestAESKey();

    // sending functions
    void sendEncryptedFileAndCountCRC();
    bool sendEncryptedFile(const std::string &file_name);

    std::string client_name_;
    std::string aes_key_;
    std::array<unsigned char, 16> client_id_;
    std::shared_ptr<TransferInfoManager> transfer_info_manager_ptr_;
    std::unique_ptr<ConnectionManager> connection_manager_ptr_;
    std::unique_ptr<RSAPrivateWrapper> rsa_ptr_;
    std::unique_ptr<ClientState> state_;

    class Loader
    {
    public:
        explicit Loader(Client &client) : client_(client) {}

        void load();

    private:
        const std::string loadMeInfo();
        void handleLoadMeInfoError(const std::exception &e);
        const std::string loadPrivateKey();
        Client &client_;
    };
};
