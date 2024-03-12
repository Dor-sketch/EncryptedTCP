#pragma once

class Client;  // Forward declaration

enum class ClientStateEnum
{
    INITIAL,
    AWAITING_UUID,     // Client is not registered and needs a UUID.
    AWAITING_NEW_AES,  // Client is partially registered and requests a new AES
    AWAITING_OLD_AES,  // Client is signing in and needs the previous AES key.
    CRC_VERIFYING,  // Client is sending a file, and the CRC is being verified.
};

class ClientState
{
public:
    friend class Client;
    virtual ~ClientState() = default;
    virtual void handleRequest(Client *client) = 0;
    virtual void changeState(Client *client, const ClientStateEnum &newState);

protected:
    ClientState() = default;  // Prevent instantiation outside of client.
};

class InitialState : public ClientState
{
public:
    void handleRequest(Client *client) override;
};

class AwaitingUUIDState : public ClientState
{
public:
    void handleRequest(Client *client) override;
};

class AwaitingNewAESState : public ClientState
{
public:
    void handleRequest(Client *client) override;
};

class AwaitingOldAESState : public ClientState
{
public:
    void handleRequest(Client *client) override;
};

class CRCVerificationState : public ClientState
{
public:
    void handleRequest(Client *client) override;
};
