#include "ClientState.hpp"

#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <filesystem>

#include "Client.hpp"
#include "LoggerModule.hpp"
#include "SignErrors.hpp"
#include "TransferInfoManager.hpp"

using namespace ErrorsModule;

void Client::handleRequest() { state_->handleRequest(this); }

// TODO: In more complex applications, this function should be replaced with a
// set of overloaded constructors for each state. This will also prevent
// unwanted state changes, or loops in the state machine.
void ClientState::changeState(Client *client, const ClientStateEnum &newState)
{
    switch (newState)
    {
        case ClientStateEnum::INITIAL:
            client->setState(std::make_unique<InitialState>());
            break;
        case ClientStateEnum::AWAITING_UUID:
            client->setState(std::make_unique<AwaitingUUIDState>());
            break;
        case ClientStateEnum::AWAITING_NEW_AES:
            client->setState(std::make_unique<AwaitingNewAESState>());
            break;
        case ClientStateEnum::AWAITING_OLD_AES:
            client->setState(std::make_unique<AwaitingOldAESState>());
            break;
        case ClientStateEnum::CRC_VERIFYING:
            client->setState(std::make_unique<CRCVerificationState>());
            break;
    }
}

// ========== InitialState ==========
void InitialState::handleRequest(Client *client)
{
    try
    {
        client->signUp();
        changeState(client, ClientStateEnum::AWAITING_NEW_AES);
    }
    catch (const SignInError &e)
    {
        WARN_LOG("Dear {}, a signing event, please note: {}",
                 client->getClientName(),
                 e.getFullMessage(e.getStatus(), e.getExtraInfo()));

        switch (e.getStatus())
        {
            case SignInStatus::ALREADY_REGISTERED:
                changeState(client, ClientStateEnum::AWAITING_OLD_AES);
                break;
            default:
                WARN_LOG(
                    "Exiting client loop: Failed to sign up in "
                    "InitialState::handleRequest. Error: {}",
                    e.what());
                return;
        }
    }
    catch (const std::exception &e)
    {
        WARN_LOG(
            "Exiting client loop: Failed to sign up in "
            "InitialState::handleRequest. Error: {}",
            e.what());
        return;
    }
    client->handleRequest();
}

// ========== AwaitingUUIDState ==========

void AwaitingUUIDState::handleRequest(Client *client)
{
    client->registerClient();
    changeState(client, ClientStateEnum::AWAITING_NEW_AES);
}

// ========== AwaitingNewAESState ==========

void AwaitingNewAESState::handleRequest(Client *client)
{
    try
    {
        client->getNewAESKey();
        changeState(client, ClientStateEnum::CRC_VERIFYING);
    }
    catch (const SignInError &e)
    {
        WARN_LOG("Dear {}, a signing event, please note: {}",
                 client->getClientName(),
                 e.getFullMessage(e.getStatus(), e.getExtraInfo()));

        switch (e.getStatus())
        {
            // It is possible here to return to the initial state and try to
            // register again, but this is not implemented because it is
            // infinitely possible to get into a loop in bach mode.
            default:
                WARN_LOG(
                    "Exiting client loop: Failed to get new AES key in "
                    "AwaitingNewAESState::handleRequest. Error: {}",
                    e.what());
                return;
        }
    }
    catch (const std::exception &e)
    {
        WARN_LOG(
            "Exiting client loop: Failed to get new AES key in "
            "AwaitingNewAESState::handleRequest. Error: {}",
            e.what());
        return;
    }

    client->handleRequest();
}

// ========== AwaitingOldAESState ==========
void AwaitingOldAESState::handleRequest(Client *client)
{
    try
    {
        client->signIn();
        changeState(client, ClientStateEnum::CRC_VERIFYING);
        client->handleRequest();
    }
    catch (const SignInError &e)
    {
        WARN_LOG("Dear {}, a signing event, please note: {}",
                 client->getClientName(),
                 e.getFullMessage(e.getStatus(), e.getExtraInfo()));

        switch (e.getStatus())
        {
            case SignInStatus::FAILURE_INVALID_ME_INFO:
            case SignInStatus::FAILURE_INVALID_UUID:
                std::filesystem::remove("me.info");
                std::filesystem::remove("priv.key");

// For debug mode because it can create a loop
#ifdef ENABLE_DEBUG_LOGGING
                client->setClientID(boost::uuids::nil_generator()());
                // no need to reset name since the problem not in transfer.info
                changeState(client, ClientStateEnum::INITIAL);
                client->handleRequest();
#else
                break;
#endif
            default:
            {
                return;
            }
        }
    }
    catch (const std::exception &e)
    {
        WARN_LOG(
            "Exiting client loop: Failed to sign in in "
            "AwaitingOldAESState::handleRequest. Error: {}",
            e.what());
    }
}

// ========== CRCVerificationState ==========

void CRCVerificationState::handleRequest(Client *client)
{
    int file_count = 0;
    do
    {
        try
        {
            client->sendEncryptedFileAndCountCRC();
            ++file_count;
        }
        catch (const NoMoreFilesException &e)
        {
            LOG(file_count == 0 ? "No files to send. Exiting client loop."
                                : "[{}] Files sent. No more files to send. "
                                  "Exiting client loop.",
                file_count);
            break;
        }
        catch (const std::exception &e)
        {
            WARN_LOG(
                "Exiting client loop: Failed to send and verify file in "
                "CRCVerificationState::handleRequest. Error: {}",
                e.what());
        }
    } while (true);
}
