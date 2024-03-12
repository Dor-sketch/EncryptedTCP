#include <iostream>
#include <sstream>
#include <string>

#include "Client.hpp"
#include "FileEncryptor.hpp"
#include "LoggerModule.hpp"

int runClient()
{
    try
    {
        Client client;
        client.handleRequest();
    }
    catch (const std::exception& e)
    {
        WARN_LOG(
            "Unhandled exception reached main: {}\nPlease review logs history. "
            "If all requests were successful, please ignore this message.",
            e.what());
        return EXIT_FAILURE;
    }
    catch (...)
    {
        CRITICAL_LOG("An unknown exception reached main.", "");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void printHelp()
{
    const std::string help =
        "Usage: ./client_app [OPTIONS]\n"
        "\nOptions:\n"
        "  -h, --help      Show this help message and exit.\n"
        "  --decrypt       Run in decryption mode - currently not supported.\n"
        "  --log=LEVEL     Set the logging level (DEBUG, CRITICAL).\n";

    LOG("{}",help);
}

int main(int argc, char const* const* argv)
{
    try
    {
        LoggerModule::init();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Failed to initialize logging: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    /*bool decryptMode = false;*/
    LoggerModule::setLogLevel(spdlog::level::info);

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--decrypt")
        {
            LOG("Decryption mode is currently not supported.", "");
        }
        else if (arg == "--log=DEBUG")
        {
            LoggerModule::setLogLevel(spdlog::level::debug);
            WARN_LOG("Running in debug mode.", "");
        }
        else if (arg == "--log=CRITICAL")
        {
            LoggerModule::setLogLevel(spdlog::level::critical);
            CRITICAL_LOG("Running in critical mode.", "");
        }
        else if (arg == "-h" || arg == "--help")
        {
            printHelp();
            return EXIT_SUCCESS;
        }
        else
        {
            std::cerr << "Unknown option: " << arg << std::endl;
            printHelp();
            return EXIT_FAILURE;
        }
    }

    return runClient();
}