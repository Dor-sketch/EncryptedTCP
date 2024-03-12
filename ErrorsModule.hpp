#pragma once

#include <map>
#include <stdexcept>
#include <string>

namespace ErrorsModule
{


// ==================== Files ====================
class NoMoreFilesException : public std::runtime_error
{
public:
    NoMoreFilesException() : std::runtime_error(predefinedMessage) {}

    // Overloaded constructor for custom messages
    explicit NoMoreFilesException(const std::string& customMessage)
        : std::runtime_error(customMessage)
    {
    }

private:
    static const std::string predefinedMessage;
};

// ==================== Return Client ====================
class AlreadyRegisteredException : public std::runtime_error
{
public:
    AlreadyRegisteredException() : std::runtime_error(predefinedMessage) {}

    // Overloaded constructor for custom messages
    explicit AlreadyRegisteredException(const std::string& customMessage)
        : std::runtime_error(customMessage)
    {
    }

private:
    static const std::string predefinedMessage;
};

}  // namespace ErrorsModule