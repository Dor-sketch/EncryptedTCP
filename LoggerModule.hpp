#pragma once

#include <fmt/core.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <cstdarg>
#include <iomanip>  // needed for setw and setfill
#include <iostream>
#include <iterator>
#include <ostream>
#include <sstream>
#include <string>
#include <type_traits>  // needed for std::is_same
#include <vector>

class LoggerModule
{
public:
    struct HexBuffer
    {
        const std::vector<unsigned char> &buffer;

        explicit HexBuffer(const std::vector<unsigned char> &buf) : buffer(buf) {}
    };

    static inline std::shared_ptr<spdlog::logger> logger_ = nullptr;

    static void init()
    {
        if (!logger_)
        {
            auto console_sink =
                std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            console_sink->set_pattern("[%^%l%$] %v");
            logger_ = std::make_shared<spdlog::logger>("logger", console_sink);
            console_sink->set_level(spdlog::level::debug);
            logger_->set_level(spdlog::level::debug);
            spdlog::register_logger(logger_);
        }
    }

    static void setLogLevel(spdlog::level::level_enum level)
    {
        if (logger_)
        {
            logger_->set_level(level);
        }
    }

private:
    template <typename T>
    static constexpr bool is_byte_vector =
        std::is_same<T, std::vector<unsigned char>>::value;

    template <typename T>
    static auto format_arg(const T &arg)
    {
        if constexpr (is_byte_vector<T>)
            return HexBuffer(arg);
        else
            return arg;
    }

public:
    template <typename... Args>
    static void log(const char *file, int line, spdlog::level::level_enum level,
                    const std::string &fmt, Args... args)
    {
        const int maxFileWidth = sizeof("TransferInfoManager.cpp") - 1;
        const int maxLineNumWidth = 3;
        const int maxTotalWidth = maxFileWidth + maxLineNumWidth + 5;

        std::ostringstream oss;
        oss << "[" << file << ":" << line << "]";

        int actualLength = oss.str().length();
        int spacesRequired = maxTotalWidth - actualLength;
        oss << std::string(spacesRequired, ' ');

        oss << "[%^%l%$] %v";

        spdlog::set_pattern(oss.str());

        switch (level)
        {
            case spdlog::level::info:
                logger_->info(fmt, format_arg(args)...);
                break;
            case spdlog::level::warn:
                logger_->warn(fmt, format_arg(args)...);
                break;
            case spdlog::level::err:
                logger_->error(fmt, format_arg(args)...);
                break;
            case spdlog::level::critical:
                logger_->critical(fmt, format_arg(args)...);
                break;
            case spdlog::level::debug:
                logger_->debug(fmt, format_arg(args)...);
                break;
            default:
                logger_->info(fmt, format_arg(args)...);
                break;
        }
    }
};

namespace fmt
{
template <>
struct formatter<LoggerModule::HexBuffer>
{
    template <typename ParseContext>
    constexpr auto parse(ParseContext &ctx)
    {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const LoggerModule::HexBuffer &buf, FormatContext &ctx)
    {
        std::string formatted;
        for (size_t i = 0; i < buf.buffer.size(); ++i)
        {
            formatted += fmt::format("{:02x} ", buf.buffer[i]);
            if ((i + 1) % 8 == 0) formatted += "\n";
        }
        return format_to(ctx.out(), "{}", formatted);
    }
};
}  // namespace fmt

struct AnsiColorCodes
{
    static constexpr const char *RESET = "\033[0m";
    static constexpr const char *BOLD = "\033[1m";
    static constexpr const char *RED = "\033[31m";
    static constexpr const char *GREEN = "\033[32m";
    static constexpr const char *YELLOW = "\033[33m";
    static constexpr const char *BLUE = "\033[34m";
    static constexpr const char *MAGENTA = "\033[35m";
};


#define DEBUG_LOG(fmt, ...)                                          \
    LoggerModule::log(__FILE__, __LINE__, spdlog::level::debug, fmt, \
                      ##__VA_ARGS__)
#define LOG(fmt, ...)                                               \
    LoggerModule::log(__FILE__, __LINE__, spdlog::level::info, fmt, \
                      ##__VA_ARGS__)
#define WARN_LOG(fmt, ...)                                          \
    LoggerModule::log(__FILE__, __LINE__, spdlog::level::warn, fmt, \
                      ##__VA_ARGS__)
#define ERROR_LOG(fmt, ...)                                        \
    LoggerModule::log(__FILE__, __LINE__, spdlog::level::err, fmt, \
                      ##__VA_ARGS__)
#define CRITICAL_LOG(fmt, ...)                                          \
    LoggerModule::log(__FILE__, __LINE__, spdlog::level::critical, fmt, \
                      ##__VA_ARGS__)
