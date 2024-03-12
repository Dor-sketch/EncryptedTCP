#pragma once

#include <string>
#include <tuple>
#include <vector>

class TransferInfoManager
{
public:
    TransferInfoManager();
    explicit TransferInfoManager(const std::string &input_file_name);
    ~TransferInfoManager() = default;

    std::string getName() const;
    std::string getIPAddress() const;
    int getPort() const;
    std::string getFileName();

private:
    std::string client_name_;
    int port_number_;
    std::string ip_address_;
    std::vector<std::string> file_names_;
    std::string file_name_;

    // File related methods
    void moveToNextFile();
    std::tuple<std::string, int, std::string> readIPAndPortAndNameFromFile();
    std::tuple<std::string, int, std::string> readIPAndPortAndNameFromFile(
        const std::string &input_file_name);
    void setIPAndPortAndName(const std::string &ip, int port,
                             std::string &name);
};
