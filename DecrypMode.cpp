#include "dirent.h"
#include "FileEncryptor.hpp"
#include "LoggerModule.hpp"
#include <fstream>

namespace
{
void decryptFile(const std::string &key, const std::string &filePath)
{
    std::string fileContent;

    // Read the encrypted file into a string
    std::ifstream inputFile(filePath);
    if (inputFile)
    {
        std::ostringstream ss;
        ss << inputFile.rdbuf();
        fileContent = ss.str();
    }
    else
    {
        std::cerr << "Failed to open " << filePath << " ";
        perror("Error");  // Print more detailed error information
    }
    inputFile.close();  // Close the file to release any locks on it
    try
    {
        FileEncryptor fileEncryptor(key, filePath);
        fileEncryptor.decryptToFile(fileContent, filePath);
    }
    catch (const std::exception &e)
    {
        ERROR_LOG("Failed to decrypt file: {}", e.what());
    }
    catch (...)
    {
        ERROR_LOG("Failed to decrypt file: Unknown exception.", "");
    }
}

bool isValidKey(const std::string &key)
{
    // Check if the key is 32 characters long
    if (key.length() != 32)
    {
        return false;
    }
    // Check if the key is a valid hexadecimal string
    for (char c : key)
    {
        if (!std::isxdigit(c))
        {
            return false;
        }
    }
    return true;
}

const std::string getKey()
{
    std::string key;
    while (true)
    {
        std::cout << "Enter the decryption key: ";
        std::cin >> key;
        if (isValidKey(key))
        {  // You need to define this function to check the key's validity
            break;  // Exit the loop if the key is valid
        }
        std::cout << "Invalid key. Please try again.\n";
    }
    return key;
}

int decrypt()
{
    auto key = getKey();

    // Open directory
    DIR *dir;
    struct dirent *ent;
    std::string dirPath = "../server/uploaded_files/";

    if ((dir = opendir(dirPath.c_str())) != nullptr)
    {
        // Loop through all files in the directory
        while ((ent = readdir(dir)) != nullptr)
        {
            std::string fileName = ent->d_name;
            if (fileName == "." || fileName == "..") continue;  // Skip . and ..

            std::string filePath = dirPath + fileName;
            LOG("Decrypting file: {}", filePath);

            // Call the new decryptFile function
            decryptFile(key, filePath);
        }
        closedir(dir);
    }
    else
    {
        // Could not open directory
        perror("Could not open directory");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
}  // namespace