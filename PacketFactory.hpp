# pragma once
#include <optional>

namespace PacketUtils
{
std::unique_ptr<Packet> createPacket(std::optional<ClientID> clientID,
                                     std::optional<RequestOp> op,
                                     std::optional<ClientName> clientName,
                                     std::optional<PublicKey> publicKey,
                                     std::optional<FileName> fileName,
                                     std::optional<FileContent> fileContent)
{
    if (clientID && op && clientName)
    {
        return PacketWithClientName::createUnique(*clientID, *op, *clientName);
    }
    else if (clientID && clientName && publicKey)
    {
        return PacketWithPublicKey::createUnique(*clientID, *clientName,
                                                 *publicKey);
    }
    else if (clientID && op && fileName)
    {
        return PacketWithFileName::createUnique(*clientID, *op, *fileName);
    }
    else if (clientID && fileName && fileContent)
    {
        return PacketWithFile::createUnique(*clientID, *fileName, *fileContent);
    }
    else
    {
        throw std::invalid_argument("Invalid combination of arguments");
    }
}

std::unique_ptr<Packet> createPacket(const ClientID &clientID,
                                             const RequestOp &requestOp,
                                             const ClientName &clientName)
{
    return createPacket(clientID, requestOp, clientName, std::nullopt,
                        std::nullopt, std::nullopt);
}

std::unique_ptr<Packet> createPacket(const ClientID &clientID,
                                             const ClientName &clientName,
                                             const PublicKey &publicKey)
{
    return createPacket(clientID, std::nullopt, clientName, publicKey,
                        std::nullopt, std::nullopt);
}

std::unique_ptr<Packet> createPacket(const ClientID &clientID,
                                             const FileName &fileName,
                                             const FileContent &fileContent)
{
    return createPacket(clientID, std::nullopt, std::nullopt, std::nullopt,
                        fileName, fileContent);
}

std::unique_ptr<Packet> createPacket(const ClientID &clientID,
                                             const RequestOp &requestOp,
                                             const FileName &fileName)
{
    return createPacket(clientID, requestOp, std::nullopt, std::nullopt,
                        fileName, std::nullopt);
}
} // namespace PacketUtils
