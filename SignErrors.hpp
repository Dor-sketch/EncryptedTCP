#pragma once
namespace ErrorsModule
{
enum SignInStatus
{
    SUCCESS_SIGN_IN,
    FAILURE_NETWORK_ERROR,
    FAILURE_INVALID_UUID,
    FAILURE_INVALID_ME_INFO,
    FAILURE_GENERAL,
    FAILURE_INVALID_AES,
    ALREADY_REGISTERED,
    FAILURE_IN_AES_ENCRYPTION,
    FAILURE_INFO_CREATION,
    FAILURE_RSA_KEY_CREATION
};

class SignInError : public std::runtime_error
{
public:
    SignInError(const std::string& extraInfo, SignInStatus status);
    explicit SignInError(SignInStatus status);

    static const std::string getMessageForStatus(SignInStatus status);
    SignInStatus getStatus() const;

    const std::string& getExtraInfo() const { return extraInfo_; }

    static const std::string getFullMessage(SignInStatus status,
                                            const std::string& extraInfo);

    static const std::map<SignInStatus, std::string> statusMessages;

private:
    SignInStatus status_;
    std::string extraInfo_;
    static const std::string predefinedMessage;
};
}  // namespace ErrorsModule