# 📡 Encrypted Communication System

## Created By Dor Pasca | October 26, 2023

This project was conducted before the devastating and murderous attack that occurred on October 7th. Since that day, Israel has been in a state of war, facing unprecedented challenges on multiple fronts. These are indeed dark and trying times for the nation and its people.

While this is a small project, it is solemnly dedicated to all those who have lost their lives in these troubling times, as well as those who, due to the war or other adversities, have faced interruptions or obstacles in their own endeavors.

May this work serve as a modest tribute to their memory, their resilience, and to the peaceful times we all hope to see again soon.

---

![DALL·E 2023-11-09 10 23 22 - A dynamic and tech-oriented cover photo for a GitHub project  The image should illustrate an advanced communication ecosystem with visual elemen](https://github.com/Dor-sketch/EncryptedTCP/assets/138825033/bcf5f5c9-5440-4abc-9445-52d94ca2665b)


## 📑 Table of Contents

- [Created By Dor Pasca | October 26, 2023](#created-by-dor-pasca--october-26-2023)
- [📑 Table of Contents](#-table-of-contents)
- [1. 🌐 Overview](#1--overview)
  - [1.1. 🎯 Design Philosophy](#11--design-philosophy)
  - [1.2. 💡 Why It Stands Out](#12--why-it-stands-out)
  - [1.3. What I've Learned](#13-what-ive-learned)
    - [1.3.1. Technical Skills and Concepts](#131-technical-skills-and-concepts)
    - [1.3.2. Soft Skills](#132-soft-skills)
    - [1.3.3. Tools and Environments](#133-tools-and-environments)
- [2. Part 1: How to Run](#2-part-1-how-to-run)
- [3. 🐍 Start the Python Server](#3--start-the-python-server)
  - [3.1. Prerequisites](#31-prerequisites)
  - [3.2. 🛠 Dependencies](#32--dependencies)
  - [3.3. Runing the Server](#33-runing-the-server)
    - [3.3.1. Basic Server Start](#331-basic-server-start)
    - [3.3.2. Debug Mode](#332-debug-mode)
    - [3.3.3. Encryption Mode](#333-encryption-mode)
  - [3.4. 🔍 Using the Server Logs](#34--using-the-server-logs)
  - [3.5. 🐛 Using the `debug_log` Decorator](#35--using-the-debug_log-decorator)
    - [3.5.1. How it Works](#351-how-it-works)
- [4. ➕➕ Start the C++ Client](#4--start-the-c-client)
  - [4.1. Prerequisites](#41-prerequisites)
  - [4.2. 📚 Libraries](#42--libraries)
    - [4.2.1. Notes](#421-notes)
  - [4.3. 🛠 Compile and Run](#43--compile-and-run)
    - [4.3.1. 🏃‍♂️ Run](#431-️-run)
  - [4.4. 🚀 Available Options](#44--available-options)
  - [4.5. 🔒 Modes of Operation Explained](#45--modes-of-operation-explained)
    - [4.5.1. 🗝 Decryption Mode](#451--decryption-mode)
    - [4.5.2. 🌐 Normal Mode](#452--normal-mode)
  - [4.6. 📑 Logging](#46--logging)
- [5. Part 2: Client Modules Design in Depth](#5-part-2-client-modules-design-in-depth)
- [6. 📫 Client Module](#6--client-module)
  - [6.1. 🔍 Overview](#61--overview)
  - [6.2. 🌟 Key Features and Design Choices](#62--key-features-and-design-choices)
- [7. 🛗 ClientState Module](#7--clientstate-module)
  - [7.1. 🔍 Overview](#71--overview)
  - [7.2. General Workflow](#72-general-workflow)
  - [7.3. 🌟 Key Features and Design Choices](#73--key-features-and-design-choices)
  - [7.4. 🚦 How It Works: ClientState Module in Depth](#74--how-it-works-clientstate-module-in-depth)
- [8. Detailed TCP Flow in Client-Server Communication](#8-detailed-tcp-flow-in-client-server-communication)
  - [8.1. 📝 Real-world Example: Handling New Clients](#81--real-world-example-handling-new-clients)
    - [8.1.1. New Client Registration and UUID Allocation](#811-new-client-registration-and-uuid-allocation)
  - [8.2. AwaitingUUIDState: Setting Configurations Based on Received UUID](#82-awaitinguuidstate-setting-configurations-based-on-received-uuid)
    - [8.2.1. Public RSA Key Exchange and AES Key Encryption](#821-public-rsa-key-exchange-and-aes-key-encryption)
    - [8.2.2. AES Key Decryption and File Transfer](#822-aes-key-decryption-and-file-transfer)
    - [8.2.3. Handling Returning Clients](#823-handling-returning-clients)
- [9. 🛄 Packet Module](#9--packet-module)
  - [9.1. 📑 Summary](#91--summary)
  - [9.2. 🗝️ Key Features](#92-️-key-features)
  - [9.3. 💡 Design Choices](#93--design-choices)
  - [9.4. 🛠️ How It Works](#94-️-how-it-works)
  - [9.5. 🏭 Factory Design and Sub-Factories in Derived Classes](#95--factory-design-and-sub-factories-in-derived-classes)
- [10. 🛂 TransferInfoManager Module](#10--transferinfomanager-module)
  - [10.1. 🔍 Overview](#101--overview)
  - [10.2. 🌟 Features](#102--features)
  - [10.3. Usage](#103-usage)
- [11. ✈️ ConnectionManager](#11-️-connectionmanager)
  - [11.1. 🌟 Features](#111--features)
  - [11.2. 🛠️ How It Works](#112-️-how-it-works)
  - [11.3. Not Afraid of Bad Connections](#113-not-afraid-of-bad-connections)
  - [11.4. Cautions](#114-cautions)
  - [11.5. Note on Error Design](#115-note-on-error-design)
- [12. 🛃 Server Response Parser Module](#12--server-response-parser-module)
  - [12.1. 🔍 Overview](#121--overview)
  - [12.2. 🌟 Implementation](#122--implementation)
  - [12.3. 🎛 Usage](#123--usage)
  - [12.4. 📚 Additional Notes](#124--additional-notes)
- [13. 🔒 File Encryption and CRC Module](#13--file-encryption-and-crc-module)
  - [13.1. 🔍 Overview](#131--overview)
  - [13.2. 🌟 Features](#132--features)
  - [13.3. 🛠️ Usage](#133-️-usage)
  - [13.4. 💡 Best Practices](#134--best-practices)
- [14. 🌐 Server Modules Overview](#14--server-modules-overview)
- [15. 📋 Brief](#15--brief)
- [16. 📌 Key Features](#16--key-features)
- [17. 🌐 Server Class](#17--server-class)
  - [17.1. 🛠 Argument Parsing](#171--argument-parsing)
  - [17.2. 📊 Byte Formatting](#172--byte-formatting)
  - [17.3. 🧵 Threading](#173--threading)
- [18. 📩 Request Handling Module](#18--request-handling-module)
  - [18.1. 📋 Brief](#181--brief)
  - [18.2. 📚 Classes](#182--classes)
  - [18.3. 🧰 Utilities](#183--utilities)
- [19. 📚 Database Management](#19--database-management)
- [20. 📦 ParseRequestManager Module](#20--parserequestmanager-module)
  - [20.1. 📋 Brief](#201--brief)
  - [20.2. 🛠 Components](#202--components)

## 1. 🌐 Overview

The Client Program is an **advanced communication ecosystem** developed to prioritize **security, performance, and modularity**. It's engineered with **C++ 17**, leveraging cutting-edge features such as **structured bindings**, `std::filesystem`, and `std::map` to create a system that is **scalable** and **maintainable**.

---

### 1.1. 🎯 Design Philosophy

- **Security First**: Built-in mechanisms for encrypted communication and data integrity checks.

- **High Performance**: Optimized to handle large-scale data transfers with minimal latency.

- **Modular Design**: Following SOLID principles and design patterns like the State Pattern for high cohesion and low coupling.

- **Modern C++ Practices**: Utilization of C++ 17 features ensures that the codebase is contemporary and takes advantage of the latest language improvements.

### 1.2. 💡 Why It Stands Out

- **Encapsulation**: Distinct modules with friend classes and private constructors enable a high level of encapsulation.

- **State Management**: Employing the State Pattern, inspired by "Effective C++, Item 31: Making functions virtual with respect to more than one object", the program segregates the responsibilities of state transition and business logic.

- **Ease of Use**: A straightforward API abstracts the internal complexities, offering the end-user a seamless experience.

- **Forward Compatibility**: Designed with extensibility in mind, making it easier to integrate future C++ features and third-party libraries.

### 1.3. What I've Learned

#### 1.3.1. Technical Skills and Concepts

- **Advanced C++ Features**: Utilized modern C++ constructs for robust and clean code.

- **Error Handling in C++**: Mastered exception handling to build fault-tolerant applications.

- **Concurrency in C++**: Deepened understanding of multithreading and asynchronous programming.

- **JSON Parsing**: Acquired skills in parsing and debugging JSON files for security vulnerabilities.

- **Timeout Management**: Implemented timeout features in network operations to enhance security.

- **Threat Assessment**: Conducted software vulnerability assessments following best practices from "The Art of Software Security Assessment".

- **Encryption and Security Protocols**: Implemented RSA and AES encryption in secure client-server communications.

- **Secure Coding Practices**: Adopted coding practices that prioritize security, including input validation, sanitization, and secure session management.

- **Version Control**: Utilized git and GitHub for code management, including secure branching strategies.

- **Database Management**: Practiced secure SQL query formulation to prevent SQL injection attacks.

- **Advanced Logging**: Utilized comprehensive logging to monitor and alert on security events.

#### 1.3.2. Soft Skills

- **Critical Thinking**: Refined problem-solving and analytical skills, particularly in identifying security risks.

- **Risk Assessment**: Developed the ability to assess and prioritize security risks in a software project.

#### 1.3.3. Tools and Environments

- **VSCode**: Mastered using VSCode as the primary IDE, including its security extensions.

- **Makefile**: Crafted Makefiles that include security checks in the build process.

- **Security Auditing Tools**: Gained experience using tools like `valgrind` for security auditing.

- **Formatting Tools**: Utilized `clang-format` for code formatting and `cppcheck` for static analysis, `black` for Python formatting and `pylint` for static analysis.

\newpage

## 2. Part 1: How to Run

## 3. 🐍 Start the Python Server

### 3.1. Prerequisites

**Python Version**: Python 3 or higher

**Libraries**:

### 3.2. 🛠 Dependencies

- `sys`, `os`, `socket`, `threading`, `subprocess`: For all your system-level operational needs.
- `argparse`: Making the command-line your playground.
- `logging`: For maintaining those essential logs.
- `re`: To play around with regular expressions.
- `binascii`, `zlib`, `struct`: Your toolkit for binary and data manipulation.
- `datetime`: Because timing is everything.
- `sqlite3`: For all your database operations.
- `termcolor`: For pretty and colorful logs.
- `colorlog`: Because why stop at just colorless logs?
- `Cryptodome`: For secure cryptographic operations.
- `Enum`: For robust enumeration types.
- 🧩 Custom modules - included inside

📝 Make sure to install Python dependencies which are not part of the standard library.

---

### 3.3. Runing the Server

This script is designed to serve multiple functionalities like starting a server, running in debug mode, and encrypting files. Below are the commands to utilize these functionalities.

#### 3.3.1. Basic Server Start

To start the server with default settings, execute the following command:

```bash
python3 server.py
```

By default, the server runs with a logging level set to INFO. It will automatically disconnect and close after detecting inactivity for a specified time period.

#### 3.3.2. Debug Mode

To run the server in debug mode, which sets the logging level to DEBUG, use the following command:

  ```bash
    python3 server.py --debug
  ```

**Note**: In debug mode, the server will return incorrect CRC values. Additionally, the automatic disconnection and closing functionalities are disabled when the server is unused.

#### 3.3.3. Encryption Mode

To run the server in encryption mode, use the following command:

```bash
python3 server.py --encrypt
```

In this mode, the server not only runs but also triggers a C++ program that encrypts files. The logs for this operation will be stored with a CRITICAL logging level. This mode compiles the client program, builds transfer info of the client source files, and sends it to the server. It also stores the files in an encrypted format in the server directory (instead of the usual plaintext format). The output log in this mode will display the AES key, which can later be used to decrypt the files.

**Please Note**: While this mode allows you to encrypt files for a measure of security, it's generally not as secure as using asymmetric cryptography. It is advisable not to use this for highly sensitive information unless combined with additional security measures.

---

### 3.4. 🔍 Using the Server Logs

**Logging Levels**: Various logging levels are supported for debugging and monitoring:

- DEBUG: Detailed information, useful for debugging.
- INFO: General confirmation that things are working as expected.
- WARNING: Indications of something unexpected.
- ERROR: More severe issues, yet the software is still functional.
- CRITICAL: Critical issues that could make the program inoperable.

Each module has its own logger, in order to provide a more granular level of control. For example, the `server.py` script has a logger named `server_logger`, while the `database.py` script has a logger named `db_logger`. This not only allows you to set different logging levels for different modules, but also provide reach information about the source of the log - including a link to the line number and file name.

---

### 3.5. 🐛 Using the `debug_log` Decorator

The reciever modulu also equiped with its own logging mehanism, leveraging python decos. The `debug_log` decorator provides enhanced logging functionality when you're running your code in debug mode. It is built using Python's `functools.wraps` to preserve the function's original information (like its name and docstring).

#### 3.5.1. How it Works

When `DEBUG_MODE` is set to `True`, the `debug_log` decorator performs the following actions:

1. **Before Function Execution**: Logs the name of the function being called along with its arguments and keyword arguments. If any argument is a byte string, it gets displayed in hexadecimal format.

2. **After Function Execution**: Logs the returned value from the function. If the return value is a byte string, it gets displayed in hexadecimal format.

      ```python
      DEBUG_MODE = False
      def debug_log(func):
          @functools.wraps(func)
          def wrapper(*args, **kwargs):
              if DEBUG_MODE:
                  # Log function name and argument
              result = func(*args, **kwargs
              if DEBUG_MODE:
                  # Log function return value
              return result
          return wrapper
      ```

- **Using the decorator**: To use this decorator, simply add it above the function definition like so:

    ```python
      @debug_log
      def your_function(arg1, arg2):
          # Your code here
    ```

To turn on and of the decorations, you can simple change the `DEBUG_MODE` variable in the module.

---

## 4. ➕➕ Start the C++ Client

### 4.1. Prerequisites

**Compiler**: C++17 compliant compiler such as `g++`

**Features**: Filesystem (C++17 and above)

### 4.2. 📚 Libraries

- **Standard Template Library (STL)**: The classic C++ library that needs no introduction.
- **Boost Libraries**: Pumping up your C++ game.
  - `Boost.Asio`: For smooth asynchronous programming.
  - `Boost.Archive`: Base64 encoding and decoding made easy.
  - `Boost.UUID`: For when you need unique identifiers.
- **Crypto++**: Your go-to for cryptographic operations.
  - File and Filter components for that extra layer of security.
- **spdlog**: Logging but faster and better.
- **fmt**: Because string formatting shouldn't be a hassle.

**Custom Headers**:

- `Client.hpp`
- `ClientState.hpp`
- `ConnectionManager.hpp`
- `ErrorsModule`
- `FileEncryptor.hpp`
- `Keys.hpp`
- `LoggerModule.hpp`
- `NetworkErrors.hpp`
- `Packet.hpp`
- `PacketFactory.hpp`
- `PacketPrint.hpp`
- `Response.hpp`
- `SignErrors.hpp`
- `TransferInfoManager.hpp`

#### 4.2.1. Notes

- 📝 Some of these libraries like Crypto++ and Boost are not header-only and will require installation.
- 📝 The code makes use of the C++17 Filesystem Library; ensure your compiler supports this.

---

### 4.3. 🛠 Compile and Run

👉 Below are the commands and explanations for compiling and running your client application.

1. **Default Compilation**: To compile the client application with default settings, navigate to the project directory and run this command. Note: This will generate an executable named 'client_app'. The default compilation mode is 'release'.

      ```bash
      make
      ```

2. **Debug Tests**: To compile with debug tests, run the following command. Warning: This is not recommended and is only for testing purposes. Changing log level is also available in release mode throgh args (see below).

    ```bash
    make debug
    ```

3. **Decryption Mode**: To compile in decryption mode, use this command. This activates a script to decrypt files in the ../server/uploaded_files/ directory.

      ```bash
      make MODE=decrypt.
      ```

4. **Set Log Level:** To set the log level, run this command. This will affect the verbosity of logs during runtime.

    ```bash
    make LOG_LEVEL=CRITICAL
    ```

5. **make info:** To get a transfer.info file, in addition to the executable, run this command. Default files include the program source files.

    ```bash
    make info
    ```

6. **make clean:** To clean the project directory, run this command. This will remove all executables and configuration files.

    ``` bash
    make clean
    ```

---

#### 4.3.1. 🏃‍♂️ Run

👉 Below are the commands and explanations for running your client application with various options.

```bash
# 1. Run with default options:
./client_app

# 2. Run in decryption mode:
# Note: Make sure to run the server in encryption mode first.
./client_app --decrypt

# 3. Set logging levels:
./client_app --log=<LEVEL>
# <LEVEL> can be DEBUG, INFO, WARNING, ERROR, or CRITICAL.
```

### 4.4. 🚀 Available Options

- `-h, --help`: Show the help message and exit.
- `--decrypt`: Run the application in decryption mode.
- `--log=LEVEL`: Set the logging level (`DEBUG`, `CRITICAL`).

### 4.5. 🔒 Modes of Operation Explained

#### 4.5.1. 🗝 Decryption Mode

- Running the client application with the `--decrypt` option will put it in decryption mode.
- You'll be prompted to enter the decryption key, which should be a 32-character hexadecimal string.
- The application will then decrypt files in the `../server/uploaded_files/` directory using the provided key.

#### 4.5.2. 🌐 Normal Mode

- Without the `--decrypt` flag, the application will operate in normal mode and handle requests to the server.

### 4.6. 📑 Logging

- Different logging levels like `DEBUG` and `CRITICAL` are supported.
- Use the `--log` option to set the log level.

## 5. Part 2: Client Modules Design in Depth

## 6. 📫 Client Module

### 6.1. 🔍 Overview

The `Client` module is the nexus of the client-side communication system. Designed using the State Pattern, it provides a seamless experience for users by internally managing various client states. Users interact with the `Client` module via a single method, keeping the state transitions completely transparent.

### 6.2. 🌟 Key Features and Design Choices

- **User-Friendly API**: A single method `handleRequest` is exposed for user interaction. Upon invocation, this method delegates the request to the appropriate state object, abstracting away the complexities of state transitions.

    ```cpp
    void Client::handleRequest() { state_->handleRequest(this); }
    ```

    In practical terms, a user would only need to do the following:

    ```cpp
        // ctor automatically sets the state to INITIAL
        Client client;
        // delegates the request to the INITIAL state
        client.handleRequest();
    ```

    As seen above, the user doesn't need to know anything about the state management. They interact solely with the `Client` class.

- **Encapsulation and State Management**: Internal state logic is abstracted away from the end-user. State transitions are managed within the `Client` module, and individual state classes are declared as 'friends', thus maintaining a high level of encapsulation.

---

## 7. 🛗 ClientState Module

### 7.1. 🔍 Overview

The `ClientState` module acts as the skeleton for the different states a `Client` can assume. It contains the logic required for state transitions and dictates the client behavior at any given state.

### 7.2. General Workflow

1. **New Client Registration:** A new client initiates the communication by sending a registration request.
2. **UUID Allocation:** The server responds by allocating a Unique User ID (UUID) for the client.
3. **Public RSA Key Exchange:** The client sends its public RSA key to the server.
4. **AES Key Encryption:** The server generates an AES key, encrypts it with the client's public RSA key, and sends it back.
5. **AES Key Decryption:** The client decrypts the AES key using its private RSA key.
6. **File Transfer:** The client sends files encrypted with the decrypted AES key to the server.
7. **Returning Clients:** If a returning client wants to sign in, the server sends them the previous AES key from the database.

### 7.3. 🌟 Key Features and Design Choices

- **State Transition Responsibility**: The module assumes the responsibility of transitioning between states. This design choice ensures a separation of concerns, keeping the Client module unburdened from internal state management complexities.

- **Friendship for Encapsulation**: Utilizing the 'friend' keyword in C++, state classes are declared as friends of the Client class. This enables them to access private and protected members of the Client class, allowing for a high level of encapsulation while maintaining a clean architecture.

- **State Constructors**: Constructors for the state classes are intentionally kept private to safeguard against unauthorized instantiation. This design choice ensures that only the Client class, which is a friend of the state classes, can instantiate them.

---

### 7.4. 🚦 How It Works: ClientState Module in Depth

- The `ClientState::changeState` function serves as the fulcrum for state transitions, orchestrating the shifts based on specific enum values.

    ```cpp
    void ClientState::changeState(Client *client,
      const ClientStateEnum &state)
    {
          switch (state)
          {
            case ClientStateEnum::INITIAL:
                client->setState(std::make_unique<InitialState>());
                break;
            // ...
            case ClientStateEnum::CRC_VERIFYING:
                client->setState(
                std::make_unique<CRCVerificationState>());
                break;
        }
    }
    ```

Each state object knows which state to transition to next and invokes `changeState` accordingly. This ensures that the state transition logic is completely abstracted away from the `client` - in addition to the user.

## 8. Detailed TCP Flow in Client-Server Communication

### 8.1. 📝 Real-world Example: Handling New Clients

#### 8.1.1. New Client Registration and UUID Allocation

When a new client instance is constructed, it enters the `InitialState`. In this state, the client checks for predefined configuration files. If none are found, the client sends a request to the server for sign-up. After successful registration, the server sends back a UUID, and the client transitions to the `AwaitingUUIDState`. If the client is already registered, the system transitions to the `AwaitingOldAESState`.

```cpp
void InitialState::handleRequest(Client *client)
{
    try
    {
        client->signUp();
        changeState(client, ClientStateEnum::AWAITING_UUID);
    }
    // Custom-defined exception
    catch (const AlreadyRegisteredException &e)
    {
        // Logging mechanism
        changeState(client, ClientStateEnum::AWAITING_OLD_AES);
    }
    // Trigger the next state
    client->handleRequest();
}
```

---

### 8.2. AwaitingUUIDState: Setting Configurations Based on Received UUID

When the client transitions to the `AwaitingUUIDState`, it performs initial configurations using a UUID that it receives from the server. In this state, the client executes the `handleRequest` method to initiate client registration.

```cpp
// client's request for initial configuration is handled.
void AwaitingUUIDState::handleRequest(Client *client)
{
    // set its initial configurations based on the received UUID.
    client->registerClient();

    // Transition to the next state for new AES key.
    changeState(client, ClientStateEnum::AWAITING_NEW_AES);
}
```

The registerClient method encapsulates the logic for client registration and initial configuration.

```cpp
void Client::registerClient()
{
    auto response = connection_manager_ptr_->connectSendReceiveDisconnect(
        *createPacket(ClientID(getClientID()),
        RequestOp::OP_SIGN_UP,
        ClientName(getClientName()))
        );

    if (response->getStatusCode() ==
     ResponseStatus::STATUS_SIGN_UP_SUCCESS)
    {
        createMeInfo(dynamic_cast<ResponseWithUUID &>(*response));
        loadClientInfo();
    }
    else
    {
        ERROR_LOG("Sign up failed: {}", response->getStatusCodeString());
    }
}
```

---

#### 8.2.1. Public RSA Key Exchange and AES Key Encryption

Once the UUID is received and the RSA key pair is generated, the client transitions to `AwaitingNewAESState`. Here, it sends its public RSA key to the server. The server then generates an AES key, encrypts it using the client's RSA key, and sends it back. Than it is decrypted using the client's private RSA key, and stored in the client's member variable.

```cpp
void AwaitingNewAESState::handleRequest(Client *client)
{
    try
    {
        client->getNewAESKey();
        changeState(client, ClientStateEnum::CRC_VERIFYING);
    }
    // ...
}
```

#### 8.2.2. AES Key Decryption and File Transfer

In the `CRCVerifyingState`, the client sends files to the server, encrypted with this AES key.

```cpp
void CRCVerifyingState::handleRequest(Client *client)
{
    // Perform file transfer operations using the decrypted AES key
}
```

#### 8.2.3. Handling Returning Clients

For returning clients, the server retrieves the previously stored AES key from the database and sends it back to the client. The client then uses this key for file encryption.

```cpp
void AwaitingOldAESState::handleRequest(Client *client)
{
    // ...
}
```

---

- **🗃️ A Note on Encapsulation**: Although each state has access to the `changeState` method, it does introduce a slight chink in the armor of strict encapsulation. For larger projects, one could consider overriding the `changeState` method within each derived state class to limit their capabilities. In the current project context, this is considered an acceptable trade-off given the limited number of states and straightforward state transition logic.

---

## 9. 🛄 Packet Module

### 9.1. 📑 Summary

The `Packet` Module is a robust, type-safe, and extensible system designed for creating and managing a variety of packet types in client-server communication systems. Built on modern C++17 features, it aims to offer a scalable and maintainable way of dealing with packets.

---

### 9.2. 🗝️ Key Features

- **Type-Safety**: Wrapped classes like `ClientID`, `ClientName`, `PublicKey`, etc., ensure robust type-checking.
- **Factory Design Pattern**: Flexible packet creation without exposing constructor details.
- **Encapsulation**: Advanced OOP principles are used to hide the complexities and maintain a clean API.
- **Extensibility**: The design allows easy addition of new packet types or fields.

---

### 9.3. 💡 Design Choices

- **Factory Function**: The `Packet::createPacket()` static method serves as a main factory function. It encapsulates the object creation logic, thereby ensuring that only valid packet objects can be created. It also allows the addition of new packet types without modifying existing code.
- **Use of `std::optional`**: This provides flexibility in the arguments passed to the factory function, making it easier to extend functionality later.
- **Wrapped Field Classes**: By wrapping fields like client name and public key into their own strongly-typed classes (`ClientName`, `PublicKey`), we make the code more readable and less error-prone.
- **Auto Keyword**: Utilizing the `auto` keyword for type inference provides cleaner code and makes future changes less error-prone.

---

### 9.4. 🛠️ How It Works

1. **Creating a Packet**: Use the `Packet::createPacket()` factory function. Based on the parameters passed (all as `std::optional`), it returns a `std::unique_ptr` to the appropriate packet object.

    ```cpp
    auto packet =
      Packet::createPacket(clientID, requestOp, clientName, publicKey);
    ```

2. **Accessing Fields**: You can access encapsulated fields via getter methods provided in each class. These fields are type-safe due to the use of wrapper classes.

    ```cpp
    auto client_name = packet->getClientName();
    ```

3. **Packing and Unpacking**: The base `Packet` class and all its derivatives provide a `pack()` method that serializes the packet into a byte vector, which can then be sent over the network.

    ```cpp
    auto packedData = packet->pack();
    ```

4. **Logging and Debugging**: Functions like `prepareLog()` and `print()` offer easy logging and debugging capabilities.

---

### 9.5. 🏭 Factory Design and Sub-Factories in Derived Classes

The system is architected with two layers of factory methods to ensure both generalization and specialization in packet creation:

1. **Main Factory Method (`Packet::createPacket`)**: This static method serves as the primary entry point for packet creation. It examines the parameters passed and delegates the packet creation to the appropriate derived class's specialized factory method.

    ```cpp
    std::unique_ptr<Packet> Packet::createPacket(
        std::optional<ClientID> clientID,
        std::optional<RequestOp> op,
        std::optional<ClientName> clientName,
        // ... other optional parameters
    )

    {
        if (clientID && op && clientName)
        {
            return PacketWithClientName::createUnique(
            *clientID, *op, *clientName);
        }
        // ...
    }
    ```

2. **Derived Class Factory Methods (e.g., `PacketWithClientName::createUnique`)**: Each derived class has its own static `createUnique` method that returns a `std::unique_ptr` to an object of its type. This method is called by the main `Packet::createPacket` factory method.

    ```cpp
      static std::unique_ptr<PacketWithClientName>
        PacketWithClientName::createUnique(
        ClientID &clientID,
        RequestOp op,
        ClientName &clientName);
    ```

This dual-layer approach ensures that:

- Users interact only with the main `createPacket` factory method for all packet types.
- The correct derived class is instantiated based on the parameters passed.
- The architecture remains open for extension but closed for modification, aligning well with the Open/Closed Principle of SOLID design guidelines.

---

- 📝 **A Notes on Design Decisions - `createPacket` Function Overloading vs Templating**:

  The `createPacket` function currently uses explicit function overloading rather than templating. This was a conscious decision for several reasons:

  1. **Limited Argument Combinations**: The function handles specific combinations of arguments that aren't merely dependent on the type of arguments, but also on their logical grouping.

  2. **Readability**: Using function overloading makes the implementation easier to read and understand, especially for those unfamiliar with template metaprogramming in C++.

  3. **Maintainability**: While function overloading makes the implementation somewhat verbose, it's straightforward to add new combinations of arguments or modify existing ones without affecting other parts of the code.

  Although using templating might offer a more elegant and generalized solution, the benefits of explicit function overloading in this case—mainly readability and maintainability—outweigh the compactness that templates could provide.

---

## 10. 🛂 TransferInfoManager Module

### 10.1. 🔍 Overview

The **TransferInfoManager** module emerges as a pivotal interface tailored for clients keen on accruing insights about IP addresses, port numbers, client names, and affiliated file names straight from a configuration file. Marked by its methodical approach towards the management of transfer-related data, this module unfurls several core features:

### 10.2. 🌟 Features

1. **Robustness and Error Handling**:
   With resilience at its core, the module exhibits impeccable error-handling capacities. It assiduously validates files, ensuring they exist, are regular, and aren't empty. Any deviations are logged promptly. In critical situations, exceptions are raised, constantly keeping the client in the loop about potential hiccups.

2. **Flexibility with File Reading**:
   This module can adeptly read multiple file names from its configuration, thus allowing an organized processing of a file series. This paves the way for scalability when orchestrating multiple file transfers in a sequenced manner.

3. **Efficient IP and Port Parsing**:
   Harnessing the prowess of C++'s Standard Library, the extraction of IP and port details is both effective and steadfast. Beyond this, the module ensures the integrity of the IP format and the port range.

4. **Maintainable and Clean Code**:
   Eschewing the pitfalls of magic numbers or strings, the module leans on `constexpr` for enhanced clarity and maintainability. Its layout is intuitive, facilitating effortless integrations and tweaks by developers.

5. **Delegated Constructors**:
   Anchored in the principle of DRY (Don't Repeat Yourself), the module embraces delegated constructors. This fosters consistency across constructors and champions the reuse of code.

6. **Compatibility with Modern C++ Standards**:
   By tapping into modern C++ paradigms like structured bindings and the `<filesystem>` header, the module aligns seamlessly with contemporary C++ best practices.

---

### 10.3. Usage

Engaging with the **TransferInfoManager** is straightforward. Initialize the object, choosing to provide the name of your configuration file or not. The pre-set configuration file is christened `transfer.info`.

TransferInfoManager manager;  // Resorts to the default 'transfer.info'
TransferInfoManager customManager("customFile.info");

Subsequently, harness member functions to extract the information you require:

---

## 11. ✈️ ConnectionManager

`ConnectionManager` streamlines complex network tasks, making data transmission straightforward. It works closely with the `Client` module, which delegates all networking to it. The class constructor initializes with a `TransferInfoManager` for validating IP addresses, port numbers, and file names. The primary API, `connectSendReceiveDisconnect`, encapsulates the entire networking process.

```cpp
auto response = connectionManager.connectSendReceiveDisconnect(packet);
// Alternatively, in a less friendly RIIA style:
auto response = connectSendReceiveDisconnect(createPacket(...));
```

---

### 11.1. 🌟 Features

- **Lambda Functions**: Provides flexibility and extensibility in how operations are executed.
- **Custom Error Handling**: Allows for specific error types to be individually managed, enhancing robustness.
- **Advanced Retrying**: Implements a configurable and robust retry mechanism for fault tolerance.
- **Encapsulation**: Streamlines client-side network operations by providing a clean and easy-to-use API.
- **Boost ASIO**: Takes advantage of asynchronous I/O operations for optimized performance.
- **Connection Management**: Ensures the reliability of data transmission by effectively managing the state of server connections.

### 11.2. 🛠️ How It Works

The `handleOperationWithRetry` method is designed to accept a function object as an argument. This function will be executed until it succeeds or until a maximum retry limit is reached, providing a versatile and robust retry mechanism.

```cpp
void ConnectionManager::handleOperationWithRetry(
    const std::function<void(std::unique_ptr<Response> &)> &operation,
    std::unique_ptr<Response> &outResponse)
{
    // Implementation here
}
```

The primary API, `connectSendReceiveDisconnect`, leverages `handleOperationWithRetry` by passing a lambda function that encompasses the entire network operation sequence—connection, data transmission, and disconnection.

```cpp
std::unique_ptr<Response> ConnectionManager::connectSendReceiveDisconnect(
    const PacketUtils::Packet &packet)
{
    // Initialize a unique_ptr for the response
    std::unique_ptr<Response> response;

    // Call handleOperationWithRetry
    handleOperationWithRetry(
        [this, &packet](std::unique_ptr<Response> &outResponse)
        {
            // Implementation here
        },
        response
    );

    // Additional error handling and logic
    // ...

    return response;
}
```

### 11.3. Not Afraid of Bad Connections

Beyond the retry mechanism, `ConnectionManager` has a robust exception handling feature. The `handleNetworkException` function is declared as a friend of `ConnectionManager` due to several reasons:

1. **Tight Coupling**: It requires access to the class's private and protected members to handle network exceptions effectively, justifying the need for elevated access permissions.
2. **Ease of Refactoring**: Having internal access ensures that refactoring or extending ConnectionManager won't negatively impact this function, making the codebase more maintainable.
3. **Explicit Relationship**: Declaring it as a friend function clearly signals its special relationship with ConnectionManager, improving code readability and providing better context.

### 11.4. Cautions

- **Breaks Encapsulation**: This 'friend' status partially compromises the encapsulation principle, meaning future modifications to `ConnectionManager` should account for potential impacts on `handleNetworkException`.
- **Maintainability Risk**: Overuse of friend functions can make the codebase tightly coupled and difficult to maintain. Therefore, this feature should be used judiciously.
- **Implementation Note**: The program is currently not designed to handle exceptions fully but aims to demonstrate a conceptual understanding. Custom error classes are defined under `NetworkErrors.cpp` in the `ErrorsModule` namespace.

---

### 11.5. Note on Error Design

The `ErrorsModule` namespace is implemented across multiple files but shares a single namespace. This approach, inspired by the C++ `std` namespace, keeps the code clean and organized.

---

## 12. 🛃 Server Response Parser Module

### 12.1. 🔍 Overview

🎯 A comprehensive C++ framework engineered for interpreting server responses, which are provided as byte buffers. The architecture is modular, capable of parsing various server messages, and is designed to be easily extensible for future message formats. This aligns well with `Item 18: Make interfaces easy to use correctly and hard to use incorrectly` from "Effective C++".

---

### 12.2. 🌟 Implementation

- **🌐 Base Response Class**
  - 🎁 Handles basic properties and provides utilities for printing.

- **🔐 UUID, AES Key, & CRC Response Classes**
  - 🌱 Derived classes that specialize in parsing specific server responses.

- **🏭 ResponseFactory Function**
  - 🛠 Implements the Factory Design Pattern.
  - 👇 Responsible for creating the appropriate response object.

    ```cpp
    std::unique_ptr<Response> ResponseFactory(
        const std::vector<unsigned char> &buffer);
    ```

  - 🔍 Internally uses a switch statement based on the status bytes to determine the type of the response.
  - 📐 Modular design allows for easy expansion, adhering to the Open/Closed Principle of the SOLID design guidelines.

---

### 12.3. 🎛 Usage

1. **🏭 Factory Function**
    - 📋 Create a response object using the `ResponseFactory` function.

    ```cpp
    auto response = ResponseFactory(buffer);
    ```

    - 💡 The factory takes care of the underlying logic, so the user doesn't need to worry about it.

2. **📄 Accessing Data**
    - 🛠 If the object is created successfully (memory management handled by smart pointers), you can easily access the data through getter methods.

    ```cpp
    if (response)
    {
        std::cout << "Response: " << response->getOpCode() << std::endl;
        // ...
    }
    ```

    - 📊 Includes an advanced logging mechanism with ANSI characters for clear, structured logs.

### 12.4. 📚 Additional Notes

- 🎉 Inspired by C++ Core Guidelines outlined by Scott Meyers.
- 🎨 Makes use of ANSI characters for logging, stored in an enum class for user-friendliness.

---

## 13. 🔒 File Encryption and CRC Module

### 13.1. 🔍 Overview

A C++ module aimed at handling file encryption and CRC calculations. This module is composed of a `FileEncryptor` class and a `CRCUtils` namespace, which provides a variety of utility functions. It leverages the Crypto++ library for AES encryption and CRC32 calculations.

### 13.2. 🌟 Features

- **CRCUtils Namespace**: Houses utility functions for CRC calculations and file encryption/decryption.
  - `calculateCRC`: Calculates the CRC32 value for a given string.
  - `encryptToString`: Encrypts a plaintext string using a given key and initialization vector.
  - `encryptFileToString`: Encrypts the content of a file and returns it as a string.
  - `decryptToString`: Decrypts an encrypted string using a given key and initialization vector.

- **FileEncryptor Class**: A class designed to encapsulate file encryption and decryption logic.
  - `decryptToFile`: Decrypts an encrypted string and writes the result to a file.
  - `encryptAndComputeCRC`: Encrypts the content of a file and computes its CRC32 value.

---

### 13.3. 🛠️ Usage

To use this module, include the headers and link against the Crypto++ library. Initialize a `FileEncryptor` object with a key and input file name, then use the utility functions to perform encryption and CRC calculations.

```cpp
FileEncryptor encryptor(keyHex, inputFileName);
auto [encryptedData, crcValue] = encryptor.encryptAndComputeCRC();
```

### 13.4. 💡 Best Practices

- Avoid setting the IV (Initialization Vector) to zeros for real-world applications. This is done here for simplicity but is not recommended.
- Logging has been used for debugging purposes and should be minimized or made optional in a production environment.
- Do not use DEBUG_LOG or ERROR_LOG in production; these are placeholders for your logging implementation.

---

## 14. 🌐 Server Modules Overview

## 15. 📋 Brief

Server employs context managers for resource management and runs in its own thread. Modular design spans multiple Python classes to handle tasks like database management and request parsing.

## 16. 📌 Key Features

- Dynamic ports with fallbacks
- Colored logging
- Data parsing for client requests
- Modular architecture
- File encryption in 'encrypt' mode
- Timeout/session controls
- Exception handling

## 17. 🌐 Server Class

Handles connection lifecycle and data traffic.

### 17.1. 🛠 Argument Parsing

Uses `argparse` for CLI argument parsing, particularly for debug and encryption modes.

### 17.2. 📊 Byte Formatting

`prettyBytes` translates byte data into readable format.

### 17.3. 🧵 Threading

Runs in its own thread, with an additional thread for C++ encryption if needed.

## 18. 📩 Request Handling Module

### 18.1. 📋 Brief

Python-based framework for client-server request management. Classes inherit from `BaseRequestHandler` for specialized functionality.

### 18.2. 📚 Classes

- `BaseRequestHandler`: Initializes client ID and payload, defines virtual `handle_request`.
- `RegisterHandler`: Manages client registration.
- `PublicKeyHandler`: Manages public keys received from clients, and returns AES keys.
- `FileDecryptHandler`: Decrypts files and store them in the server specified directory.
- `ReconnectHandler`: Handles reconnection requests - feches AES key from database and returns it to client.
- `AcknowledgmentHandler`: Handles acknowledgments for different requests such as CRC verification, file decryption, etc.

### 18.3. 🧰 Utilities

- `get_handler_for_code`: Returns best handler class for given code. It is used as the entry point for request handling, and it works by mapping each status code to a handler class.

## 19. 📚 Database Management

`DatabaseManager` class acts as context manager for SQLite3 database interactions. Logging via Python's native logging framework.

## 20. 📦 ParseRequestManager Module

### 20.1. 📋 Brief

Responsible for parsing client requests. Main class is `ParseRequestManager`.

### 20.2. 🛠 Components

- Header and Payload Extraction: Uses Python's `struct` library.
- Logging and Debugging: Utilizes Python's `logging` library.
