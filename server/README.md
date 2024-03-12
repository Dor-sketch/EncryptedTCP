# 🐍 Python Server

The Python server is a multi-threaded server that can handle multiple clients at once. It is designed to be a secure and robust server that can handle various client requests. The server is designed to be modular, with different classes handling different types of requests. It also has a database module to handle all database operations.

---
<!-- @import "[TOC]" {cmd="toc" depthFrom=2 depthTo=3 orderedList=false} -->

<!-- code_chunk_output -->

- [🚀 Start the Python Server](#-start-the-python-server)
  - [🛠 Prerequisites](#-prerequisites)
  - [🏃‍♂️ Runing the Server](#️-runing-the-server)
- [🌐 Server Modules Overview](#-server-modules-overview)
  - [🌐 Server Class](#-server-class)
  - [📩 Request Handling Module](#-request-handling-module)
  - [📚 Database Module](#-database-module)
  - [📦 ParseRequestManager Module](#-parserequestmanager-module)

<!-- /code_chunk_output -->
---

## 🚀 Start the Python Server

### 🛠 Prerequisites

- **Python Version**: Python 3 or higher

- **Dependencies**:

  - **Standard Library**:
    - `sys`, `os`, `socket`, `threading`, `subprocess`: For all your system-level operational needs.
    - `Enum`: For robust enumeration types.
    - `datetime`: Because timing is everything.
    - `sqlite3`: For all your database operations.
    - `argparse`: Making the command-line your playground.
    - `logging`: For maintaining those essential logs.
    - `re`: To play around with regular expressions.
    - `binascii`, `zlib`, `struct`: Your toolkit for binary and data manipulation.

  - **External Libraries**:
    - `termcolor`: For pretty and colorful logs.
    - `colorlog`: Because why stop at just colorless logs?
    - `Cryptodome`: For secure cryptographic operations. **Note**: This library name is now `pycryptodome`. Also note that imports might be under `Crypto` instead of `Cryptodome`.

  - 🧩 **Custom modules** - included inside

Make sure to install Python dependencies which are not part of the standard library. Also, make sure to use updated version of python.

---

### 🏃‍♂️ Runing the Server

This script is designed to serve multiple functionalities like starting a server, running in debug mode, and encrypting files. Below are the commands to utilize these functionalities.

#### Basic Server Start

To start the server with default settings, execute the following command:

```bash
python3 server.py
```

By default, the server runs with a logging level set to INFO. It will automatically disconnect and close after detecting inactivity for a specified time period.

#### Debug Mode

To run the server in debug mode, which sets the logging level to DEBUG, use the following command:

  ```bash
    python3 server.py --debug
  ```

**Note**: In debug mode, the server will return incorrect CRC values. Additionally, the automatic disconnection and closing functionalities are disabled when the server is unused.

#### Encryption Mode

To run the server in encryption mode, use the following command:

```bash
python3 server.py --encrypt
```

In this mode, the server not only runs but also triggers a C++ program that encrypts files. The logs for this operation will be stored with a CRITICAL logging level. This mode compiles the client program, builds transfer info of the client source files, and sends it to the server. It also stores the files in an encrypted format in the server directory (instead of the usual plaintext format). The output log in this mode will display the AES key, which can later be used to decrypt the files.

**Please Note**: While this mode allows you to encrypt files for a measure of security, it's generally not as secure as using asymmetric cryptography. It is advisable not to use this for highly sensitive information unless combined with additional security measures.

---

#### 🔍 Using the Server Logs

**Logging Levels**: Various logging levels are supported for debugging and monitoring:

- DEBUG: Detailed information, useful for debugging.

- INFO: General confirmation that things are working as expected.

- WARNING: Indications of something unexpected.

- ERROR: More severe issues, yet the software is still functional.

- CRITICAL: Critical issues that could make the program inoperable.

Each module has its own logger, in order to provide a more granular level of control. For example, the `server.py` script has a logger named `server_logger`, while the `database.py` script has a logger named `db_logger`. This not only allows you to set different logging levels for different modules, but also provide reach information about the source of the log - including a link to the line number and file name.

---

#### 🐛 Using the `debug_log` Decorator

The reciever modulu also equiped with its own logging mehanism, leveraging python decos. The `debug_log` decorator provides enhanced logging functionality when you're running your code in debug mode. It is built using Python's `functools.wraps` to preserve the function's original information (like its name and docstring).

#### How it Works

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

## 🌐 Server Modules Overview

Server employs context managers for resource management and runs in its own thread. Modular design spans multiple Python classes to handle tasks like database management and request parsing.

Key Features include:

- Dynamic ports with fallbacks
- Colored logging
- Data parsing for client requests
- Modular architecture
- File encryption in 'encrypt' mode
- Timeout/session controls
- Exception handling

### 🌐 Server Class

- Handles connection lifecycle and data traffic.

- Uses `argparse` for CLI argument parsing, particularly for debug and encryption modes.

- `prettyBytes` translates byte data into readable format.

- Runs in its own thread, with an additional thread for C++ encryption if needed.

### 📩 Request Handling Module

Python-based framework for client-server request management. Classes inherit from `BaseRequestHandler` for specialized functionality.

#### 📚 Classes

- `BaseRequestHandler`: Initializes client ID and payload, defines virtual `handle_request`.

- `RegisterHandler`: Manages client registration.

- `PublicKeyHandler`: Manages public keys received from clients, and returns AES keys.

- `FileDecryptHandler`: Decrypts files and store them in the server specified directory.

- `ReconnectHandler`: Handles reconnection requests - feches AES key from database and returns it to client.

- `AcknowledgmentHandler`: Handles acknowledgments for different requests such as CRC verification, file decryption, etc.

#### 🧰 Utilities

- `get_handler_for_code`: Returns best handler class for given code. It is used as the entry point for request handling, and it works by mapping each status code to a handler class.

### 📚 Database Module

`DatabaseManager` class acts as context manager for SQLite3 database interactions. Logging via Python's native logging framework.

### 📦 ParseRequestManager Module

Responsible for parsing client requests. Main class is `ParseRequestManager`.

Components:

- Header and Payload Extraction: Uses Python's `struct` library.

- Logging and Debugging: Utilizes Python's `logging` library.

- Error Handling: Uses Python's `try-except` blocks.

- Data Parsing: Uses Python's `zlib` and `binascii` libraries.
