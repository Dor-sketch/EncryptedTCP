import struct
import logging
import functools
import select
import time

HEADER_FORMAT = "<16sBHI"
DEBUG_MODE = True  # This mode is not affected by the --debug flag
# enable it by setting DEBUG_MODE to True

ANSI_BLUE_BRIGHT = "\033[1;94m"
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"

def debug_log(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if DEBUG_MODE:
            arg_strs = [
                hexlify(arg) if isinstance(arg, bytes) else str(arg) for arg in args
            ]
            kwarg_strs = {
                k: hexlify(v) if isinstance(v, bytes) else str(v)
                for k, v in kwargs.items()
            }
            logging.debug(
                f"Calling {func.__name__} with args: {', '.join(arg_strs)} and kwargs: {kwarg_strs}"
            )

        result = func(*args, **kwargs)

        if DEBUG_MODE:
            result_str = hexlify(result) if isinstance(
                result, bytes) else str(result)
            logging.debug(f"{func.__name__} returned {result_str}")

        return result

    return wrapper


def hexlify(data):

    return " ".join(f"{byte:02x}" for byte in data)


class ParseRequestManager:
    def __init__(self, conn):
        self.conn = conn
        self._header_data = None
        self._client_id = None
        self._version = None
        self._code = None
        self._payload_size = None
        self._payload_data = None

        try:
            self._initialize()
        except Exception as e:
            # Handle the exception here
            logging.error(
                f"Error during ParseRequestManager initialization: {e}")
            self.close_connection()

    def _initialize(self):
        self._header_data = self._retrieve_header_data()
        result = self._parse_header_data()
        if result is not None:
            (
                self._client_id,
                self._version,
                self._code,
                self._payload_size,
            ) = result
            self._log_header_info()

            if self._payload_size:
                self._payload_data = self._retrieve_payload_data()

    @debug_log
    def _retrieve_header_data(self):
        try:
            header_size = struct.calcsize(HEADER_FORMAT)
            return self._receive_data(header_size)
        except ValueError as ve:
            logging.error(f"ValueError in _retrieve_header_data: {ve}")
            self.close_connection()
        except IOError as ioe:
            logging.error(f"IOError in _retrieve_header_data: {ioe}")
            self.close_connection()

    def close_connection(self):

        try:
            self.conn.close()
        except Exception as e:
            logging.error(f"Error closing connection: {e}")

    def _receive_data(self, size, timeout=3):
        logging.debug(f"Receiving data of size: {size}")
        data = b""
        start_time = time.time()
        while len(data) < size:
            logging.debug(
                f"Received data length: {len(data)}, Expected size: {size}")
            ready, _, _ = select.select([self.conn], [], [], timeout)
            if not ready:
                elapsed_time = time.time() - start_time
                logging.warning(
                    f"Timeout waiting for data ({elapsed_time:.2f} seconds elapsed)"
                )
                raise TimeoutError("Timeout waiting for data")
            more_data = self.conn.recv(size - len(data))
            if not more_data:
                logging.error("Connection closed prematurely")
                raise ValueError("Incomplete request data")
            data += more_data
            logging.debug(
                f"Received data length: {len(data)}, Expected size: {size}")
        return data

    @debug_log
    def _parse_header_data(self):
        if self._header_data is None:
            logging.error("Header data is None. Cannot unpack.")
            return None

        try:
            return struct.unpack(HEADER_FORMAT, self._header_data)
        except struct.error as se:
            logging.error(f"Struct error in _parse_header_data: {se}")
            return None

    @debug_log
    def _retrieve_payload_data(self):
        if self._payload_size is None:
            logging.error(
                "Payload size is None. Cannot retrieve payload data.")
            return None
        logging.debug(f"Payload size: {self._payload_size}")
        try:
            logging.debug(
                f"Retrieving payload data of size: {self._payload_size}")

            payload_data = self._receive_data(self._payload_size)
            if len(payload_data) == self._payload_size - 1:
                payload_data += self.conn.recv(1)
            return payload_data
        except ValueError as ve:
            logging.error(f"ValueError in _retrieve_payload_data: {ve}")
        except IOError as ioe:
            logging.error(f"IOError in _retrieve_payload_data: {ioe}")

    def _log_header_info(self):
        if self._client_id is None:
            logging.error("Client ID is None. Cannot log header info.")
            return
        client_id_hex = self._client_id.hex()
        logging.debug(
            f"{ANSI_BLUE_BRIGHT}Header:{ANSI_RESET}\n"
            f"{ANSI_BOLD}Client ID:{ANSI_RESET} {client_id_hex}\n"
            f"{ANSI_BOLD}Version:{ANSI_RESET} {self._version}\n"
            f"{ANSI_BOLD}Code:{ANSI_RESET} {self._code}\n"
            f"{ANSI_BOLD}Payload Size:{ANSI_RESET} {self._payload_size}"
        )

    def print_header(self):
        client_id_hex = self._client_id.hex()
        logging.debug(
            f"{ANSI_BLUE_BRIGHT}Header:{ANSI_RESET}\n"
            f"{ANSI_BOLD}Client ID:{ANSI_RESET} {client_id_hex}\n"
            f"{ANSI_BOLD}Version:{ANSI_RESET} {self._version}\n"
            f"{ANSI_BOLD}Code:{ANSI_RESET} {self._code}\n"
            f"{ANSI_BOLD}Payload Size:{ANSI_RESET} {self._payload_size}"
        )

    @property
    def payload(self):
        return self._payload_data

    @property
    def client_id(self):
        return self._client_id

    @property
    def version(self):
        return self._version

    @property
    def code(self):
        return self._code

    @property
    def payload_size(self):
        return self._payload_size
