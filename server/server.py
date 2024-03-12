import socket
import logging
import binascii
from prettybytes import pretty_bytes
from database import DatabaseManager
from requests import get_handler_for_code
from receiver import ParseRequestManager
import select
import time
from loggers import server_logger
from loggers import args

# Constants
DEFAULT_PORT = 1357
PORT_FILE = "port.info"
ANSI_BLUE_BRIGHT = "\033[1;94m"
ANSI_RESET = "\033[0m"


if args.debug:
    server_logger.setLevel(logging.DEBUG)
elif args.encrypt:
    server_logger.setLevel(logging.CRITICAL)
else:
    server_logger.setLevel(logging.INFO)


class Server:
    def __init__(self):
        self.start_time = time.time()
        self.port = self.get_port()
        self.initialize_database()

    def initialize_database(self):
        with DatabaseManager() as db:
            server_logger.debug("Database initialized")

    def get_port(self):
        try:
            with open(PORT_FILE, "r") as f:
                port = int(f.read().strip())
                if 0 <= port <= 65535:
                    server_logger.info(f"Using port number from file: {port}")
                    return port
                else:
                    raise ValueError("Port number must be between 0 and 65535")
        except (FileNotFoundError, ValueError, TypeError) as e:
            server_logger.warning(f"{e}. Using default port {DEFAULT_PORT}.")
            return DEFAULT_PORT

    def connect_server(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(("localhost", self.port))
        except socket.error as e:
            server_logger.error(f"Socket error: {e}")
            exit(1)

    def disconnect_server(self):
        self.sock.close()
        server_logger.info("Server connection closed")

    def start_waiting(self):
        session_time = 0
        self.sock.listen(5)
        try:
            while True:
                session_time = time.time() - self.start_time
                ready, _, _ = select.select([self.sock], [], [], 30)
                if not ready and not args.debug:
                    elapsed_time = time.time() - self.start_time
                    if elapsed_time > 240:
                        server_logger.critical(
                            f"No connection received in {round(elapsed_time)} seconds. Stopping server..."
                        )
                        self.disconnect_server()
                        break
                    if elapsed_time > 180:
                        server_logger.critical(
                            f"No connection received in {round(elapsed_time)} seconds. Server will stop in 60 seconds."
                        )
                        break
                    elif elapsed_time > 60:
                        server_logger.warning(
                            f"No connection received in {round(elapsed_time)} seconds. Server will stop in 120 seconds."
                        )
                    else:
                        server_logger.warning(
                            f"No connection received in {round(elapsed_time)} seconds"
                        )
                    continue
                server_logger.info(f"Listening on port {self.port}...")
                conn, addr = self.sock.accept()
                server_logger.info(f"Connection received from {addr}")
                self.process_request_data(conn)
                conn.close()
        except KeyboardInterrupt:
            server_logger.critical(
                "\nKeyboard interrupt received: stopping server...")
        finally:
            self.disconnect_server()

    def log_bytes(self, data):
        server_logger.info(f"Received {len(data)} bytes")
        server_logger.info(f"Data: {binascii.hexlify(data)}")
        hex_response = binascii.hexlify(data).decode("utf-8")
        server_logger.info(f"Data: {hex_response}")

    def process_request_data(self, conn):
        start_time = time.time()
        try:
            parse_request_manager = ParseRequestManager(conn)
            if args.debug:
                parse_request_manager.print_header()

            server_logger.debug(
                f"{ANSI_BLUE_BRIGHT}Payload:{ANSI_RESET}\n{pretty_bytes(parse_request_manager.payload)}"
            )

            handler = get_handler_for_code(
                code=parse_request_manager.code,
                client_id=parse_request_manager.client_id,
                payload=parse_request_manager.payload,
            )
            response = handler.handle_request()
            formatted_data = pretty_bytes(response)
            server_logger.debug(
                f"Sending {len(response)} bytes:\n{formatted_data}")
            conn.settimeout(5)  # Set a timeout of 5 seconds

            if conn.fileno() != -1:
                conn.send(response)
            else:
                logging.warning(
                    "Connection is no longer active. Aborting send.")

        except socket.timeout:
            logging.error("Failed to send response: operation timed out")
            conn.close()
        except Exception as e:
            logging.error(f"Error processing request data: {e}")
            conn.close()

        elapsed_time = time.time() - start_time
        server_logger.info(
            f"Response sent in {round(elapsed_time)} seconds. Running time: {round(time.time()-self.start_time)} seconds"
        )

    def run(self):
        with self:
            self.connect_server()
            self.start_waiting()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type or exc_value or traceback:
            server_logger.error(
                f"Exception occurred:\n{exc_type}\n{exc_value}\n{traceback}"
            )
        self.disconnect_server()


if __name__ == "__main__":
    if args.debug:
        server_logger.critical("Running in debug mode")

    with Server() as server:
        server.run()
