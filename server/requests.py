import zlib
import struct
import uuid
from datetime import datetime
import os
# pycryptodome instead of Cryptodome
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from database import DatabaseManager
from loggers import requests_logger
from loggers import args

# Constants
VERSION = 3
RESPONSE_HEADER_FORMAT = "<BHI"
USER_ID_FORMAT = "<16s"  # also header format
REGISTER_PAYLOAD_FORMAT = "<255s"
ID_SIZE = 16  # 128-bit UUID = AES key size. Defined once here for convenience
NAME_FIELD_LENGTH = 255  # The name field is 255 bytes long - max length
PUBLIC_KEY_FIELD_LENGTH = 160

# Request and Response codes
REGISTER_REQUEST = 1025
PUBLIC_KEY_REQUEST = 1026
RECONNECT_REQUEST = 1027
CRC_SUCCESS_REQUEST = 1029
CRC_RETRY_REQUEST = 1030
CRC_FAILURE_REQUEST = 1031
ENCRYPTED_FILE_REQUEST = 1028
REGISTER_SUCCESS_RESPONSE = 2100
REGISTER_FAIL_RESPONSE = 2101
PUBLIC_KEY_SUCCESS_RESPONSE = 2102
FILE_RECEIVED_RESPONSE = 2103
ACKNOWLEDGMENT_RESPONSE = 2104
RECONNECT_REQUEST_ACCEPTED_RESPONSE = 2105
RECONNECT_REQUEST_DENIED_RESPONSE = 2106
GENERAL_ERROR_RESPONSE = 2107

ANSI_BLUE = "\033[1;34m"
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"

class BaseRequestHandler:
    def __init__(self, client_id=None, payload=None):
        self.client_id = client_id
        self.payload = payload

    def handle_request(self):
        raise NotImplementedError(
            "The method handle_request is not implemented!")

    def pack_response_header(
        self, Version=VERSION, Code=GENERAL_ERROR_RESPONSE, Payload_Size=0
    ):
        requests_logger.debug(
            f"{ANSI_BLUE}Packing response header:{ANSI_RESET} Version={Version}, Code={Code}, Payload_Size={Payload_Size}"
        )
        response_header = struct.pack(
            RESPONSE_HEADER_FORMAT, Version, Code, Payload_Size
        )
        return response_header

    def check_valid_string(self, string):
        has_null_terminator = 0
        if len(string) > NAME_FIELD_LENGTH:
            requests_logger.warning("string field too long")
        elif len(string) == 0 or string == b"\x00" * len(string):
            requests_logger.warning("string field is empty")
        else:
            # Verify that the payload is terminated with a null byte
            if string[-1] != 0:
                string_bytes = bytes(string, "utf-8")
                for i in range(len(string_bytes)):
                    requests_logger.debug(
                        "string[{}]: {}".format(i, chr(string_bytes[i]))
                    )
                requests_logger.warning("string does not have null terminator")
            else:
                has_null_terminator = 1
        return has_null_terminator

    def general_error_msg(self):
        requests_logger.error(
            f"Client {str(uuid.UUID(bytes=self.client_id)).upper()} sent invalid public key"
        )
        response_header = self.pack_response_header()
        return response_header

    def fetch_client_data_by_id(self, client_id):
        with DatabaseManager() as db:
            client_data = db.fetch_client_data(client_id)
            return client_data


# Entry point for the handler classes, encapsulate the request handling logic
def get_handler_for_code(code, client_id, payload):
    handlers = {
        REGISTER_REQUEST: RegisterHandler,
        PUBLIC_KEY_REQUEST: PublicKeyHandler,
        ENCRYPTED_FILE_REQUEST: FileDecryptHandler,
        RECONNECT_REQUEST: ReconnectHandler,
        CRC_SUCCESS_REQUEST: AcknowledgmentHandler,
        CRC_RETRY_REQUEST: AcknowledgmentHandler,
        CRC_FAILURE_REQUEST: AcknowledgmentHandler,
    }

    handler_class = handlers.get(code)
    if not handler_class:
        raise ValueError(f"No handler found for code: {code}")

    return handler_class(client_id, payload)


# Responsible to the fist registration of a client, including:
# - generate a new UUID for the client
# - add the client to the database with its name and UUID
# - send the UUID to the client
class RegisterHandler(BaseRequestHandler):
    def __init__(self, client_id, payload):
        super().__init__(client_id, payload)
        self.uuid = (
            None  # set a default value. uuid = client_id, name changed for clarity
        )
        self.name = self.payload

    def handle_request(self):
        if self.can_register() == REGISTER_SUCCESS_RESPONSE:
            response = self.set_new_client()
        else:
            response = self.new_client_error()
        return response

    # generate a negative respone without payload
    def new_client_error(self, Version=3, Code=GENERAL_ERROR_RESPONSE, Payload_Size=0):
        return self.pack_response_header(Version, Code, Payload_Size)

    # do some checks before registering a client
    def can_register(self):
        if not self.check_valid_string(self.name):
            requests_logger.info(
                "name {} is not valid for registration.\n\n".format(self.name)
            )
            return REGISTER_FAIL_RESPONSE
        with DatabaseManager() as db:
            if db.check_existing_clients(client_field="Name", client_value=self.name):
                requests_logger.warning(
                    "Client with the name {} is already registered".format(
                        self.name.decode("utf-8").strip("\x00")
                    )
                )
            if db.check_existing_clients(
                client_field="ClientID", client_value=self.client_id
            ):  # assuming you have a self.client_id
                requests_logger.critical(
                    "Client with the ID {} is already registered".format(
                        self.client_id)
                )
                return REGISTER_FAIL_RESPONSE
        return REGISTER_SUCCESS_RESPONSE

    # a function to complete the registration process:
    # generate UUID, add client to database, and send response
    def set_new_client(
        self, Version=3, Code=REGISTER_SUCCESS_RESPONSE, Payload_Size=ID_SIZE
    ):
        with DatabaseManager() as db:
            self.uuid = db.add_client_to_database(self.name)
        response_payload = struct.pack(USER_ID_FORMAT, self.uuid.bytes)
        response_header = self.pack_response_header(
            Version=Version, Code=Code, Payload_Size=Payload_Size
        )
        return response_header + response_payload


class AcknowledgmentHandler(BaseRequestHandler):
    def __init__(self, client_id, payload):
        super().__init__(client_id, payload)

    def handle_request(self):
        requests_logger.info(
            "Update from client: {} recieved.".format(self.client_id))
        response = self.pack_response_header(Code=ACKNOWLEDGMENT_RESPONSE)
        return response

    def update_file_status(self):
        pass


# Responsible for generating a new AES key for a client
# > store it in the database with the client's public key
# > encrypt the AES key with the client's public key
# > send the encrypted AES key to the client
class PublicKeyHandler(BaseRequestHandler):
    def __init__(self, client_id, payload):
        super().__init__(client_id, payload)
        self.unpack_public_key()

    def handle_request(self):
        try:
            return_status = self.can_add_key()
            if return_status == PUBLIC_KEY_SUCCESS_RESPONSE:
                self.generate_AES_key()
                self.store_AES_key()
                response = self.response_with_AES()
            else:
                # response = genral_error_msg(client_id=client_id)
                response = self.pack_response_header(Code=return_status)
            return response
        except Exception as e:
            # Handle the exception here and return a general error message
            requests_logger.error(f"Error during request handling: {e}")
            response = self.pack_response_header(Code=GENERAL_ERROR_RESPONSE)
            return response

    def unpack_public_key(self):
        if len(self.payload) > NAME_FIELD_LENGTH + PUBLIC_KEY_FIELD_LENGTH:
            requests_logger.error(
                "payload too long, unpacking first valid bytes")
            self.payload = self.payload[0: NAME_FIELD_LENGTH +
                                        PUBLIC_KEY_FIELD_LENGTH]
        self.name = bytes(self.payload[0:NAME_FIELD_LENGTH])
        requests_logger.debug(
            "Unpacked name: [{}]".format(self.name.strip(b"\x00").decode())
        )
        self.public_key = self.payload[NAME_FIELD_LENGTH:]

        temp_string = ""
        for i in range(len(self.public_key)):
            temp_string += f"{self.public_key[i]:02x}"
            if (i + 1) % ID_SIZE == 0:
                temp_string += "\n"
        if temp_string:
            requests_logger.debug("Key: \n" + temp_string)

    def pretty_print_uuid(self):
        try:
            uuid_obj = uuid.UUID(self.client_id.hex())
            requests_logger.info(f"UUID: {uuid_obj}")
        except ValueError:
            requests_logger.error("Invalid UUID format provided!")

    def can_add_key(self):
        requests_logger.debug("Checking if client can get AES key...")
        # print nice uuid from byte
        self.pretty_print_uuid()

        # convert client_id to uuid object
        try:
            uuid_obj = uuid.UUID(bytes=self.client_id)
        except ValueError:
            requests_logger.warning("Invalid UUID format provided!")
            return GENERAL_ERROR_RESPONSE

        if not self.check_valid_string(self.name):
            requests_logger.warning(f"name {self.name} is not a valid name.")
        elif not self.public_key:
            requests_logger.warning("key is empty")
        elif len(self.public_key) > PUBLIC_KEY_FIELD_LENGTH:
            requests_logger.warning("key is too long")
        else:
            with DatabaseManager() as db:
                if not db.check_existing_clients(
                    client_field="ID", client_value=self.client_id.hex()
                ):
                    print(
                        f"Client {str(uuid.UUID(bytes=self.client_id)).upper()} is not registered"
                    )
                else:
                    requests_logger.warning(
                        f"Client {str(uuid.UUID(bytes=self.client_id)).upper()} is registered whithout a key - updating public key"
                    )
                    db.conn.execute(
                        "UPDATE clients SET public_key=? WHERE ID=?",
                        [self.public_key, str(self.client_id)],
                    )
                    db.conn.commit()
                    return PUBLIC_KEY_SUCCESS_RESPONSE
        return GENERAL_ERROR_RESPONSE

    def generate_AES_key(self):
        try:
            np_pad_key = self.public_key.rstrip(b"\x00")
            self.aes_key = os.urandom(ID_SIZE)  # 128-bit AES key
            requests_logger.critical(f"AES key: {self.aes_key.hex()}")
            self.encrypt_AES_key()
        except Exception as e:
            # Handle the exception here
            requests_logger.error(f"Error during AES key generation: {e}")

    def encrypt_AES_key(self):
        try:
            client_public_key = RSA.importKey(self.public_key)
        except ValueError as ve:
            requests_logger.error(f"RSA key format error: {ve}")
            requests_logger.error("Please check the format of the RSA key.")
            requests_logger.error(
                "Ensure that the key is in the correct format and valid."
            )
            raise ValueError("Invalid RSA key format")
        cipher_rsa = PKCS1_OAEP.new(client_public_key)
        self.encrypted_aes_key = cipher_rsa.encrypt(self.aes_key)

    def store_AES_key(self):
        with DatabaseManager() as db_manager:
            db_manager.store_AES_key(
                self.client_id, self.public_key, self.aes_key)

    def response_with_AES(self, Code=PUBLIC_KEY_SUCCESS_RESPONSE):
        try:
            uuid_bytes = bytes.fromhex(self.client_id.hex())
            payload = struct.pack(f"<16s", uuid_bytes) + self.encrypted_aes_key
            payload_size = len(payload)
            requests_logger.debug(f"payload_size: {payload_size}")
            response_header = self.pack_response_header(
                Code=Code, Payload_Size=payload_size
            )
            return response_header + payload
        except struct.error as e:
            requests_logger.error(f"Error while packing AES key: {e}")
            raise ValueError("Error packing AES key")


class ReconnectHandler(PublicKeyHandler):
    def __init__(self, client_id, payload):
        super().__init__(client_id, payload)

    def handle_request(self):
        client_data = self.fetch_client_data_by_id(self.client_id)
        if not client_data:
            return self.pack_response_header(Code=RECONNECT_REQUEST_DENIED_RESPONSE)

        _, _, public_key, _, aes_key = client_data

        client_id_str = str(uuid.UUID(bytes=self.client_id)).upper()

        if not public_key or not aes_key:
            if not public_key and not aes_key:
                requests_logger.error(
                    f"Client {client_id_str} has {ANSI_BOLD}no public key and no AES key{ANSI_RESET}. Has the client completed the registration protocol?"
                )
            elif not public_key:
                requests_logger.error(
                    f"Client {client_id_str} has {ANSI_BOLD}no public key{ANSI_RESET}. Has the client completed the registration protocol?"
                )
            elif not aes_key:
                requests_logger.error(
                    f"Client {client_id_str} has {ANSI_BOLD}no AES key{ANSI_RESET}. Has the client completed the registration protocol?"
                )
            return self.pack_response_header(Code=RECONNECT_REQUEST_DENIED_RESPONSE)


        self.public_key = public_key
        self.aes_key = aes_key
        # Check the length of aes_key
        key_length = len(self.aes_key)
        if key_length <= 8:  # magic number for 64-bit key
            aes_key_snippet = self.aes_key
        else:
            aes_key_snippet = self.aes_key[:8]
        requests_logger.info(
            f"SENSITIVE DATA: AES key snippet: {aes_key_snippet.hex()}..."
        )
        self.encrypt_AES_key()
        return self.response_with_AES(Code=RECONNECT_REQUEST_ACCEPTED_RESPONSE)


class FileDecryptHandler(BaseRequestHandler):
    UPLOAD_FOLDER = "uploaded_files"
    FIELD_SIZE_NAME = 255
    FIELD_SIZE_CONTENT_SIZE = 4

    def __init__(self, client_id, payload):
        super().__init__(client_id, payload)
        if not os.path.exists(self.UPLOAD_FOLDER):
            os.makedirs(self.UPLOAD_FOLDER)
        self.iv = b"\x00" * ID_SIZE  # 16 bytes of zeros
        self.unpack_file()

    def unpack_file(self):
        (self.file_content_size,) = struct.unpack(
            "<I", self.payload[: self.FIELD_SIZE_CONTENT_SIZE]
        )

        start_of_filename = self.FIELD_SIZE_CONTENT_SIZE
        end_of_filename = self.FIELD_SIZE_CONTENT_SIZE + NAME_FIELD_LENGTH

        self.file_name = (
            self.payload[start_of_filename:end_of_filename].decode().strip(
                "\0")
        )
        self.file_content = self.payload[
            end_of_filename: end_of_filename + self.file_content_size
        ]
        requests_logger.debug(f"File name: {self.file_name}")
        requests_logger.debug(f"File content size: {self.file_content_size}")

    def handle_request(self):
        decrypted_data = None
        self.getAESKey()
        try:
            decrypted_data = self.decrypt_data()
            no_padding_data = self.remove_padding(decrypted_data)

            snippet_size = min(10, len(no_padding_data))
            snippet = no_padding_data[:snippet_size]

            requests_logger.info(
                f"Received file data snippet (first {snippet_size} bytes): {snippet}"
            )
            if args.encrypt:
                self.storeFile(self.file_content)
            else:
                self.storeFile(no_padding_data)
        except Exception as e:
            requests_logger.error(f"Error during file decryption: {e}")
            if (e.args[0] == "UNIQUE constraint failed: files.ID"):
                requests_logger.warning(
                    f"File {self.file_name} already exists in the database"
                )
        try:
            crc_value = self.calculate_crc()
        except Exception as e:
            requests_logger.error(f"Error during CRC calculation: {e}")
        try:
            if args.debug:
                requests_logger.critical(
                    "Passing wrong CRC value for testing purposes")
                crc_value = crc_value + 1
            response = self.response_withCRC(crc_value)
            return response
        except Exception as e:
            requests_logger.error(f"Error during CRC response handler: {e}")
        return self.general_error_msg()

    def getAESKey(self):
        with DatabaseManager() as db:
            client_data = self.fetch_client_data_by_id(self.client_id)
            if not client_data:
                return self.pack_response_header(Code=RECONNECT_REQUEST_DENIED_RESPONSE)
            _, _, _, _, aes_key_hex = client_data
            self.aes_key = aes_key_hex  # Convert from hex to bytes

    def decrypt_data(self):
        try:
            truncated_hex_content = self.file_content[:50].hex()
            ellipsis = "..." if len(self.file_content) > 50 else ""

            requests_logger.debug(
                f'"{self.file_name}" encrypted content ({self.file_content_size} bytes):\n{truncated_hex_content}{ellipsis}'
            )
            aes_key_snippet = self.aes_key[:8]
            requests_logger.info(
                f"SENSITIVE DATA: AES key snippet: {aes_key_snippet.hex()}..."
            )
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=b"\x00" * ID_SIZE)
            decrypted_data = cipher.decrypt(self.file_content)
            self.file_content_size = len(decrypted_data)
        except ValueError as e:
            requests_logger.error(
                f"Decryption error for client with ID: {self.client_id}. Error: {e}"
            )
            raise ValueError("AES decryption error")
        return decrypted_data

    def remove_padding(self, data: bytes) -> bytes:
        """Remove PKCS#7 padding."""
        padding_length = data[
            -1
        ]  # Get the last byte, which indicates the padding length
        return data[:-padding_length]

    def hex_ascii_to_original(self, data: bytes) -> bytes:
        """Convert ASCII hex representation back to its original form."""
        as_str = data.decode("utf-8")
        return bytes.fromhex(as_str)

    def calculate_crc(self):
        try:
            checksum = zlib.crc32(self.file_content)
            requests_logger.info(f"CRC: {checksum}")
            return checksum
        except Exception as e:
            requests_logger.error(f"Error during CRC calculation: {e}")
            raise

    def response_withCRC(self, crc_value):

        try:
            #  payload: 16 bytes for UUID, 4 bytes for content size after decryption
            # 255 bytes for file name, 4 bytes for CRC value
            requests_logger.debug(
                f"self.client_id format: {type(self.client_id)}, value: {self.client_id}"
            )
            response_payload = struct.pack(USER_ID_FORMAT, self.client_id)

            requests_logger.debug(
                f"self.file_content_size: {type(self.file_content_size)}, value: {self.file_content_size}"
            )
            response_payload += struct.pack("<I", self.file_content_size)

            requests_logger.debug(
                f"self.file_name format: {type(self.file_name.encode())}, value: {self.file_name.encode()}"
            )
            response_payload += struct.pack(REGISTER_PAYLOAD_FORMAT,
                                            self.file_name.encode())

            requests_logger.debug(
                f"crc_value format: {type(crc_value)}, value: {crc_value}"
            )
            # Fix: append crc_value to existing payload
            response_payload += struct.pack("<I", crc_value)

            if (
                len(response_payload) != 279
            ):  # Fix: use != instead of "is not" for integer comparison
                requests_logger.error(
                    f"Error while packing CRC value: Payload size is {len(response_payload)} instead of 279"
                )
                raise ValueError("Error packing CRC response")
            response_header = self.pack_response_header(
                Code=FILE_RECEIVED_RESPONSE, Payload_Size=len(response_payload)
            )
            requests_logger.debug(
                "header (%d bytes): %s", len(
                    response_header), response_header.hex()
            )
            requests_logger.debug(
                "payload (%d bytes): %s",
                len(response_payload),
                response_payload[:50].hex()
                + ("..." if len(response_payload) > 50 else ""),
            )
            return response_header + response_payload

        except struct.error as e:
            requests_logger.error(f"Error while packing CRC value: {e}")
            raise ValueError("Error packing CRC response")

    def storeFile(self, original_string):
        file_path = os.path.join(self.UPLOAD_FOLDER, self.file_name)
        requests_logger.info(f"Saving file to {file_path}")
        with open(file_path, "wb") as file:
            file.write(original_string)
            requests_logger.info(f"File {file_path} saved successfully")

        # update files db
        with DatabaseManager() as db:
            db.add_file_to_database(
                UUID=self.client_id, file_name=self.file_name, path_name=file_path
            )


class FileSaveHandler(BaseRequestHandler):
    FILE_SAVE_PATH = "path/to/save/directory/"  # TODO: Define the desired path

    def __init__(self, client_id, payload):
        super().__init__(client_id, payload)
        self.file_content = (
            payload
        )

    def handle_request(self):
        with DatabaseManager() as db:
            aes_key = db.get_AES_key_for_client(self.client_id)

        if not aes_key:
            requests_logger.error(
                f"No AES key found for client {self.client_id}")
            return self.pack_response_header(Code=GENERAL_ERROR_RESPONSE)

        decrypted_content = self.decrypt_with_AES(aes_key, self.file_content)
        filename = f"{self.client_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
        with open(os.path.join(self.FILE_SAVE_PATH, filename), "wb") as file:
            file.write(decrypted_content)

        return self.pack_response_header(Code=FILE_RECEIVED_RESPONSE)

    def decrypt_with_AES(self, key, content):
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(content)
