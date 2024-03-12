import struct
import datetime
import logging
import argparse

ID_MAX = 2 ** 128 - 1
AES_KEY_MAX = 2 ** 128 - 1
PUBLIC_KEY_MAX = 2 ** 160 - 1
ENCODING = "utf-8"
SIXTEEN_BYTES_PACK = ">16s"

# TODO: Declare constants for size of fields
class LevelColoredFormatter(logging.Formatter):
    LEVEL_COLORS = {
        "DEBUG": "blue",
        "INFO": "white",
        "WARNING": "magenta",
        "ERROR": "yellow",
        "CRITICAL": "red",
    }

    def format(self, record):
        record.combined_info = f"[{record.filename}:{record.lineno}]"
        levelname = record.levelname
        levelname_color = self.LEVEL_COLORS.get(levelname, "grey")
        record.levelname = colored(levelname, levelname_color)
        log_message = super().format(record)
        record.levelname = levelname
        return log_message


# Create new logger for parser
parser_logger = logging.getLogger("parser")
parser_logger.setLevel(logging.DEBUG)

if not parser_logger.handlers:
    parser_console_handler = logging.StreamHandler()
    parser_console_handler.setLevel(logging.DEBUG)
    parser_formatter = LevelColoredFormatter(
        "%(combined_info)-20s [%(levelname)-12s] %(message)-10s"
    )
    parser_console_handler.setFormatter(parser_formatter)
    parser_logger.propagate = False
    parser_logger.addHandler(parser_console_handler)


parser = argparse.ArgumentParser(
    description="Run the server with optional debug mode.")
parser.add_argument("--debug", action="store_true", help="Run in debug mode")
parser.add_argument("--encrypt", action="store_true", help="Encrypt the files")
args = parser.parse_args()

if args.debug:
    parser_logger.setLevel(logging.DEBUG)
elif args.encrypt:
    parser_logger.setLevel(logging.CRITICAL)
else:
    parser_logger.setLevel(logging.INFO)


def client_pack_check(id, name, public_key, last_seen, aes_key):
    if not isinstance(id, int) or not 0 <= id <= ID_MAX:
        parser_logger.warning(f"Invalid ID for client: {id}")
    if not isinstance(name, str):
        parser_logger.warning(f"Invalid name for client: {name}")
    if not isinstance(public_key, int) or not 0 <= public_key <= PUBLIC_KEY_MAX:
        parser_logger.warning(f"Invalid public key for client: {public_key}")
    if not isinstance(last_seen, datetime.datetime):
        parser_logger.warning(f"Invalid timestamp for client: {last_seen}")
    if not isinstance(aes_key, int) or not 0 <= aes_key <= AES_KEY_MAX:
        parser_logger.warning(f"Invalid AES key for client: {aes_key}")


# Define a function to pack the fields into a dictionary
def pack_client(id, name, public_key, last_seen, aes_key):
    client_pack_check(id, name, public_key, last_seen, aes_key)
    id_bytes = struct.pack(
        SIXTEEN_BYTES_PACK, id.to_bytes(16, byteorder="big"))
    name_bytes = struct.pack(f">{len(name)}s", name.encode(ENCODING))
    public_key_bytes = struct.pack(
        ">160s", public_key.to_bytes(160, byteorder="big"))
    last_seen_bytes = struct.pack(">Q", int(last_seen.timestamp()))
    aes_key_bytes = struct.pack(
        SIXTEEN_BYTES_PACK, aes_key.to_bytes(16, byteorder="big"))
    return {
        "id": id_bytes,
        "name": name_bytes,
        "public_key": public_key_bytes,
        "last_seen": last_seen_bytes,
        "aes_key": aes_key_bytes,
    }


def unpack_client(packed_data):
    try:
        id = int.from_bytes(
            struct.unpack(SIXTEEN_BYTES_PACK, packed_data["id"])[
                0], byteorder="big"
        )
        name = struct.unpack(f'>{len(packed_data["name"])}s', packed_data["name"])[
            0
        ].decode(ENCODING)
        public_key = int.from_bytes(
            struct.unpack(">160s", packed_data["public_key"])[
                0], byteorder="big"
        )
        last_seen = datetime.datetime.fromtimestamp(
            struct.unpack(">Q", packed_data["last_seen"])[0]
        )
        aes_key = int.from_bytes(
            struct.unpack(SIXTEEN_BYTES_PACK, packed_data["aes_key"])[
                0], byteorder="big"
        )
        return id, name, public_key, last_seen, aes_key
    except Exception as e:
        parser_logger.error(f"Error unpacking client data: {e}")
        raise


def file_pack_check(id, FileName, PathName, Verified):
    if not isinstance(id, int) or not 0 <= id <= ID_MAX:
        parser_logger.warning(f"Invalid ID for file: {id}")
    if not isinstance(FileName, str):
        parser_logger.warning(f"Invalid FileName for file: {FileName}")
    if not isinstance(PathName, str):
        parser_logger.warning(f"Invalid PathName for file: {PathName}")
    if not isinstance(Verified, int) or Verified not in [0, 1]:
        parser_logger.warning(f"Invalid Verified status for file: {Verified}")


def pack_file(id, FileName, PathName, Verified):
    file_pack_check(id, FileName, PathName, Verified)
    id_bytes = struct.pack(
        SIXTEEN_BYTES_PACK, id.to_bytes(16, byteorder="big"))
    FileName_bytes = struct.pack(
        f">{len(FileName)}s", FileName.encode(ENCODING))
    PathName_bytes = struct.pack(
        f">{len(PathName)}s", PathName.encode(ENCODING))
    Verified_bytes = struct.pack(">B", Verified)
    return {
        "id": id_bytes,
        "FileName": FileName_bytes,
        "PathName": PathName_bytes,
        "Verified": Verified_bytes,
    }


def unpack_file(packed_data):
    try:
        id = int.from_bytes(
            struct.unpack(SIXTEEN_BYTES_PACK, packed_data["id"])[
                0], byteorder="big"
        )
        FileName = struct.unpack(
            f'>{len(packed_data["FileName"])}s', packed_data["FileName"]
        )[0].decode(ENCODING)
        PathName = struct.unpack(
            f'>{len(packed_data["PathName"])}s', packed_data["PathName"]
        )[0].decode(ENCODING)
        Verified = struct.unpack(">B", packed_data["Verified"])[0]
        return id, FileName, PathName, Verified
    except Exception as e:
        parser_logger.error(f"Error unpacking file data: {e}")
        raise
