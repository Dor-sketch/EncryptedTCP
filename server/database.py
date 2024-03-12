import sqlite3
from datetime import datetime
import uuid
import os
import base64
from enum import Enum, auto
from loggers import db_logger

class ClientFields(Enum):
    ID = auto()
    NAME = auto()
    PUBLIC_KEY = auto()
    LAST_SEEN = auto()
    AES_KEY = auto()



ALLOWED_FIELDS = [
    "ID",
    "Name",
    "last_seen",
    "public_key",
    "aes_key",
]

DB_FILE = "database.db"


# ANSI escape codes
BOLD = "\033[1m"
RED = "\033[91m"
RESET = "\033[0m"

def colorize_field(field):
    return f"{BOLD}{RED}{field}{RESET}"

def log_query_result(query_result):
    field_titles = ["ID", "name", "public_key", "last_seen", "aes_key"]
    formatted_result = []

    for idx, item in enumerate(query_result):
        field_title = (
            colorize_field(field_titles[idx])
            if idx < len(field_titles)
            else colorize_field("UnknownField")
        )

        if field_title == colorize_field("name") and isinstance(item, bytes):
            # Decode the name from bytes to string
            decoded_name = item.decode("utf-8").rstrip("\x00")
            formatted_value = f"{field_title}: {decoded_name}"
        elif isinstance(item, bytes) and field_title != colorize_field("name"):
            # Use Base64 encoding for byte strings (like keys)
            base64_encoded = base64.b64encode(item).decode("utf-8")
            formatted_value = f"{field_title}: {base64_encoded}"
        elif isinstance(item, (int, bool, uuid.UUID)):
            formatted_value = f"{field_title}: {str(item)}"
        elif isinstance(item, datetime):
            formatted_value = f"{field_title}: {item.strftime('%Y-%m-%d %H:%M:%S.%f')}"
        elif isinstance(item, str):
            formatted_value = f"{field_title}: {item}"
        else:
            formatted_value = f"{field_title}: Unknown type"

        formatted_result.append(formatted_value)

    formatted_data = "\n".join(formatted_result)
    db_logger.debug("Data found in database: [{}]".format(formatted_data))


class DatabaseManager:
    def __init__(self, db_file=DB_FILE):
        self.db_file = db_file
        if os.path.exists(self.db_file) is False:
            db_logger.warning(
                "Database file not found. Creating new database file.")
        self.conn = self._connect_to_db()
        self._create_tables()

    def delete_database_file(self):
        if os.path.exists(self.db_file):
            os.remove(self.db_file)
            db_logger.info("Database file deleted.")
        else:
            db_logger.error("Database file not found.")

    def _connect_to_db(self):
        return sqlite3.connect(self.db_file)

    def _create_tables(self):
        try:
            cursor = self.conn.cursor()
            cursor.executescript(
                """
                CREATE TABLE IF NOT EXISTS clients (
                    ID BINARY(16) PRIMARY KEY,
                    name VARCHAR(256),
                    public_key BINARY(160),
                    last_seen DATETIME,
                    aes_key BINARY(16)
                );
                CREATE TABLE IF NOT EXISTS files (
                    ID BINARY(16) PRIMARY KEY,
                    FileName VARCHAR(256),
                    PathName VARCHAR(256),
                    Verified BOOLEAN
                );
                """
            )
            self.conn.commit()
            cursor.close()
        except sqlite3.Error as e:
            db_logger.error(f"Database error: {e}")

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def get_AES_key_for_client(self, client_id):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT aes_key FROM clients WHERE ID=?", client_value)
            aes_key = cursor.fetchone()
            if aes_key:
                return aes_key[0]
            else:
                return None
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return None

    def store_AES_key(self, client_id, public_key_bytes, aes_key):
        last_seen = datetime.now()

        try:
            formatted_uuid = str(uuid.UUID(client_id.hex()))
        except ValueError:
            db_logger.error(f"Invalid UUID format: {client_value}")
            return False

        try:
            # Update both the public key and the AES key in the database
            self.conn.execute(
                "UPDATE clients SET public_key=?, last_seen=?, aes_key=? WHERE ID=?",
                (public_key_bytes, last_seen, aes_key, formatted_uuid),
            )
            self.conn.commit()
            db_logger.debug("AES key stored in database.")
        except sqlite3.Error as e:
            db_logger.error(f"Database error: {e}")

    def generate_UUID(self):
        # string format is used to avoid SQLite3 maximum int size errors
        new_user_id = uuid.uuid4()
        while self.check_existing_clients(
            client_field="ID", client_value=str(new_user_id)
        ):
            new_user_id = uuid.uuid4()
        db_logger.critical("Generated new UUID: {}".format(new_user_id))
        return new_user_id

    def add_client_to_database(self, name):
        client_id = self.generate_UUID()
        last_seen = datetime.now()
        self.conn.text_factory = bytes
        self.conn.execute(
            "INSERT INTO clients (ID, Name, last_seen, public_key, aes_key) VALUES (?, ?, ?, 0, 0)",
            [str(client_id), name, last_seen],
        )
        self.conn.commit()
        return client_id

    def check_existing_clients(self, client_field, client_value):
        if client_field not in ALLOWED_FIELDS:
            print("Invalid client field provided.")
            return False
        # Ensure ID field value has dashes
        if client_field == "ID":
            try:
                formatted_uuid = str(uuid.UUID(client_value))
                client_value = formatted_uuid
                db_logger.debug("formatted_uuid: {}".format(formatted_uuid))
            except ValueError:
                db_logger.warning(
                    "Invalid UUID format: {}.".format(client_value))
                return False
        data = None
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM clients WHERE {}=?".format(
                    client_field), (client_value,)
            )
            data = cursor.fetchone()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False
        finally:
            if data:
                log_query_result(data)
            else:
                db_logger.warning(
                    "Unregistered client: Please complete registration.")

        return bool(data)

    def fetch_client_data(self, client_id):
        client_field = "ID"
        client_value = client_id

        try:
            formatted_uuid = str(uuid.UUID(client_id.hex()))
            client_value = formatted_uuid
        except ValueError:
            return False
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM clients WHERE {}=?".format(
                    client_field), (client_value,)
            )
            data = cursor.fetchone()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False
        finally:
            if data:
                log_query_result(data)
                return data
            else:
                db_logger.warning(
                    "Data not found in database for field: [{}] with value: [{}]. Was the data base deleted? Is it a registered client?".format(
                        client_field, client_value
                    )
                )

    def get_public_key(self, client_id):
        data = self.fetch_client_data(client_id)
        if data:
            # Assuming that public_key is the third item in the returned tuple
            return data[2]
        else:
            db_logger.warning(
                "Public key not found for client ID: [{}]. Was the database deleted? Is it a registered client?".format(
                    client_id
                )
            )
            return None

    def fetch_client_data_by_field(self, client_id, field_enum):
        client_field = "ID"
        client_value = client_id

        try:
            formatted_uuid = str(uuid.UUID(client_id.hex()))
            client_value = formatted_uuid
        except ValueError:
            return None

        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM clients WHERE {}=?".format(
                    client_field), (client_value,)
            )
            data = cursor.fetchone()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return None

        if data:
            return data[4]
        else:
            db_logger.warning(
                "Data not found in database for field: [{}] with value: [{}]. Was the database deleted? Is it a registered client?".format(
                    client_field, client_value
                )
            )
            return None

    def execute_query(self, query, query_params):
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, query_params)
            self.conn.commit()
            cursor.close()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False
        return True

    def add_file_to_database(self, UUID, file_name, path_name=""):
        # TODO: Add checks (e.g., to ensure file with same name doesn't exist already, etc.)

        self.conn.execute(
            "INSERT INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)",
            [str(UUID), file_name, path_name, False],
        )
        self.conn.commit()
