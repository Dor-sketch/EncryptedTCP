import logging
import argparse
from termcolor import colored


class LevelColoredFormatter(logging.Formatter):
    LEVEL_COLORS = {
        "DEBUG": "blue",
        "INFO": "green",
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "magenta",
    }

    def format(self, record):
        record.combined_info = f"[{record.filename}:{record.lineno}]"
        levelname = record.levelname
        levelname_color = self.LEVEL_COLORS.get(levelname, "white")
        record.levelname = colored(levelname, levelname_color)
        log_message = super().format(record)
        record.levelname = levelname
        return log_message


server_logger = logging.getLogger("server")

# Check if the server_logger object already has handlers attached
if not server_logger.handlers:
    # Set up the console handler with a custom formatter
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    formatter = LevelColoredFormatter(
        "%(combined_info)-20s [%(levelname)-8s] %(message)s"
    )
    console_handler.setFormatter(formatter)
    server_logger.propagate = False
    server_logger.addHandler(console_handler)

parser = argparse.ArgumentParser(
    description="Run the server with optional debug mode.")
parser.add_argument("--debug", action="store_true", help="Run in debug mode")
parser.add_argument("--encrypt", action="store_true", help="Encrypt the files")
args = parser.parse_args()


class LevelColoredFormatter(logging.Formatter):
    LEVEL_COLORS = {
        "DEBUG": "cyan",
        "INFO": "green",
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "magenta",
    }

    def format(self, record):
        record.combined_info = f"[{record.filename}:{record.lineno}]"
        levelname = record.levelname
        levelname_color = self.LEVEL_COLORS.get(levelname, "white")
        record.levelname = colored(levelname, levelname_color)
        log_message = super().format(record)
        record.levelname = levelname
        return log_message


requests_logger = logging.getLogger("requests")
requests_logger.setLevel(logging.DEBUG)

if not requests_logger.handlers:
    requests_console_handler = logging.StreamHandler()
    requests_console_handler.setLevel(logging.DEBUG)
    requests_formatter = LevelColoredFormatter(
        "%(combined_info)-20s [%(levelname)-20s] %(message)-20s"
    )

    requests_console_handler.setFormatter(requests_formatter)
    requests_logger.propagate = False
    requests_logger.addHandler(requests_console_handler)


parser = argparse.ArgumentParser(
    description="Run the server with optional debug mode.")
parser.add_argument("--debug", action="store_true", help="Run in debug mode")
parser.add_argument("--encrypt", action="store_true", help="Encrypt the files")
args = parser.parse_args()

# Set the logging level based on the command-line argument
if args.debug:
    requests_logger.setLevel(logging.DEBUG)
elif args.encrypt:
    requests_logger.setLevel(logging.CRITICAL)
else:
    requests_logger.setLevel(logging.INFO)


class DBColoredFormatter(logging.Formatter):
    LEVEL_COLORS = {
        "DEBUG": "grey",
        "INFO": "cyan",
        "WARNING": "yellow",
        "ERROR": "magenta",
        "CRITICAL": "red",
    }

    def format(self, record):
        record.combined_info = f"[{record.filename}:{record.lineno}]"
        levelname = record.levelname
        levelname_color = self.LEVEL_COLORS.get(levelname, "white")
        record.levelname = colored(levelname, levelname_color)
        log_message = super().format(record)
        record.levelname = levelname
        return log_message


db_logger = logging.getLogger("requests")
db_logger.setLevel(logging.DEBUG)

if not db_logger.handlers:
    db_console_handler = logging.StreamHandler()
    db_console_handler.setLevel(logging.DEBUG)
    db_formatter = DBColoredFormatter(
        "%(combined_info)-20s [%(levelname)-12s] %(message)s"
    )

    db_console_handler.setFormatter(db_formatter)
    db_logger.propagate = False
    db_logger.addHandler(db_console_handler)

parser = argparse.ArgumentParser(
    description="Run the server with optional debug mode.")
parser.add_argument("--debug", action="store_true", help="Run in debug mode")
parser.add_argument("--encrypt", action="store_true", help="Encrypt the files")
args = parser.parse_args()

if args.debug:
    db_logger.setLevel(logging.DEBUG)
elif args.encrypt:
    db_logger.setLevel(logging.CRITICAL)
else:
    db_logger.setLevel(logging.INFO)
