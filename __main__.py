import logging
import logging.config
from scan import nmap_scan, httpx_scan
import argparse

logging_configs = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {
            "format": "[%(asctime)s] %(message)s",
        },
    },
    "handlers": {
        "file": {
            "level": "DEBUG",
            "class": "logging.FileHandler",
            "filename": "report.log",
            "formatter": "simple",
            "mode": "w",
        },
        "console": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "formatter": "simple",
        },
    },
    "loggers": {
        "report": {
            "handlers": ["file", "console"],
            "level": "DEBUG",
        },
    },
}
logging.config.dictConfig(logging_configs)


def parser_args():
    parser = argparse.ArgumentParser(description="Scan target IP")

    parser.add_argument("--scan", action="store_true", help="Scan target IP")

    parser.add_argument(
        "--scan_nmap", action="store_true", help="Scan target IP with nmap"
    )

    parser.add_argument(
        "--scan_httpx", action="store_true", help="Scan target IP with httpx"
    )

    parser.add_argument(
        "-t", "--target", type=str, help="Target IP to scan", required=True
    )

    return parser.parse_args()


def main():
    args = parser_args()

    if args.scan:
        nmap_scan(args.target)
        httpx_scan(args.target)
    else:
        if args.scan_nmap:
            nmap_scan(args.target)

        if args.scan_httpx:
            httpx_scan(args.target)


if __name__ == "__main__":
    main()
