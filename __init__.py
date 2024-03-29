from pathlib import Path

MAX_RUCURSION_DEPTH = 5

# URL_GUARD = ("docs", "examples")
URL_GUARD = tuple()

THIS_FOLDER = Path(__file__).parent

REPORTS_FOLDER = THIS_FOLDER.joinpath("reports")
if not REPORTS_FOLDER.exists():
    REPORTS_FOLDER.mkdir()

REPORTS_ZIP_FOLDER = THIS_FOLDER.joinpath("reports_zip")
if not REPORTS_ZIP_FOLDER.exists():
    REPORTS_ZIP_FOLDER.mkdir()


def get_target_folder(target, clear=False):
    def clear_dir(dir):
        if dir.exists():
            for item in dir.iterdir():
                if item.is_dir():
                    clear_dir(item)
                else:
                    item.unlink()
            dir.rmdir()

    if "/" in target:
        target = target.split("/")[0]
    TARGET_FOLDER = REPORTS_FOLDER.joinpath(target)

    if clear and TARGET_FOLDER.exists():
        clear_dir(TARGET_FOLDER)

    if not TARGET_FOLDER.exists():
        TARGET_FOLDER.mkdir()

    return TARGET_FOLDER


TARGET_FOLDER = get_target_folder


def get_protocol_target_folder(target, protocol):
    PROTOCOL_FOLDER = get_target_folder(target).joinpath(protocol)
    if not PROTOCOL_FOLDER.exists():
        PROTOCOL_FOLDER.mkdir()

    return PROTOCOL_FOLDER


PROTOCOL_FOLDER = get_protocol_target_folder
