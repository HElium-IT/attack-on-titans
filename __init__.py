from pathlib import Path

THIS_FOLDER = Path(__file__).parent

REPORTS_FOLDER = THIS_FOLDER.joinpath("reports")
if not REPORTS_FOLDER.exists():
    REPORTS_FOLDER.mkdir()


def get_target_folder(target):
    TARGET_FOLDER = REPORTS_FOLDER.joinpath(target)
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
