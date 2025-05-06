from very_based_interface.vbi_file import VbiFile
from pathlib import Path

BASE_DATA_DIRECTORY = Path("_data")
BASE_OUT_DIRECTORY = Path("_out")


def run_vbi(vbi_name: str):
    path = BASE_DATA_DIRECTORY / f"{vbi_name}.vbi"
    assert path.is_file() and path.exists(), "VBI not found!"

    with open(path, "rb") as f:
        vbi = VbiFile(f)

    vbi.load()
    vbi.dump_files(BASE_OUT_DIRECTORY / vbi_name, skip_writing=True)


def test_gameos():
    run_vbi("gameos")


def test_systemos():
    run_vbi("system")


def test_eraos():
    run_vbi("vermintide2_era")


def test_gamecore():
    run_vbi("gamecore_10.0.19041.4350")


def test_new_gamecore():
    run_vbi("gamecore_10.0.22621.4304")


def test_old_era():
    run_vbi("era_loader_c0")


if __name__ == "__main__":
    test_old_era()
