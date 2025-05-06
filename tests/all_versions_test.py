from very_based_interface.vbi_file import VbiFile
from pathlib import Path

BASE_DATA_DIRECTORY = Path("_data")
BASE_OUT_DIRECTORY = Path("_out")


def test_all_versions(skip_writing=True):
    all_versions_folder = BASE_DATA_DIRECTORY / "all_versions"
    all_versions_output = BASE_OUT_DIRECTORY / "all_versions"

    failed = False
    for vbi_file in all_versions_folder.iterdir():
        vbi_file_name = vbi_file.with_suffix("").name
        version, os_type, os_version = vbi_file_name.split("_")
        version = int(version[1:])  # v?
        if version != 1:
            continue

        with vbi_file.open("rb") as f:
            vbi = VbiFile(f)

        try:
            vbi.load()
            vbi.dump_files(
                all_versions_output / vbi_file_name, skip_writing=skip_writing
            )
        except Exception as ex:
            print(f"Failed to load {os_type} {os_version} {version} VBI.")
            print(ex)
            failed = True

    assert not failed


if __name__ == "__main__":
    test_all_versions(False)
