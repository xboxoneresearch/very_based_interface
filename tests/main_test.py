from very_based_interface.vbi_file import VbiFile
import os

def run_vbi(vbi_name: str):
    path = f"_data/{vbi_name}.vbi"
    assert os.path.isfile(path), "VBI not found!"

    with open(path, "rb") as f:
        vbi = VbiFile(f)

    vbi.load()
    vbi.dump_files(f"_out/{vbi_name}")

def test_gameos(): run_vbi("gameos")
def test_systemos(): run_vbi("system")
def test_eraos(): run_vbi("vermintide2_era")
def test_gamecore(): run_vbi("gamecore_10.0.19041.4350")
def test_new_gamecore(): run_vbi("gamecore_10.0.22621.4304")
def test_old_era(): run_vbi("era_loader_c0")