from .vbi_file import VbiFile
import typer
from pathlib import Path
from typing_extensions import Annotated

app = typer.Typer()

@app.command()
def extract(vbi_path: 
            Annotated[Path,
                      typer.Argument(help="The path to the VBI file",
                                     exists=True, 
                                     file_okay=True, 
                                     dir_okay=False, 
                                     readable=True, 
                                     writable=False, 
                                     resolve_path=True)], 
            output_folder: 
            Annotated[Path, 
                      typer.Argument(help="The path to extract all files into", 
                                     file_okay=False, 
                                     dir_okay=True, 
                                     writable=True, 
                                     readable=False, 
                                     resolve_path=True)]
                        = "vbi_output"):
    """
    Extracts all files contained within the provided VBI into the specified directory.
    """
    with open(vbi_path, "rb") as f:
        vbi = VbiFile(f)

    vbi.load()
    vbi.dump_files(output_folder)

def main():
    app()

if __name__ == "__main__":
    main()