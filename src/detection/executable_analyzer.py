
import platform
from functools import lru_cache

from .models import ImportedFunction


@lru_cache(maxsize=256)
def get_imported_functions(
    executable_path: str
) -> list[ImportedFunction]:

    system = platform.system()

    if system == "Windows":
        return get_pe_imports(executable_path)

    elif system == "Linux":
        return get_elf_imports(executable_path)

    else:
        print(f"[UNSUPPORTED] Operating system: {system}")
        return []


def get_pe_imports(path):
    import pefile

    imports = []

    pe = pefile.PE(path, fast_load=True)

    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        ]
    )

    # Read normal imports
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode(errors="ignore")

        for imported in entry.imports:
            if imported.name:
                api = imported.name.decode(errors="ignore")

                imports.append({
                    "dll": dll,
                    "api": api
                })

    # Read delay-loaded imports
    for entry in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
        dll = entry.dll.decode(errors="ignore")

        for imported in entry.imports:
            if imported.name:
                api = imported.name.decode(errors="ignore")

                imports.append({
                    "dll": dll,
                    "api": api
                })

    pe.close()

    return imports

def get_elf_imports(
    executable_path: str
) -> list[ImportedFunction]:

    from elftools.elf.elffile import ELFFile

    imported_functions = []

    try:
        with open(executable_path, "rb") as file:
            elf = ELFFile(file)

            # Inspect the dynamic symbol table.
            symbol_table = elf.get_section_by_name(".dynsym")

            if symbol_table is None:
                return imported_functions

            for symbol in symbol_table.iter_symbols():

                # Undefined symbols are references to functions
                # that the executable expects from shared libraries.
                if symbol["st_shndx"] == "SHN_UNDEF":

                    function_name = symbol.name

                    if function_name:
                        imported_functions.append(
                            ImportedFunction(
                                dll="ELF",
                                function=function_name
                            )
                        )

    except (
        FileNotFoundError,
        PermissionError,
        OSError,
        ValueError,
    ) as error:
        print(f"[ELF ERROR] {executable_path}: {error}")

    return imported_functions
