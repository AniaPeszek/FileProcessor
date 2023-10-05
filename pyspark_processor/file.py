import pefile
from models import ArchitectureType, MaliciousType


class File:
    def __init__(self, pe: pefile.PE, path: str):
        self.pe = pe
        self.path = path
        self.size = pe.OPTIONAL_HEADER.SizeOfImage
        self.architecture = self.get_file_architecture()
        self.number_of_imports = self.get_number_of_imports()
        self.number_of_exports = self.get_number_of_exports()

    def get_metadata(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "type": self.path[-3:].upper(),
            "architecture": self.architecture,
            "number_of_imports": self.number_of_imports,
            "number_of_exports": self.number_of_exports,
            "malicious_type": MaliciousType.malicious.value
            if self.path[1] == "1"
            else MaliciousType.clean.value,
        }

    def get_file_architecture(self) -> ArchitectureType:
        if (
            self.pe.FILE_HEADER.Machine
            == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]
        ):
            return ArchitectureType.x32.value
        if (
            self.pe.FILE_HEADER.Machine
            == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
        ):
            return ArchitectureType.x64.value
        return None

    def get_number_of_imports(self) -> int:
        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return len(self.pe.DIRECTORY_ENTRY_IMPORT)
        return 0

    def get_number_of_exports(self) -> int:
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            return len(self.pe.DIRECTORY_ENTRY_EXPORT.symbols)
        return 0
