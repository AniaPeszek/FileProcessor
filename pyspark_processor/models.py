from enum import Enum

from pyspark.sql.types import (
    StructType,
    StructField,
    StringType,
    IntegerType,
)
from sqlalchemy import Column, Integer, String, Enum as SQLAlchemyEnum, Index
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class FileType(str, Enum):
    DLL = "DLL"
    EXE = "EXE"


class ArchitectureType(str, Enum):
    x32 = "x32"
    x64 = "x64"


class MaliciousType(str, Enum):
    malicious = "malicious"
    clean = "clean"


class FileMetadata(Base):
    __tablename__ = "files_metadata"

    id = Column(Integer, primary_key=True)
    path = Column(String, nullable=False, unique=True)
    size = Column(Integer, nullable=False)
    type = Column(SQLAlchemyEnum(FileType), nullable=False)
    architecture = Column(SQLAlchemyEnum(ArchitectureType), nullable=True)
    number_of_imports = Column(Integer, nullable=False)
    number_of_exports = Column(Integer, nullable=False)
    malicious_type = Column(SQLAlchemyEnum(MaliciousType), nullable=False)


MetadataSchema = StructType(
    [
        StructField("path", StringType(), False),
        StructField("size", IntegerType(), False),
        StructField("type", StringType(), True),
        StructField("architecture", StringType(), False),
        StructField("number_of_imports", IntegerType(), False),
        StructField("number_of_exports", IntegerType(), False),
        StructField("malicious_type", StringType(), False),
    ]
)
