import logging
import os
import tempfile

import pefile
import requests
from pyspark.conf import SparkConf
from pyspark.sql import SparkSession, Row
from pyspark.sql.types import StructType, StructField, StringType
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from file import File
from models import Base, MetadataSchema

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# SQLAlchemy database configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

# Create the database tables
Base.metadata.create_all(engine)

PROPERTIES = {
    "user": os.environ.get("SQL_USER"),
    "password": os.environ.get("SQL_PASSWORD"),
    "driver": "org.postgresql.Driver",
    "stringtype": "unspecified",
}
TABLE_NAME = "files_metadata"
DATA_SOURCE_PATH = os.getenv("DATA_SOURCE_PATH")
JDBC_URL = f"jdbc:postgresql://db:5432/{os.environ.get('SQL_DATABASE')}"
spark_conf = (
    SparkConf()
    .setAppName("FileProcessor")
    .set("spark.jars", os.getenv("SPARK_CLASSPATH"))
    .set("spark.sql.catalog.db", "org.apache.spark.sql.jdbc.PostgresCatalog")
    .set("spark.sql.catalog.db.url", JDBC_URL)
    .set("spark.sql.catalog.db.write.jdbc.option.driver", "org.postgresql.Driver")
    .set("spark.sql.catalog.db.write.jdbc.option.url", JDBC_URL)
    .set("spark.sql.catalog.db.write.jdbc.option.user", os.environ.get("SQL_USER"))
    .set(
        "spark.sql.catalog.db.write.jdbc.option.password",
        os.environ.get("SQL_PASSWORD"),
    )
)

spark = SparkSession.builder.config(conf=spark_conf).getOrCreate()
spark.sparkContext.setLogLevel("INFO")

schema = StructType([StructField("path", StringType(), True)])
stream = (
    spark.readStream.option("sep", ",")
    .option("cleanSource", "delete")
    .schema(schema)
    .csv("/stream")
)


def process_file(row):
    logger.debug(f"Processing file {row['path']}")
    metadata = get_metadata(DATA_SOURCE_PATH, row["path"])
    if metadata.get("warning"):
        logger.warning(metadata.get("warning"))
        return
    logger.info(metadata)
    result = save_metadata(metadata)
    logger.info(f"result {result}")
    if "error" in result:
        logger.error(result["error"])


def is_file_in_db(path: str) -> bool:
    logger.debug(f"Checking if {path} is in the database")
    filter_condition = f"path = '{path}'"
    df = spark.read.jdbc(
        JDBC_URL, TABLE_NAME, properties=PROPERTIES, predicates=[filter_condition]
    )
    if df.first():
        logger.debug(f"File {path} already exists in the database.")
        return True
    logger.debug(f"File {path} does NOT exist in the database.")
    return False


def get_metadata(url: str, path: str) -> dict:
    if is_file_in_db(url + path):
        return {"warning": "duplicate"}
    try:
        logger.debug(f"Downloading {url + path}")
        response = requests.get(url + path)
        if response.status_code == 200:
            with tempfile.NamedTemporaryFile(dir="/tmp") as f:
                f.write(response.content)
                try:
                    pe = pefile.PE(f.name)
                except pefile.PEFormatError as e:
                    logger.error(f"Error parsing {path}: {str(e)}")
                    return {"warning": f"parsing error"}

            file = File(pe, url + path, is_malicious=path[1] == "1")
            if file.architecture:
                return file.get_metadata()
            return {"warning": "architecture not in scope"}
        else:
            logger.error(
                f"Failed to download {url}. Status code: {response.status_code}"
            )
            return {"error": response.status_code}
    except Exception as e:
        logger.error(f"Error downloading {url + path}: {str(e)}")
        return {"error": f"Error downloading {url + path}: {str(e)}"}


def save_metadata(metadata: dict) -> dict:
    try:
        if "error" not in metadata:
            metadata_df = spark.createDataFrame(
                [Row(**metadata)], schema=MetadataSchema
            )
            metadata_df.write.jdbc(
                JDBC_URL, TABLE_NAME, properties=PROPERTIES, mode="append"
            )
            return {"success": metadata}
        else:
            return {"error": metadata["error"]}
    except Exception as e:
        if "ERROR: duplicate key value violates unique constraint" in str(e):
            return {
                "warning": f"File {metadata['path']} already exists in the database."
            }
        else:
            logger.error(str(e))
            return {"error": f"Error saving metadata: {str(e)}"}


def foreach_batch_function(df, _):
    batch_df = df.select("path")
    paths = batch_df.collect()
    for path in paths:
        process_file(path)


if __name__ == "__main__":
    query = stream.writeStream.foreachBatch(foreach_batch_function).start()
    spark.streams.awaitAnyTermination()
