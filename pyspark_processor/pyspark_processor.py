import logging
import os
import tempfile

import pefile
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from pyspark.conf import SparkConf
from pyspark.sql import SparkSession, Row
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from file import File
from models import Base, MetadataSchema

app = Flask(__name__)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# SQLAlchemy database configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

# Create the database tables
Base.metadata.create_all(engine)

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

PROPERTIES = {
    "user": os.environ.get("SQL_USER"),
    "password": os.environ.get("SQL_PASSWORD"),
    "driver": "org.postgresql.Driver",
    "stringtype": "unspecified",
}
TABLE_NAME = "files_metadata"
DATA_SOURCE_PATH = os.getenv("DATA_SOURCE_PATH")
CLEAN_FILES_URL = DATA_SOURCE_PATH + "/0/00Tree.html"
MALWARE_FILES_URL = DATA_SOURCE_PATH + "/1/00Tree.html"


@app.route("/process_files", methods=["POST"])
def process_files():
    try:
        n = int(request.json.get("n"))
        logger.debug(f"Files to process: {n}")
        file_list = list_all_files(CLEAN_FILES_URL)

        # TODO: to change
        for i in range(n):
            logger.debug(f"Processing file {file_list[i]}")
            metadata = get_metadata(DATA_SOURCE_PATH, file_list[i])
            if metadata.get("warning"):
                logger.debug("skip")
                continue
            logger.debug(metadata)
            result = save_metadata(metadata)
            logger.debug(f"result {result}")
            if "error" in result:
                return jsonify({"error": result["error"]}), 500
        return jsonify({"message": f"Processed {n} files successfully."}), 200
    except Exception as e:
        return jsonify({"error": {str(e)}}), 400


# TODO: change to stream
def list_all_files(url: str) -> list:
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        links = soup.find_all("a")
        offset = 2  # skip first two links - there are links to dir and parent dir
        return [link.get("href") for link in links if link.get("href")][offset:]
    return []


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

            file = File(pe, url + path)
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
