import os
import subprocess
import tempfile

import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from pyspark.conf import SparkConf
from pyspark.sql import SparkSession, Row
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, ArchitectureType, MaliciousType, MetadataSchema

app = Flask(__name__)

SPARK_SERVICE_URL = os.getenv("SPARK_SERVICE_URL")
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
        print(f"Files to process: {n}")
        file_list = list_all_files(CLEAN_FILES_URL)
        print(file_list)

        # TODO: change to while loop
        for i in range(n):
            print(i)
            print(f"Processing file {file_list[i]}")
            metadata = get_metadata(DATA_SOURCE_PATH, file_list[i])
            if metadata.get("message") == "duplicate":
                print("duplicate")
                continue
            print(metadata)
            result = save_metadata(metadata)
            print(f"result {result}")
            if "error" in result:
                return jsonify({"error": result["error"]}), 500
        return jsonify({"message": f"Processed {n} files successfully."}), 200
    except Exception as e:
        return jsonify({"error": {str(e)}}), 400


# TODO: add caching if possible
def list_all_files(url: str) -> list:
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        links = soup.find_all("a")
        offset = 2  # skip first two links - there are links to dir and parent dir
        return [link.get("href") for link in links if link.get("href")][offset:]
    return []


def is_file_in_db(path: str) -> bool:
    print(f"Checking if {path} is in the database")
    filter_condition = f"path = '{path}'"
    df = spark.read.jdbc(
        JDBC_URL, TABLE_NAME, properties=PROPERTIES, predicates=[filter_condition]
    )
    if df:
        print(f"File {path} already exists in the database.")
        return True
    print(f"File {path} does NOT exist in the database.")
    return False


def get_metadata(url: str, path: str) -> dict:
    if is_file_in_db(url + path):
        return {"message": "duplicate"}
    try:
        response = requests.get(url + path)
        if response.status_code == 200:
            with tempfile.NamedTemporaryFile(dir="/tmp") as f:
                f.write(response.content)
                metadata = subprocess.run(["file", f.name], stdout=subprocess.PIPE)
                metadata = metadata.stdout.decode("utf-8").strip().split(" ")
                size_in_bytes = f.tell()
                # TODO: do I need it?
                sha_id = subprocess.run(["sha256sum", f.name], stdout=subprocess.PIPE)
                sha_id = sha_id.stdout.decode("utf-8").strip().split(" ")[0]

            if len(metadata) > 1:
                architecture = (
                    ArchitectureType.x32.value
                    if "32" in metadata[1]
                    else ArchitectureType.x64.value
                )
            else:
                architecture = None
            file_metadata = {
                "path": url + path,
                "size": int(size_in_bytes),
                "type": path[-3:].upper(),
                "architecture": architecture,
                "number_of_imports": 0,
                "number_of_exports": 0,
                "hash_sum": str(sha_id),
                "malicious_type": MaliciousType.malicious.value
                if path[1] == "1"
                else MaliciousType.clean.value,
            }
            print(file_metadata)
            return file_metadata
        else:
            print(f"Failed to download {url}. Status code: {response.status_code}")
            return {"error": response.status_code}
    except Exception as e:
        print(f"Error downloading {url}: {str(e)}")
        return {"error": {str(e)}}


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
                "message": f"File {metadata['path']} already exists in the database."
            }
        else:
            print(metadata)
            print(str(e))
            return {"error": f"Error saving metadata: {str(e)}"}


#  TODO: remove - for development only
@app.route("/get/<int:id>", methods=["GET"])
def get_object_by_id(id):
    try:
        filter_condition = f"id = {id}"
        df = spark.read.jdbc(
            JDBC_URL, TABLE_NAME, properties=PROPERTIES, predicates=[filter_condition]
        )
        obj = df.first()

        if obj is not None:
            obj_data = {
                "id": obj.id,
                "path": obj.path,
                "size": obj.size,
                "type": obj.type,
                "architecture": obj.architecture,
                "number_of_imports": obj.number_of_imports,
                "number_of_exports": obj.number_of_exports,
                "hash_sum": obj.hash_sum,
                "malicious_type": obj.malicious_type,
            }
            return jsonify(obj_data), 200
        else:
            return jsonify({"error": "Object not found"}), 404
    except ValueError:
        return jsonify({"error": "Invalid input. 'id' must be an integer."}), 400


#  TODO: remove - for development only
@app.route("/get_all", methods=["GET"])
def get_all_objects():
    try:
        df = spark.read.jdbc(JDBC_URL, TABLE_NAME, properties=PROPERTIES)
        if df:
            print(df.show())
            pandas_df = df.toPandas()
            json_result = pandas_df.to_json(orient="records")
            return json_result, 200
        else:
            return jsonify({"error": "No objects found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# TODO: to remove - for development only
@app.route("/list_files", methods=["GET"])
def list_files():
    try:
        url = CLEAN_FILES_URL
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            links = soup.find_all("a")
            for link in links:
                href = link.get("href")
                if href:
                    print(href)
        else:
            return (
                jsonify(
                    {
                        "message": f"Failed to retrieve the page. Status code: {response.status_code}"
                    }
                ),
                response.status_code,
            )
        return jsonify({"message": "success"}), 200
    except Exception as e:
        return jsonify({"error": e.__str__()}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
