import os
import random
import string

from flask import Flask, request, jsonify
from pyspark.sql import SparkSession, Row
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pyspark.conf import SparkConf

from models import Base, FileMetadata, FileType, ArchitectureType, MaliciousType

app = Flask(__name__)

SPARK_SERVICE_URL = os.getenv("SPARK_SERVICE_URL")
# SQLAlchemy database configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

# Create the database tables
Base.metadata.create_all(engine)

if os.getenv("DATA_SOURCE_TYPE") == "s3":
    s3_bucket = os.getenv("DATA_SOURCE_PATH")
    s3_path = f"s3a://{s3_bucket}/0/"

    aws_region = os.getenv("AWS_REGION")
else:
    raise NotImplementedError("Only S3 data source is supported at the moment.")

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
    .set("spark.hadoop.fs.s3a.access.key", os.environ.get("AWS_ACCESS_KEY_ID"))
    .set("spark.hadoop.fs.s3a.secret.key", os.environ.get("AWS_SECRET_KEY"))
    .set(
        "spark.hadoop.fs.s3a.aws.credentials.provider",
        "org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider",
    )
)

spark = SparkSession.builder.config(conf=spark_conf).getOrCreate()
spark.sparkContext.setLogLevel("DEBUG")

PROPERTIES = {
    "user": os.environ.get("SQL_USER"),
    "password": os.environ.get("SQL_PASSWORD"),
    "driver": "org.postgresql.Driver",
}
TABLE_NAME = "files_metadata"


@app.route("/process_files", methods=["POST"])
def process_files():
    try:
        n = int(request.json.get("n"))
        result = f"Processed {n} files successfully."
        return jsonify({"message": result}), 200

    except ValueError:
        return jsonify({"error": "Invalid input. 'n' must be an integer."}), 400


@app.route("/list_files", methods=["GET"])
def list_files():
    try:
        file_list = (
            spark.sparkContext.wholeTextFiles(s3_path).map(lambda x: x[0]).collect()
        )
        for file_path in file_list:
            print(file_path)

        return jsonify({"message": "success"}), 200
    except Exception as e:
        # return jsonify({"error": e.__str__()}), 400
        return jsonify({"error": e}), 400


#  TODO: remove - for development only
def create_random_record(session, i):
    path = "".join(random.choices(string.ascii_letters + string.digits, k=10)) + ".dll"
    size = random.uniform(1.0, 100.0)
    file_type = random.choice([FileType.DLL, FileType.EXE])
    architecture = random.choice([ArchitectureType.x32, ArchitectureType.x64])
    number_of_imports = random.randint(0, 100)
    number_of_exports = random.randint(0, 100)
    hash_sum = "".join(random.choices(string.ascii_letters + string.digits, k=32))
    malicious_type = random.choice([MaliciousType.malicious, MaliciousType.clean])

    new_file = FileMetadata(
        path=path,
        size=size,
        type=file_type,
        architecture=architecture,
        number_of_imports=number_of_imports,
        number_of_exports=number_of_exports,
        hash_sum=hash_sum,
        malicious_type=malicious_type,
    )
    return new_file


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
