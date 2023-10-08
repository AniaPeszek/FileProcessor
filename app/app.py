import datetime
import logging
import math
import os
import random
import string

import pandas as pd
from flask import Flask, request, jsonify

from paths_df import PathsDataFrame

app = Flask(__name__)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

paths_to_safe_files = PathsDataFrame(is_safe=True)
paths_to_malware = PathsDataFrame(is_safe=False)


@app.route("/process", methods=["POST"])
def process_files():
    try:
        n = int(request.json.get("n"))
        task = math.ceil(n / 2)
        real_batch_size = 0

        for path in [paths_to_safe_files, paths_to_malware]:
            if path.files_df.empty:
                logger.debug("Loading paths...")
                path.load_df()

            logger.debug("Saving tasks...")
            batch_df = path.files_df.head(task)
            real_batch_size += batch_df.shape[0]
            random_string = "".join(
                random.choice(string.ascii_letters) for _ in range(5)
            )
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            batch_df.to_csv(
                f"/stream/path_list_{timestamp}_{random_string}.csv",
                index=False,
                header=False,
            )
            path.files_df = path.files_df.tail(path.files_df.shape[0] - task)
        return jsonify({"message": f"Task for {real_batch_size} files created."}), 200
    except ValueError:
        return jsonify({"error": "Invalid input. 'n' must be an integer."}), 400
    except Exception as e:
        logger.error(e)
        return jsonify({"error": f"{str(e)}"}), 500


@app.route("/upload", methods=["POST"])
def upload_txt_file():
    """
    In file should be only links to files, one per line. The same vales that are in "href" attribute in data source.
    """
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file part in the request."}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected."}), 400

        if file:
            if not os.path.splitext(file.filename)[1] == ".txt":
                return jsonify({"error": "Invalid file extension."}), 400
            file.save(f"/uploads/{file.filename}")
            task = create_task_from_file(f"/uploads/{file.filename}")
            return (
                jsonify({"message": f"File uploaded successfully. Task size: {task}"}),
                200,
            )
    except Exception as e:
        logger.error(e)
        return jsonify({"error": f"{str(e)}"}), 500


def create_task_from_file(filepath: str) -> int:
    with open(filepath) as file:
        lines = file.readlines()
    batch_df = pd.DataFrame({"path": lines})
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    random_string = "".join(random.choice(string.ascii_letters) for _ in range(5))
    batch_df.to_csv(
        f"/stream/path_list_{timestamp}_{random_string}.csv",
        index=False,
        header=False,
    )
    return batch_df.shape[0]


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
