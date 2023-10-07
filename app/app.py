import datetime
import logging
import math
import os
import random
import string

from flask import Flask, request, jsonify

from paths_df import PathsDataFrame

app = Flask(__name__)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

SPARK_SERVICE_URL = os.getenv("SPARK_SERVICE_URL")

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
                f"/stream/file_list_{timestamp}_{random_string}.csv",
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
