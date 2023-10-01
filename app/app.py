import os

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

SPARK_SERVICE_URL = os.getenv("SPARK_SERVICE_URL")


@app.route("/process", methods=["POST"])
def process_files():
    try:
        n = int(request.json.get("n"))
        response = requests.post(f"{SPARK_SERVICE_URL}/process_files", json={"n": n})

        if response.status_code == 200:
            result = f"Processed {n} files successfully."
            return jsonify({"message": result}), 200
        else:
            return jsonify({"error": "Error processing data in PySpark"}), 500
    except ValueError:
        return jsonify({"error": "Invalid input. 'n' must be an integer."}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
