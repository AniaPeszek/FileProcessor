from flask import Flask, request, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, FileMetadata, FileType, ArchitectureType, MaliciousType

import random
import string
import os

app = Flask(__name__)

# SQLAlchemy database configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

# Create the database tables
Base.metadata.create_all(engine)


@app.route('/process', methods=['POST'])
def process_files():
    try:
        n = int(request.json.get('n'))
        # TODO: Process n files
        session = Session()
        for i in range(n):
            session.add(create_record(session, i))
        session.commit()

        result = f"Processed {n} files successfully."
        return jsonify({"message": result}), 200
    except ValueError:
        return jsonify({"error": "Invalid input. 'n' must be an integer."}), 400


#  TODO: remove
def create_record(session, i):
    path = ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + '.dll'
    size = random.uniform(1.0, 100.0)
    file_type = random.choice([FileType.DLL, FileType.EXE])
    architecture = random.choice([ArchitectureType.x32, ArchitectureType.x64])
    number_of_imports = random.randint(0, 100)
    number_of_exports = random.randint(0, 100)
    hash_sum = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    malicious_type = random.choice([MaliciousType.malicious, MaliciousType.clean])

    new_file = FileMetadata(
        path=path,
        size=size,
        type=file_type,
        architecture=architecture,
        number_of_imports=number_of_imports,
        number_of_exports=number_of_exports,
        hash_sum=hash_sum,
        malicious_type=malicious_type
    )
    return new_file


# for development
#  TODO: remove
@app.route('/get/<int:id>', methods=['GET'])
def get_object_by_id(id):
    try:
        session = Session()
        obj = session.query(FileMetadata).filter_by(id=id).first()

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
                "malicious_type": obj.malicious_type
            }
            return jsonify(obj_data), 200
        else:
            return jsonify({"error": "Object not found"}), 404
    except ValueError:
        return jsonify({"error": "Invalid input. 'id' must be an integer."}), 400


# for development
#  TODO: remove
@app.route('/get_all', methods=['GET'])
def get_all_objects():
    try:
        session = Session()
        # Query the database for all objects
        all_objects = session.query(FileMetadata).all()

        if all_objects:
            # Create a list of dictionary representations of the objects
            objects_data = []
            for obj in all_objects:
                obj_data = {
                    "id": obj.id,
                    "path": obj.path,
                    "size": obj.size,
                    "type": obj.type,
                    "architecture": obj.architecture,
                    "number_of_imports": obj.number_of_imports,
                    "number_of_exports": obj.number_of_exports,
                    "hash_sum": obj.hash_sum,
                    "malicious_type": obj.malicious_type
                }
                objects_data.append(obj_data)

            return jsonify(objects_data), 200
        else:
            return jsonify({"error": "No objects found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
