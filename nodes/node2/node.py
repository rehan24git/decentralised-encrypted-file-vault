import os
from flask import Flask, request, jsonify

app = Flask(__name__)

NODE_ID = "node2"
NODE_PORT = 5002

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NODE_STORAGE = os.path.join(BASE_DIR, "node_storage")

if not os.path.exists(NODE_STORAGE):
    os.makedirs(NODE_STORAGE)

@app.route("/")
def node_home():
    return jsonify({
        "node_id": NODE_ID,
        "status": "online",
        "message": "Storage node is running"
    })

@app.route("/status")
def node_status():
    files = os.listdir(NODE_STORAGE)
    return jsonify({
        "node_id": NODE_ID,
        "status": "online",
        "stored_files": len(files)
    })

@app.route("/store", methods=["POST"])
def store_file():
    if "file" not in request.files:
        return jsonify({
            "success": False,
            "message": "No file received"
        }), 400

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":
        return jsonify({
            "success": False,
            "message": "Empty filename"
        }), 400

    filename = os.path.basename(uploaded_file.filename)
    file_path = os.path.join(NODE_STORAGE, filename)

    uploaded_file.save(file_path)

    return jsonify({
        "success": True,
        "node_id": NODE_ID,
        "filename": filename,
        "message": "Encrypted file stored successfully"
    })

@app.route("/files")
def list_files():
    files = []

    for filename in os.listdir(NODE_STORAGE):
        file_path = os.path.join(NODE_STORAGE, filename)

        if os.path.isfile(file_path):
            files.append({
                "filename": filename,
                "size": os.path.getsize(file_path)
            })

    return jsonify({
        "node_id": NODE_ID,
        "files": files
    })

if __name__ == "__main__":
    print("--------------------------------")
    print("VaultX Storage Node")
    print("--------------------------------")
    print("Node ID :", NODE_ID)
    print("Port    :", NODE_PORT)
    print("Storage :", NODE_STORAGE)
    print("Status  : ONLINE")
    print("--------------------------------")

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", NODE_PORT)),
        debug=False
    )