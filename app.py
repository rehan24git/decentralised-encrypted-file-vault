from flask import Flask, render_template, request, redirect, url_for, session, send_file
import sqlite3
import os
import io
import requests

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from cryptography.fernet import Fernet


app = Flask(__name__)


# =========================
# APPLICATION SETTINGS
# =========================

app.secret_key = os.environ.get("SECRET_KEY", "vaultx_secret_key_123")

UPLOAD_FOLDER = "storage"
DATABASE = "vaultx.db"
KEY_FILE = "vaultx.key"

# Storage Node addresses
NODE1_URL = "http://127.0.0.1:5001"
NODE2_URL = "http://127.0.0.1:5002"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Maximum upload size: 50 MB
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024


# =========================
# CREATE STORAGE FOLDER
# =========================

if not os.path.exists(UPLOAD_FOLDER):

    os.makedirs(UPLOAD_FOLDER)


# =========================
# ENCRYPTION KEY
# =========================

def get_encryption_key():

    if not os.path.exists(KEY_FILE):

        key = Fernet.generate_key()

        with open(KEY_FILE, "wb") as key_file:

            key_file.write(key)

    else:

        with open(KEY_FILE, "rb") as key_file:

            key = key_file.read()

    return key


# =========================
# DATABASE CONNECTION
# =========================

def get_db():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    return connection


# =========================
# CREATE DATABASE
# =========================

def create_database():

    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            email TEXT UNIQUE NOT NULL,

            password TEXT NOT NULL

        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS files (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL,

            original_name TEXT NOT NULL,

            stored_name TEXT NOT NULL,

            file_size INTEGER NOT NULL,

            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id) REFERENCES users(id)

        )
    """)

    connection.commit()

    connection.close()


# =========================
# CHECK NODE 1 STATUS
# =========================

def check_node1():

    try:

        response = requests.get(
            NODE1_URL + "/status",
            timeout=2
        )

        if response.status_code == 200:

            node_data = response.json()

            return {
                "online": True,
                "node_id": node_data.get(
                    "node_id",
                    "node1"
                ),
                "stored_files": node_data.get(
                    "stored_files",
                    0
                )
            }

    except requests.RequestException:

        pass


    return {
        "online": False,
        "node_id": "node1",
        "stored_files": 0
    }


# =========================
# CHECK NODE 2 STATUS
# =========================

def check_node2():

    try:

        response = requests.get(
            NODE2_URL + "/status",
            timeout=2
        )

        if response.status_code == 200:

            node_data = response.json()

            return {
                "online": True,
                "node_id": node_data.get(
                    "node_id",
                    "node2"
                ),
                "stored_files": node_data.get(
                    "stored_files",
                    0
                )
            }

    except requests.RequestException:

        pass


    return {
        "online": False,
        "node_id": "node2",
        "stored_files": 0
    }


# =========================
# LOGIN PAGE
# =========================

@app.route("/")
def login_page():

    return render_template("login.html")


# =========================
# REGISTER PAGE
# =========================

@app.route("/register")
def register_page():

    return render_template("register.html")


# =========================
# REGISTER USER
# =========================

@app.route("/register", methods=["POST"])
def register():

    email = request.form["email"].strip()

    password = request.form["password"]

    hashed_password = generate_password_hash(
        password
    )

    connection = get_db()

    try:

        connection.execute(
            """
            INSERT INTO users
            (
                email,
                password
            )

            VALUES (?, ?)
            """,

            (
                email,
                hashed_password
            )
        )

        connection.commit()

    except sqlite3.IntegrityError:

        connection.close()

        return "This email is already registered."

    connection.close()

    return redirect(
        url_for("login_page")
    )


# =========================
# LOGIN USER
# =========================

@app.route("/login", methods=["POST"])
def login():

    email = request.form["email"].strip()

    password = request.form["password"]

    connection = get_db()

    user = connection.execute(
        """
        SELECT *

        FROM users

        WHERE email = ?
        """,

        (email,)
    ).fetchone()

    if not user:

        connection.close()

        return "Invalid email or password."


    password_is_correct = check_password_hash(
        user["password"],
        password
    )


    # Upgrade old plain-text test account

    if (
        not password_is_correct
        and user["password"] == password
    ):

        new_hashed_password = generate_password_hash(
            password
        )

        connection.execute(
            """
            UPDATE users

            SET password = ?

            WHERE id = ?
            """,

            (
                new_hashed_password,
                user["id"]
            )
        )

        connection.commit()

        password_is_correct = True


    connection.close()


    if password_is_correct:

        session["user_id"] = user["id"]

        session["email"] = user["email"]

        return redirect(
            url_for("dashboard")
        )


    return "Invalid email or password."


# =========================
# DASHBOARD
# =========================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        return redirect(
            url_for("login_page")
        )


    connection = get_db()

    files = connection.execute(
        """
        SELECT *

        FROM files

        WHERE user_id = ?

        ORDER BY uploaded_at DESC
        """,

        (
            session["user_id"],
        )
    ).fetchall()

    connection.close()


    total_files = len(files)


    total_size = sum(
        file["file_size"]
        for file in files
    )


    total_size_mb = round(
        total_size / (1024 * 1024),
        2
    )


    # =========================
    # CHECK BOTH NODES
    # =========================

    node1 = check_node1()

    node2 = check_node2()


    # Count online nodes

    network_nodes = 0


    if node1["online"]:

        network_nodes += 1


    if node2["online"]:

        network_nodes += 1


    # Overall network status

    if network_nodes > 0:

        network_status = "Online"

    else:

        network_status = "Offline"


    return render_template(

        "dashboard.html",

        email=session["email"],

        files=files,

        total_files=total_files,

        total_size_mb=total_size_mb,

        network_nodes=network_nodes,

        network_status=network_status,

        node1=node1,

        node2=node2
    )


# =========================
# UPLOAD FILE
# =========================

@app.route("/upload", methods=["POST"])
def upload_file():

    if "user_id" not in session:

        return redirect(
            url_for("login_page")
        )


    if "file" not in request.files:

        return redirect(
            url_for("dashboard")
        )


    file = request.files["file"]


    if file.filename == "":

        return redirect(
            url_for("dashboard")
        )


    original_name = secure_filename(
        file.filename
    )


    if original_name == "":

        return redirect(
            url_for("dashboard")
        )


    # =========================
    # READ ORIGINAL FILE
    # =========================

    file_data = file.read()


    # =========================
    # ENCRYPT FILE
    # =========================

    encryption_key = get_encryption_key()

    cipher = Fernet(encryption_key)

    encrypted_data = cipher.encrypt(
        file_data
    )


    # =========================
    # CREATE UNIQUE FILE NAME
    # =========================

    stored_name = (

        str(session["user_id"])

        + "_"

        + str(
            os.urandom(16).hex()
        )

        + ".vault"
    )


    stored_path = os.path.join(

        app.config["UPLOAD_FOLDER"],

        stored_name
    )


    # =========================
    # SAVE ENCRYPTED FILE LOCALLY
    # =========================

    with open(
        stored_path,
        "wb"
    ) as encrypted_file:

        encrypted_file.write(
            encrypted_data
        )


    # ==================================================
    # SEND ENCRYPTED FILE TO NODE 1
    # ==================================================

    try:

        with open(
            stored_path,
            "rb"
        ) as encrypted_file:

            response = requests.post(

                NODE1_URL + "/store",

                files={
                    "file": (
                        stored_name,
                        encrypted_file,
                        "application/octet-stream"
                    )
                },

                timeout=10
            )


        if response.status_code == 200:

            print("================================")
            print("Node 1: File stored successfully")
            print("File:", stored_name)
            print(
                "Response:",
                response.json()
            )
            print("================================")

        else:

            print("Node 1: Storage failed")
            print(
                "Status code:",
                response.status_code
            )


    except requests.RequestException as error:

        print("================================")
        print("Node 1 connection failed")
        print("Error:", error)
        print("================================")


    # ==================================================
    # SEND ENCRYPTED FILE TO NODE 2
    # ==================================================

    try:

        with open(
            stored_path,
            "rb"
        ) as encrypted_file:

            response = requests.post(

                NODE2_URL + "/store",

                files={
                    "file": (
                        stored_name,
                        encrypted_file,
                        "application/octet-stream"
                    )
                },

                timeout=10
            )


        if response.status_code == 200:

            print("================================")
            print("Node 2: File stored successfully")
            print("File:", stored_name)
            print(
                "Response:",
                response.json()
            )
            print("================================")

        else:

            print("Node 2: Storage failed")
            print(
                "Status code:",
                response.status_code
            )


    except requests.RequestException as error:

        print("================================")
        print("Node 2 connection failed")
        print("Error:", error)
        print("================================")


    # =========================
    # SAVE FILE METADATA
    # =========================

    connection = get_db()

    connection.execute(
        """
        INSERT INTO files
        (
            user_id,
            original_name,
            stored_name,
            file_size
        )

        VALUES (?, ?, ?, ?)
        """,

        (
            session["user_id"],
            original_name,
            stored_name,
            len(file_data)
        )
    )

    connection.commit()

    connection.close()


    return redirect(
        url_for("dashboard")
    )


# =========================
# DOWNLOAD / DECRYPT FILE
# =========================

@app.route("/download/<int:file_id>")
def download_file(file_id):

    if "user_id" not in session:

        return redirect(
            url_for("login_page")
        )


    connection = get_db()

    file_record = connection.execute(
        """
        SELECT *

        FROM files

        WHERE id = ?

        AND user_id = ?
        """,

        (
            file_id,
            session["user_id"]
        )
    ).fetchone()

    connection.close()


    if not file_record:

        return "File not found."


    stored_path = os.path.join(

        app.config["UPLOAD_FOLDER"],

        file_record["stored_name"]
    )


    if not os.path.exists(
        stored_path
    ):

        return "Encrypted file is missing."


    # =========================
    # READ ENCRYPTED FILE
    # =========================

    with open(
        stored_path,
        "rb"
    ) as encrypted_file:

        encrypted_data = encrypted_file.read()


    # =========================
    # DECRYPT
    # =========================

    encryption_key = get_encryption_key()

    cipher = Fernet(
        encryption_key
    )

    decrypted_data = cipher.decrypt(
        encrypted_data
    )


    return send_file(

        io.BytesIO(
            decrypted_data
        ),

        as_attachment=True,

        download_name=file_record[
            "original_name"
        ]
    )


# =========================
# DELETE FILE
# =========================

@app.route(
    "/delete/<int:file_id>",
    methods=["POST"]
)
def delete_file(file_id):

    if "user_id" not in session:

        return redirect(
            url_for("login_page")
        )


    connection = get_db()

    file_record = connection.execute(
        """
        SELECT *

        FROM files

        WHERE id = ?

        AND user_id = ?
        """,

        (
            file_id,
            session["user_id"]
        )
    ).fetchone()


    if not file_record:

        connection.close()

        return "File not found."


    stored_path = os.path.join(

        app.config["UPLOAD_FOLDER"],

        file_record["stored_name"]
    )


    if os.path.exists(
        stored_path
    ):

        os.remove(
            stored_path
        )


    connection.execute(
        """
        DELETE FROM files

        WHERE id = ?

        AND user_id = ?
        """,

        (
            file_id,
            session["user_id"]
        )
    )

    connection.commit()

    connection.close()


    return redirect(
        url_for("dashboard")
    )


# =========================
# LOGOUT
# =========================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login_page")
    )


# =========================
# START APPLICATION
# =========================

if __name__ == "__main__":

    create_database()

    get_encryption_key()

    app.run(
        debug=True
    )
