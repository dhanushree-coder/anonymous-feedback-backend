import mysql.connector
import os

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("yamanote.proxy.rlwy.net"),
        user=os.getenv("root"),
        password=os.getenv("rPwaOSqIAnqPGlZaArBxSCwURjqaDQFt"),
        database=os.getenv("railway"),
        port=int(os.getenv("17639"))
    )
