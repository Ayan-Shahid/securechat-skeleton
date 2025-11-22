"""SecureChat Database Module - SHA256(salt||password) as per assignment spec."""

import os
from dotenv import load_dotenv
import pymysql

load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "")
DB_NAME = os.getenv("DB_NAME", "securechat")

def get_connection():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )

def create_users_table():
    """Create users table matching assignment spec."""
    conn = get_connection()
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                username VARCHAR(32) UNIQUE NOT NULL,
                salt VARCHAR(64) NOT NULL,
                pwd_hash CHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
        conn.commit()
    print("[*] Users table ready")

def create_database():
    """Create database if not exists."""
    conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS)
    with conn:
        with conn.cursor() as cur:
            cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
    print(f"[*] Database '{DB_NAME}' ready")