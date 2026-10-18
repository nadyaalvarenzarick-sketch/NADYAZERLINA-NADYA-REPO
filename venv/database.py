"""Fungsi untuk membaca pengaturan dan membuat koneksi ke database."""

import os
import mysql.connector
from dotenv import load_dotenv

# Memuat konfigurasi dari file .env
load_dotenv()


def get_db_connection():
    """Membuat koneksi ke database MySQL."""

    return mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "root"),
        password=os.getenv("MYSQL_PASSWORD", ""),
        database=os.getenv("MYSQL_DATABASE", "db_perpustakaan")
    )