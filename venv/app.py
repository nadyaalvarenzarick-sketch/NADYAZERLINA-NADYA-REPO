import os
from functools import wraps
from datetime import date

import mysql.connector
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

# Memakai folder template sesuai struktur proyek asli.
app = Flask(__name__, template_folder="../template", static_folder="../static")
app.secret_key = os.getenv("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY belum diatur di file .env")


# =========================
# KONEKSI DATABASE
# =========================
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "root"),
        password=os.getenv("MYSQL_PASSWORD", ""),
        database=os.getenv("MYSQL_DATABASE", "db_perpustakaan")
    )


# =========================
# MEMBUAT ADMIN AWAL
# =========================
def init_admin():
    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD")

    if not password:
        raise RuntimeError("ADMIN_PASSWORD belum diatur di file .env")

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM admin WHERE username = %s", (username,))
        if cur.fetchone() is None:
            cur.execute(
                "INSERT INTO admin (username, password) VALUES (%s, %s)",
                (username, generate_password_hash(password))
            )
            conn.commit()
    finally:
        cur.close()
        conn.close()


# =========================
# PELINDUNG SESSION DAN ROLE
# =========================
def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if "role" not in session:
            flash("Silakan login terlebih dahulu.", "warning")
            return redirect(url_for("login"))
        return route_function(*args, **kwargs)
    return wrapper


def role_required(role):
    def decorator(route_function):
        @wraps(route_function)
        def wrapper(*args, **kwargs):
            if "role" not in session:
                flash("Silakan login terlebih dahulu.", "warning")
                return redirect(url_for("login"))
            if session.get("role") != role:
                flash("Kamu tidak memiliki akses ke halaman ini.", "danger")
                return redirect(url_for("dashboard"))
            return route_function(*args, **kwargs)
        return wrapper
    return decorator


# =========================
# LOGIN ADMIN DAN USER
# =========================
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if "role" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username dan password wajib diisi.", "danger")
            return render_template("login.html")

        conn = None
        cur = None
        database_aktif = "tidak diketahui"
        admin = None
        user = None

        try:
            conn = get_db_connection()
            database_aktif = conn.database
            cur = conn.cursor(dictionary=True)

            cur.execute(
                "SELECT id, username, password FROM admin WHERE username = %s",
                (username,)
            )
            admin = cur.fetchone()

            if admin and check_password_hash(admin["password"], password):
                session.clear()
                session["admin_id"] = admin["id"]
                session["username"] = admin["username"]
                session["role"] = "admin"
                return redirect(url_for("dashboard"))

            cur.execute(
                """
                SELECT id, nama, username, password
                FROM users
                WHERE username = %s
                """,
                (username,)
            )
            user = cur.fetchone()

            if user and check_password_hash(user["password"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["nama"] = user["nama"]
                session["username"] = user["username"]
                session["role"] = "user"
                return redirect(url_for("dashboard"))

            app.logger.warning(
                "DIAGNOSIS LOGIN | database=%s | admin_ditemukan=%s | "
                "user_ditemukan=%s",
                database_aktif, admin is not None, user is not None
            )
            flash("Username atau password salah.", "danger")

        except mysql.connector.Error:
            app.logger.exception("Terjadi kesalahan database saat login.")
            flash("Terjadi kesalahan pada database.", "danger")
        finally:
            if cur is not None:
                cur.close()
            if conn is not None:
                conn.close()

    return render_template("login.html")


# =========================
# REGISTER USER
# =========================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nama = request.form.get("nama", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        konfirmasi = request.form.get("konfirmasi_password", "")

        if not nama or not username or not password or not konfirmasi:
            flash("Semua data wajib diisi.", "danger")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password minimal 8 karakter.", "danger")
            return render_template("register.html")

        if password != konfirmasi:
            flash("Konfirmasi password tidak cocok.", "danger")
            return render_template("register.html")

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Periksa username pada tabel admin
            cur.execute(
                "SELECT id FROM admin WHERE username = %s",
                (username,)
            )
            if cur.fetchone():
                flash("Username sudah digunakan.", "danger")
                return render_template("register.html")

            # Periksa username pada tabel users
            cur.execute(
                "SELECT id FROM users WHERE username = %s",
                (username,)
            )
            if cur.fetchone():
                flash("Username sudah digunakan.", "danger")
                return render_template("register.html")

            # Otomatis simpan akun sekaligus data pengguna
            cur.execute(
                """
                INSERT INTO users (nama, username, password)
                VALUES (%s, %s, %s)
                """,
                (
                    nama,
                    username,
                    generate_password_hash(password)
                )
            )

            conn.commit()

            flash(
                "Registrasi berhasil! Silakan login.",
                "success"
            )
            return redirect(url_for("login"))

        except mysql.connector.Error:
            conn.rollback()
            app.logger.exception("Registrasi pengguna gagal.")
            flash("Registrasi gagal. Periksa database.", "danger")

        finally:
            cur.close()
            conn.close()

    return render_template("register.html")


# =========================
# REGISTER ADMIN (HANYA ADMIN YANG SUDAH LOGIN)
# =========================
@app.route("/register-admin", methods=["GET", "POST"])
@role_required("admin")
def register_admin():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        konfirmasi_password = request.form.get("konfirmasi_password", "")

        if not username or not password or not konfirmasi_password:
            flash("Semua data wajib diisi.", "danger")
            return render_template("register_admin.html")
        if len(password) < 8:
            flash("Password minimal 8 karakter.", "danger")
            return render_template("register_admin.html")
        if password != konfirmasi_password:
            flash("Konfirmasi password tidak cocok.", "danger")
            return render_template("register_admin.html")

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT id FROM admin WHERE username = %s", (username,))
            if cur.fetchone() is not None:
                flash("Username sudah digunakan.", "danger")
                return render_template("register_admin.html")
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cur.fetchone() is not None:
                flash("Username sudah digunakan.", "danger")
                return render_template("register_admin.html")

            cur.execute(
                "INSERT INTO admin (username, password) VALUES (%s, %s)",
                (username, generate_password_hash(password))
            )
            conn.commit()
        except mysql.connector.Error:
            conn.rollback()
            app.logger.exception("Pembuatan akun admin gagal.")
            flash("Gagal membuat akun admin. Periksa database.", "danger")
            return render_template("register_admin.html")
        finally:
            cur.close()
            conn.close()

        flash("Akun admin baru berhasil dibuat.", "success")
        return redirect(url_for("dashboard"))

    return render_template("register_admin.html")


# =========================
# DASHBOARD GABUNGAN ADMIN DAN USER
# =========================
@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT COUNT(*) AS total FROM buku")
        total_buku = cur.fetchone()["total"]

        cur.execute("SELECT COALESCE(SUM(stok), 0) AS total FROM buku")
        total_stok = cur.fetchone()["total"]

        cur.execute(
            "SELECT id, judul, penerbit, stok FROM buku "
            "WHERE stok > 0 ORDER BY judul"
        )
        buku_tersedia = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    return render_template(
        "dashboard.html",
        role=session.get("role"),
        nama=session.get("nama", session.get("username", "")),
        total_buku=total_buku,
        total_stok=total_stok,
        buku_tersedia=buku_tersedia
    )


# =========================
# DAFTAR BUKU (ADMIN DAN USER)
# =========================
@app.route("/buku")
@login_required
def daftar_buku():
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM buku ORDER BY id DESC")
        daftar = cur.fetchall()
    finally:
        cur.close()
        conn.close()
    return render_template("buku.html", daftar=daftar, role=session.get("role"))


# =========================
# TAMBAH BUKU (ADMIN SAJA)
# =========================
@app.route("/buku/tambah", methods=["GET", "POST"])
@role_required("admin")
def tambah_buku():
    if request.method == "POST":
        judul = request.form.get("judul", "").strip()
        penulis = request.form.get("penulis", "").strip()
        penerbit = request.form.get("penerbit", "").strip()

        try:
            tahun = int(request.form.get("tahun_terbit", ""))
            stok = int(request.form.get("stok", ""))
            if (
                not judul or not penulis or not penerbit
                or not 1901 <= tahun <= 2155 or stok < 0
            ):
                raise ValueError
        except ValueError:
            flash("Periksa kembali data buku yang dimasukkan.", "danger")
            return render_template(
                "form_buku.html", buku=None, tahun_sekarang=date.today().year
            )

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO buku (judul, penulis, penerbit, tahun_terbit, stok)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (judul, penulis, penerbit, tahun, stok)
            )
            conn.commit()
        finally:
            cur.close()
            conn.close()

        flash("Buku berhasil ditambahkan.", "success")
        return redirect(url_for("daftar_buku"))

    return render_template(
        "form_buku.html", buku=None, tahun_sekarang=date.today().year
    )


# =========================
# EDIT BUKU (ADMIN SAJA)
# =========================
@app.route("/buku/edit/<int:id>", methods=["GET", "POST"])
@role_required("admin")
def edit_buku(id):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM buku WHERE id = %s", (id,))
        buku = cur.fetchone()

        if buku is None:
            flash("Buku tidak ditemukan.", "warning")
            return redirect(url_for("daftar_buku"))

        if request.method == "POST":
            judul = request.form.get("judul", "").strip()
            penulis = request.form.get("penulis", "").strip()
            penerbit = request.form.get("penerbit", "").strip()
            try:
                tahun = int(request.form.get("tahun_terbit", ""))
                stok = int(request.form.get("stok", ""))
                if (
                    not judul or not penulis or not penerbit
                    or not 1901 <= tahun <= 2155 or stok < 0
                ):
                    raise ValueError
            except ValueError:
                flash("Periksa kembali data buku.", "danger")
                return render_template(
                    "form_buku.html",
                    buku=buku,
                    tahun_sekarang=date.today().year
                )

            cur.execute(
                """
                UPDATE buku
                SET judul=%s, penulis=%s, penerbit=%s,
                    tahun_terbit=%s, stok=%s
                WHERE id=%s
                """,
                (judul, penulis, penerbit, tahun, stok, id)
            )
            conn.commit()
            flash("Data buku berhasil diperbarui.", "success")
            return redirect(url_for("daftar_buku"))

        return render_template(
            "form_buku.html", buku=buku, tahun_sekarang=date.today().year
        )
    finally:
        cur.close()
        conn.close()


# =========================
# HAPUS BUKU (ADMIN SAJA)
# =========================
@app.route("/buku/hapus/<int:id>", methods=["POST"])
@role_required("admin")
def hapus_buku(id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM buku WHERE id = %s", (id,))
        conn.commit()
        if cur.rowcount:
            flash("Buku berhasil dihapus.", "success")
        else:
            flash("Buku tidak ditemukan.", "warning")
    except mysql.connector.IntegrityError:
        conn.rollback()
        flash(
            "Buku tidak bisa dihapus karena memiliki riwayat peminjaman.",
            "danger"
        )
    finally:
        cur.close()
        conn.close()
    return redirect(url_for("daftar_buku"))


# =========================
# PEMINJAMAN: USER AJUKAN, ADMIN KELOLA
# =========================
@app.route("/peminjaman", methods=["GET", "POST"])
@login_required
def peminjaman():
    # User hanya bisa mengajukan peminjaman untuk dirinya sendiri.
    if session.get("role") == "user":
        if request.method == "POST":
            try:
                buku_id = int(request.form.get("buku_id", ""))
                jumlah = int(request.form.get("jumlah", "1"))
                if jumlah < 1:
                    raise ValueError
            except ValueError:
                flash("Pilih buku dan jumlah dengan benar.", "danger")
                return redirect(url_for("peminjaman"))

            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)
            try:
                conn.start_transaction()
                cur.execute(
                    "SELECT id, stok FROM buku WHERE id = %s FOR UPDATE",
                    (buku_id,)
                )
                buku = cur.fetchone()
                if buku is None or buku["stok"] < jumlah:
                    conn.rollback()
                    flash("Stok buku tidak mencukupi.", "warning")
                    return redirect(url_for("peminjaman"))

                # Status diajukan: stok baru dikurangi saat admin menyetujui.
                cur.execute(
                    """
                    INSERT INTO peminjaman
                        (user_id, buku_id, tanggal_pinjam, status, jumlah)
                    VALUES (%s, %s, CURDATE(), 'diajukan', %s)
                    """,
                    (session["user_id"], buku_id, jumlah)
                )
                conn.commit()
                flash("Pengajuan peminjaman berhasil dikirim.", "success")
            except mysql.connector.Error:
                conn.rollback()
                app.logger.exception("Pengajuan peminjaman gagal.")
                flash("Pengajuan gagal. Periksa struktur tabel peminjaman.", "danger")
            finally:
                cur.close()
                conn.close()
            return redirect(url_for("peminjaman"))

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(
                "SELECT id, judul, penerbit, stok FROM buku "
                "WHERE stok > 0 ORDER BY judul"
            )
            buku_tersedia = cur.fetchall()
            cur.execute(
                """
                SELECT p.id, b.judul, p.tanggal_pinjam, p.tanggal_kembali,
                       p.jumlah, p.status
                FROM peminjaman p
                JOIN buku b ON b.id = p.buku_id
                WHERE p.user_id = %s
                ORDER BY p.id DESC
                """,
                (session["user_id"],)
            )
            riwayat = cur.fetchall()
        finally:
            cur.close()
            conn.close()

        return render_template(
            "peminjaman.html",
            buku_tersedia=buku_tersedia,
            daftar_user=[],
            riwayat=riwayat,
            role="user"
        )

    # Tampilan dan tindakan admin: melihat semua pengajuan serta memprosesnya.
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    try:
        if request.method == "POST":
            aksi = request.form.get("aksi", "")
            try:
                peminjaman_id = int(request.form.get("peminjaman_id", ""))
            except ValueError:
                flash("Data peminjaman tidak valid.", "danger")
                return redirect(url_for("peminjaman"))

            conn.start_transaction()
            cur.execute(
                """
                SELECT id, user_id, buku_id, jumlah, status
                FROM peminjaman WHERE id = %s FOR UPDATE
                """,
                (peminjaman_id,)
            )
            pinjam = cur.fetchone()

            if pinjam is None:
                conn.rollback()
                flash("Peminjaman tidak ditemukan.", "warning")
                return redirect(url_for("peminjaman"))

            if aksi == "setujui" and pinjam["status"] == "diajukan":
                cur.execute(
                    "SELECT stok FROM buku WHERE id = %s FOR UPDATE",
                    (pinjam["buku_id"],)
                )
                buku = cur.fetchone()
                if buku is None or buku["stok"] < pinjam["jumlah"]:
                    conn.rollback()
                    flash("Stok buku tidak mencukupi.", "danger")
                    return redirect(url_for("peminjaman"))

                cur.execute(
                    "UPDATE buku SET stok = stok - %s WHERE id = %s",
                    (pinjam["jumlah"], pinjam["buku_id"])
                )
                cur.execute(
                    "UPDATE peminjaman SET status = 'disetujui' WHERE id = %s",
                    (peminjaman_id,)
                )
                conn.commit()
                flash("Peminjaman disetujui.", "success")

            elif aksi == "tolak" and pinjam["status"] == "diajukan":
                cur.execute(
                    "UPDATE peminjaman SET status = 'ditolak' WHERE id = %s",
                    (peminjaman_id,)
                )
                conn.commit()
                flash("Pengajuan ditolak.", "success")

            elif aksi == "kembalikan" and pinjam["status"] == "disetujui":
                cur.execute(
                    "UPDATE buku SET stok = stok + %s WHERE id = %s",
                    (pinjam["jumlah"], pinjam["buku_id"])
                )
                cur.execute(
                    """
                    UPDATE peminjaman
                    SET status = 'dikembalikan', tanggal_kembali = CURDATE()
                    WHERE id = %s
                    """,
                    (peminjaman_id,)
                )
                conn.commit()
                flash("Pengembalian berhasil dicatat.", "success")
            else:
                conn.rollback()
                flash("Aksi tidak sesuai dengan status peminjaman.", "warning")

            return redirect(url_for("peminjaman"))

        cur.execute(
            "SELECT id, judul, penerbit, stok FROM buku "
            "WHERE stok > 0 ORDER BY judul"
        )
        buku_tersedia = cur.fetchall()

        cur.execute("SELECT id, nama FROM users ORDER BY nama")
        daftar_user = cur.fetchall()

        cur.execute(
            """
            SELECT p.id, u.nama, u.username, b.judul,
                   p.tanggal_pinjam, p.tanggal_kembali,
                   p.jumlah, p.status
            FROM peminjaman p
            JOIN users u ON u.id = p.user_id
            JOIN buku b ON b.id = p.buku_id
            ORDER BY p.id DESC
            """
        )
        riwayat = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    return render_template(
        "peminjaman.html",
        buku_tersedia=buku_tersedia,
        daftar_user=daftar_user,
        riwayat=riwayat,
        role="admin"
    )


# =========================
# LOGOUT
# =========================
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("Kamu berhasil logout.", "success")
    return redirect(url_for("login"))


# =========================
# JALANKAN APLIKASI
# =========================
if __name__ == "__main__":
    init_admin()
    app.run(debug=True)