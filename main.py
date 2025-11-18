import mysql.connector
import jwt
import datetime
from dotenv import load_dotenv
import os
from flask import Flask, request, jsonify, make_response
from datetime import datetime, timedelta
import secrets
from smail import send_mail
import hhuy

# Load biến môi trường từ file .env
load_dotenv()

app = Flask(__name__)

# Config
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "")
DB_NAME = os.getenv("DB_NAME", "vinh_library")
DOMAIN = os.getenv("DOMAIN")
PORT = int(os.getenv("PORT", 1235))
DEBUG = os.getenv("DEBUG", "True").lower() == "true"

JWT_SECRET = os.getenv("JWT_SECRET", "secret")
JWT_HEADER = os.getenv("JWT_HEADER", "Authorization")

API_KEY = os.getenv("API_KEY", "changeme")

# Hàm chuẩn hóa response
def make_response(status, message, data=None):
    return jsonify({
        "status": status,
        "message": message,
        "data": data
    }), status

# Kết nối MySQL
def get_db_connection():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )

from datetime import datetime, timedelta  #   import đúng

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    # Kiểm tra đầu vào
    if "datauser" not in data:
        return make_response(400, "Thiếu datauser")

    datauser = data["datauser"]
    username = datauser.get("email")
    password = hhuy.hash_key(datauser.get("password"))

    if not username or not password:
        return make_response(400, "Thiếu email hoặc password")

    # Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return make_response(403, "API key không hợp lệ")

    # Kết nối DB
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Kiểm tra người dùng theo email
    cursor.execute("SELECT * FROM users WHERE email = %s", (username,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        return make_response(404, "Người dùng không tồn tại")

    # Kiểm tra mật khẩu
    if user["pass"] != password:
        return make_response(401, "Thông tin đăng nhập không đúng")

    #   Tạo JWT token hợp lệ (15 ngày)
    payload = {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "exp": datetime.utcnow() + timedelta(days=15)
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    # Trả response
    return make_response(200, "Đăng nhập thành công", {
        "id": user["id"],
        "username": user["name"],
        "email": user["email"],
        "role": user["role"],
        "token": token
    })



@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    
    # Bắt buộc phải có datauser
    if "datauser" not in data:
        return make_response(400, "Thiếu datauser")

    # Check api_key ngoài datauser
    if data.get("api_key") != API_KEY:
        return make_response(403, "API key không hợp lệ")

    datauser = data["datauser"]
    name = datauser.get("name")
    email = datauser.get("email")
    password = datauser.get("password")
    password = hhuy.hash_key(password)

    if not name or not email or not password:
        return make_response(400, "Thiếu name, email hoặc password")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ⚡ Kiểm tra email đã tồn tại
    cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
    existing = cursor.fetchone()
    if existing:
        cursor.close()
        conn.close()
        return make_response(409, "Email đã tồn tại")

    # Thêm user mới với role = 3
    cursor.execute(
        "INSERT INTO users (name, email, pass, role) VALUES (%s, %s, %s, %s)",
        (name, email, password, 3)
    )
    conn.commit()

    cursor.close()
    conn.close()

    return make_response(201, "Đăng ký thành công", {
        "name": name,
        "email": email,
        "role": 3
    })



@app.route("/api/forgot_password", methods=["POST"])
def forgot_password():
    data = request.get_json()

    # Bắt buộc có datauser
    if "datauser" not in data:
        return jsonify({"status": 400, "message": "Thiếu datauser"}), 400

    # Kiểm tra api_key ngoài datauser
    if data.get("api_key") != API_KEY:
        return jsonify({"status": 403, "message": "API key không hợp lệ"}), 403

    datauser = data["datauser"]
    email = datauser.get("email")

    if not email:
        return jsonify({"status": 400, "message": "Thiếu email"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    #   Kiểm tra email có tồn tại trong bảng users
    cursor.execute("SELECT id, name FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({"status": 404, "message": "Email không tồn tại trong hệ thống"}), 404

    #   Tạo token ngẫu nhiên 32 ký tự
    token = secrets.token_hex(16)  # 32 ký tự hex

    #   Tính thời gian hết hạn (10 phút)
    exp_time = datetime.now() + timedelta(minutes=10)

    #   Lưu token vào bảng tempusers
    cursor.execute("""
        INSERT INTO tempusers (user_id, token, exp_time)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE token=%s, exp_time=%s
    """, (user["id"], token, exp_time, token, exp_time))
    conn.commit()

    cursor.close()
    conn.close()

    send_mail(user["name"], email, f"{DOMAIN}/reset_password?token={token}", "Đặt lại mật khẩu")

    return jsonify({
        "status": 200,
        "message": "Tạo token thành công. Vui lòng kiểm tra email để đặt lại mật khẩu.",
        "data": {
            "email": email,
            "token": token,
            "exp_time": exp_time.strftime("%Y-%m-%d %H:%M:%S")
        }
    }), 200


@app.route("/api/check_token_reset", methods=["POST"])
def check_token_reset():
    data = request.get_json()

    #   Bắt buộc có datauser
    if "datauser" not in data:
        return jsonify({"status": 400, "message": "Thiếu datauser"}), 400

    #   Kiểm tra api_key ngoài datauser
    if data.get("api_key") != API_KEY:
        return jsonify({"status": 403, "message": "API key không hợp lệ"}), 403

    datauser = data["datauser"]

    #   Lấy token từ body
    token = datauser.get("token")
    if not token:
        return jsonify({"status": 400, "message": "Thiếu token"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    #   Kiểm tra token trong bảng tempusers
    cursor.execute("SELECT token, exp_time FROM tempusers WHERE token = %s", (token,))
    record = cursor.fetchone()

    if not record:
        cursor.close()
        conn.close()
        return jsonify({
            "status": 404,
            "success": False,
            "message": "Token không tồn tại hoặc không hợp lệ."
        }), 404

    exp_time = record["exp_time"]
    now = datetime.now()

    #   Kiểm tra thời hạn: không được quá 20 phút kể từ exp_time
    if now - exp_time > timedelta(minutes=20):
        cursor.close()
        conn.close()
        return jsonify({
            "status": 410,
            "success": False,
            "message": "Token đã hết hạn."
        }), 410

    cursor.close()
    conn.close()

    #   Thành công
    return jsonify({
        "status": 200,
        "success": True,
        "message": "Token hợp lệ.",
        "data": {
            "token": token,
            "exp_time": exp_time.strftime("%Y-%m-%d %H:%M:%S")
        }
    }), 200

@app.route("/api/set_newpass", methods=["POST"])
def set_newpass():
    data = request.get_json()

    #   Bắt buộc có datauser
    if "datauser" not in data:
        return jsonify({"status": 400, "message": "Thiếu datauser"}), 400

    #   Kiểm tra api_key ngoài datauser
    if data.get("api_key") != API_KEY:
        return jsonify({"status": 403, "message": "API key không hợp lệ"}), 403

    datauser = data["datauser"]
    password = datauser.get("password")
    token = datauser.get("token")

    if not password or not token:
        return jsonify({"status": 400, "message": "Thiếu password hoặc token"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    #   Kiểm tra token có tồn tại không
    cursor.execute("SELECT user_id, exp_time FROM tempusers WHERE token = %s", (token,))
    record = cursor.fetchone()

    if not record:
        cursor.close()
        conn.close()
        return jsonify({
            "status": 404,
            "success": False,
            "message": "Token không hợp lệ hoặc không tồn tại."
        }), 404

    #   Kiểm tra token còn hạn
    exp_time = record["exp_time"]
    now = datetime.now()
    if now - exp_time > timedelta(minutes=20):
        cursor.close()
        conn.close()
        return jsonify({
            "status": 410,
            "success": False,
            "message": "Token đã hết hạn. Vui lòng tạo lại yêu cầu đặt lại mật khẩu."
        }), 410

    user_id = record["user_id"]

    #   Mã hoá mật khẩu (nếu cần bảo mật)
    # hashed_password = generate_password_hash(password)  # nếu có werkzeug.security
    hashed_password = hhuy.hash_key(password) 

    #   Cập nhật mật khẩu trong bảng users
    cursor.execute("UPDATE users SET pass = %s WHERE id = %s", (hashed_password, user_id))
    conn.commit()

    #   (Tuỳ chọn) Xoá token sau khi sử dụng
    cursor.execute("DELETE FROM tempusers WHERE token = %s", (token,))
    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({
        "status": 200,
        "success": True,
        "message": "Cập nhật mật khẩu mới thành công.",
        "data": {
            "user_id": user_id,
            "updated_at": now.strftime("%Y-%m-%d %H:%M:%S")
        }
    }), 200

@app.route("/api/show_books", methods=["POST"])
def show_books():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ✅ Lấy danh sách sách (bỏ b.rate)
    cursor.execute("""
        SELECT 
            b.books_id,
            b.Title,
            b.Description,
            GROUP_CONCAT(DISTINCT a.author_name SEPARATOR ', ') AS Author,
            c.category_name AS Category,
            b.ISBN,
            b.PublishYear,
            p.publisher_name AS Publisher,
            b.Language,
            b.DocumentType,
            b.UploadDate,
            b.UploadedBy,
            b.image,
            b.file,
            b.view_count,
            b.total_copies,
            b.status     
        FROM books b
        LEFT JOIN book_authors ba ON b.books_id = ba.book_id
        LEFT JOIN authors a ON ba.author_id = a.author_id
        LEFT JOIN categories c ON b.category_id = c.category_id
        LEFT JOIN publishers p ON b.publisher_id = p.publisher_id
        WHERE b.IsPublic = 1
        GROUP BY b.books_id
        ORDER BY b.UploadDate DESC
    """)

    books = cursor.fetchall()
    cursor.close()
    conn.close()
    if not books:
        return jsonify({
            "status": 404,
            "success": False,
            "message": "Không có sách nào trong hệ thống."
        }), 404

    return jsonify({
        "status": 200,
        "success": True,
        "message": "Lấy danh sách sách thành công.",
        "total": len(books),
        "data": books
    }), 200



@app.route("/api/add_book_review", methods=["POST"])
def add_book_review():
    data = request.get_json()

    #   Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
        }), 403

    datauser = data.get("datauser")
    token = data.get("token")

    #   Giải mã token (nếu có)
    user_id = None
    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            user_id = decoded.get("id")
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token hết hạn."}), 401
        except jwt.InvalidTokenError:
            # Nếu token lỗi => user_id vẫn là None, cho phép đánh giá ẩn danh
            user_id = None

    #   Lấy dữ liệu từ datauser
    books_id = datauser.get("books_id")
    rating = datauser.get("rating")  # Có thể None
    comment = datauser.get("comment")

    #   Kiểm tra tối thiểu: phải có books_id
    if not books_id:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu thông tin bắt buộc: books_id"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        #   Thêm dữ liệu (user_id và rating có thể NULL)
        cursor.execute("""
            INSERT INTO bookreview (user_id, books_id, rating, comment, review_date, isActive)
            VALUES (%s, %s, %s, %s, NOW(), 1)
        """, (user_id, books_id, rating, comment))

        conn.commit()

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Thêm đánh giá thành công!"
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi khi lưu đánh giá: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()


@app.route("/api/show_book_search", methods=["POST"])
def show_book_search():
    """
    API tìm kiếm sách theo tiêu đề hoặc tác giả.
    Hỗ trợ cấu trúc bảng có mối quan hệ N-N giữa books và authors.
    """
    data = request.get_json(silent=True) or {}
    keyword = data.get("keyword", "").strip()

    if not keyword:
        return jsonify({
            "success": False,
            "message": "Không có từ khóa tìm kiếm."
        }), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # ✅ Chỉ tìm theo tiêu đề hoặc tác giả, không theo thể loại
        sql = """
            SELECT 
                b.books_id AS BookID,
                b.Title,
                b.DocumentType,
                b.image AS CoverImage,
                GROUP_CONCAT(DISTINCT a.author_name SEPARATOR ', ') AS Author,
                c.category_name AS Category
            FROM books b
            LEFT JOIN book_authors ba ON b.books_id = ba.book_id
            LEFT JOIN authors a ON ba.author_id = a.author_id
            LEFT JOIN categories c ON b.category_id = c.category_id
            WHERE 
                b.Title LIKE %s
                OR a.author_name LIKE %s
            GROUP BY b.books_id, b.Title, b.DocumentType, b.image, c.category_name
            ORDER BY b.Title ASC
            LIMIT 50
        """

        search_value = f"%{keyword}%"
        cursor.execute(sql, (search_value, search_value))
        results = cursor.fetchall()

        books = [
            {
                "books_id": b.get("BookID"),
                "Title": b.get("Title"),
                "Author": b.get("Author") or "Không rõ tác giả",
                "Category": b.get("Category") or "Không rõ thể loại",
                "DocumentType": b.get("DocumentType") or "",
                "image": b.get("CoverImage") or "/logo/logo.svg",
            }
            for b in results
        ]

        return jsonify({
            "success": True,
            "count": len(books),
            "books": books
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "message": f"Lỗi server: {str(e)}"
        }), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()



@app.route("/api/show_book_reviews", methods=["POST"])
def show_book_reviews():
    data = request.get_json()

    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
        }), 403

    datauser = data.get("datauser")
    books_id = datauser.get("booksId") if datauser else None

    if not books_id:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu books_id"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Lấy danh sách đánh giá
        cursor.execute("""
            SELECT 
                br.review_id,
                br.user_id,
                u.name AS username,
                br.books_id,
                br.rating,
                br.comment,
                br.review_date,
                br.isActive
            FROM bookreview br
            LEFT JOIN users u ON br.user_id = u.id
            WHERE br.books_id = %s AND br.isActive = 1
            ORDER BY br.review_date DESC
        """, (books_id,))
        reviews = cursor.fetchall()

        # ✅ Trung bình và tổng số đánh giá
        cursor.execute("""
            SELECT ROUND(AVG(rating), 1) AS avg_rating, COUNT(*) AS total_reviews
            FROM bookreview
            WHERE books_id = %s AND isActive = 1
        """, (books_id,))
        avg_data = cursor.fetchone()

        avg_rating = avg_data["avg_rating"] or 0
        total_reviews = avg_data["total_reviews"] or 0

        # ✅ Thống kê tỷ lệ sao
        cursor.execute("""
            SELECT rating, COUNT(*) AS count
            FROM bookreview
            WHERE books_id = %s AND isActive = 1
            GROUP BY rating
        """, (books_id,))
        distribution_rows = cursor.fetchall()

        # Tạo dict 5→1 sao
        rating_distribution = {str(i): 0 for i in range(1, 6)}
        for row in distribution_rows:
            rating_distribution[str(int(row["rating"]))] = row["count"]

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Lấy danh sách đánh giá thành công!",
            "data": reviews,
            "avg_rating": avg_rating,
            "total_reviews": total_reviews,
            "rating_distribution": rating_distribution
        }), 200

    except Exception as e:
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi khi lấy dữ liệu: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()


@app.route("/api/get_book_admin", methods=["POST"])
def get_book_admin():
    data = request.get_json()
    if data.get("api_key") != API_KEY:
        return jsonify({"success": False, "message": "API key không hợp lệ."}), 403

    token = data.get("token")
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        role_id = decoded.get("role")
        email_user = decoded.get("email")
    except Exception as e:
        return jsonify({"success": False, "message": f"Lỗi xác thực token: {e}"}), 401

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        base_query = """
            SELECT 
                b.books_id,
                b.Title,
                b.Description,
                b.ISBN,
                b.PublishYear,
                b.Language,
                b.DocumentType,
                b.UploadDate,
                b.UploadedBy,
                b.IsPublic,
                b.image,
                b.publisher_id,
                b.category_id,
                c.category_name,
                p.publisher_name,
                GROUP_CONCAT(a.author_name SEPARATOR ', ') AS authors,
                GROUP_CONCAT(a.author_id SEPARATOR ',') AS author_ids
            FROM books b
            LEFT JOIN categories c ON b.category_id = c.category_id
            LEFT JOIN publishers p ON b.publisher_id = p.publisher_id
            LEFT JOIN book_authors ba ON b.books_id = ba.book_id
            LEFT JOIN authors a ON ba.author_id = a.author_id
        """

        if role_id == 1:
            cursor.execute(base_query + " GROUP BY b.books_id ORDER BY b.books_id DESC")
        elif role_id == 2:
            cursor.execute(base_query + " WHERE b.UploadedBy = %s GROUP BY b.books_id ORDER BY b.books_id DESC", (email_user,))
        else:
            return jsonify({"success": False, "message": "Bạn không có quyền xem danh sách sách."}), 403

        books = cursor.fetchall()

        # Format author_ids → list[int]
        for b in books:
            b["author_ids"] = [int(x) for x in b["author_ids"].split(",")] if b.get("author_ids") else []

        return jsonify({"success": True, "data": books}), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/api/del_book_admin", methods=["POST"])
def del_book_admin():
    data = request.get_json()

    # ===== 1. Kiểm tra API key =====
    if data.get("api_key") != API_KEY:
        return jsonify({"success": False, "message": "API key không hợp lệ."}), 403

    # ===== 2. Giải mã token =====
    token = data.get("token")
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        role_id = decoded.get("role")
        email_user = decoded.get("email")
    except Exception as e:
        return jsonify({"success": False, "message": f"Token lỗi: {e}"}), 401

    # ===== 3. Lấy books_id từ client =====
    datauser = data.get("datauser", {})
    books_id = datauser.get("books_id")

    if not books_id:
        return jsonify({"success": False, "message": "Thiếu books_id"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ===== 4. Kiểm tra sách có tồn tại không =====
        cursor.execute("SELECT * FROM books WHERE books_id=%s", (books_id,))
        book = cursor.fetchone()

        if not book:
            return jsonify({"success": False, "message": "Sách không tồn tại."}), 404

        # ===== 5. Role Admin (1) → Xóa thoải mái =====
        if role_id == 1:
            cursor.execute("DELETE FROM books WHERE books_id=%s", (books_id,))

        # ===== 6. Role Nhân viên (2) → Chỉ xóa sách do mình upload =====
        elif role_id == 2:
            cursor.execute(
                "DELETE FROM books WHERE books_id=%s AND UploadedBy=%s",
                (books_id, email_user)
            )

            if cursor.rowcount == 0:
                return jsonify({
                    "success": False,
                    "message": "Bạn không có quyền xóa sách này."
                }), 403

        else:
            return jsonify({"success": False, "message": "Không có quyền xóa."}), 403

        conn.commit()

        return jsonify({"success": True, "message": "Xóa sách thành công."}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

    finally:
        cursor.close()
        conn.close()

    data = request.get_json()
    if data.get("api_key") != API_KEY:
        return jsonify({"success": False, "message": "API key không hợp lệ."}), 403

    token = data.get("token")
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        role_id = decoded.get("role")
        email_user = decoded.get("email")
    except Exception as e:
        return jsonify({"success": False, "message": f"Token lỗi: {e}"}), 401

    datauser = data.get("datauser", {})
    books_id = datauser.get("books_id")
    if not books_id:
        return jsonify({"success": False, "message": "Thiếu books_id"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        if role_id == 1:
            cursor.execute("DELETE FROM books WHERE books_id=%s", (books_id,))
        elif role_id == 2:
            cursor.execute("DELETE FROM books WHERE books_id=%s AND UploadedBy=%s", (books_id, email_user))
        else:
            return jsonify({"success": False, "message": "Không có quyền xóa."}), 403

        conn.commit()
        return jsonify({"success": True, "message": "Xóa sách thành công."}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/api/add_book_adm", methods=["POST"])
def add_book_admin():
    data = request.get_json()

    # ===== 1. Kiểm tra API key =====
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
        }), 403

    # ===== 2. Lấy dữ liệu datauser =====
    datauser = data.get("datauser")
    if not datauser:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu dữ liệu datauser."
        }), 400

    token = data.get("token")
    email_user = None
    role_id = None

    # ===== 3. Giải mã token =====
    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
            email_user = decoded.get("email")
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token hết hạn."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Token không hợp lệ."}), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    # ===== 4. Chỉ role 1 và 2 được phép thêm sách =====
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền thêm sách."
        }), 403

    # ===== 5. Lấy thông tin sách từ body =====
    title = datauser.get("Title")
    description = datauser.get("Description")
    isbn = datauser.get("ISBN")
    publish_year = datauser.get("PublishYear")
    language = datauser.get("Language")
    document_type = datauser.get("DocumentType")
    publisher_id = datauser.get("publisher_id")
    category_id = datauser.get("category_id")
    author_ids = datauser.get("author_ids")  # LIST
    imgpath = datauser.get("image")
    docum = datauser.get("file")
    is_public = datauser.get("IsPublic", 1)

    # ===== 6. Kiểm tra dữ liệu bắt buộc =====
    if not all([title, publish_year, language, document_type, publisher_id, category_id, imgpath, docum]):
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu thông tin bắt buộc để thêm sách."
        }), 400

    if not author_ids or not isinstance(author_ids, list):
        return jsonify({
            "status": 400,
            "success": False,
            "message": "author_ids phải là danh sách chứa ít nhất 1 tác giả."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ===== 7. Thêm sách vào bảng BOOKS =====
        cursor.execute("""
            INSERT INTO books 
            (Title, Description, ISBN, PublishYear, Language, DocumentType, 
             UploadedBy, IsPublic, image, file, publisher_id, category_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            title, description, isbn, publish_year, language, document_type,
            email_user, is_public, imgpath, docum, publisher_id, category_id
        ))
        conn.commit()

        # Lấy ID cuốn sách vừa thêm
        book_id = cursor.lastrowid

        # ===== 8. Thêm vào bảng BOOK_AUTHORS =====
        for author_id in author_ids:
            cursor.execute("""
                INSERT INTO book_authors (book_id, author_id)
                VALUES (%s, %s)
            """, (book_id, author_id))

        conn.commit()

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Thêm sách thành công.",
            "book_id": book_id
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()


@app.route("/api/edit_book_admin", methods=["POST"])
def edit_book_admin():
    data = request.get_json(force=True)
    # ✅ 1. Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    # ✅ 2. Giải mã token
    token = data.get("token")
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        role_id = decoded.get("role")
        email_user = decoded.get("email")
    except Exception as e:
        return jsonify({"success": False, "message": f"Lỗi token: {e}"}), 401

    # ✅ 3. Kiểm tra quyền
    if role_id not in [1, 2]:
        return jsonify({
            "success": False,
            "message": "Bạn không có quyền chỉnh sửa sách."
        }), 403

    # ✅ 4. Chuẩn hóa cấu trúc dữ liệu (bóc tách nếu lồng nhiều lớp)
    datauser = data.get("datauser")
    while isinstance(datauser, dict) and "datauser" in datauser:
        datauser = datauser.get("datauser")
    if not datauser:
        return jsonify({
            "success": False,
            "message": "Thiếu dữ liệu datauser."
        }), 400

    # ✅ 5. Lấy thông tin sách
    books_id = datauser.get("books_id")
    author_ids = datauser.get("author_ids")

    if not books_id or not author_ids:
        return jsonify({
            "success": False,
            "message": "Thiếu books_id hoặc tác giả."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ 6. Cập nhật bảng books
        cursor.execute("""
            UPDATE books
            SET Title=%s, Description=%s, ISBN=%s, PublishYear=%s, Language=%s, DocumentType=%s,
                publisher_id=%s, category_id=%s, UploadedBy=%s, image=%s, file=%s, IsPublic=%s
            WHERE books_id=%s
        """, (
            datauser.get("Title"),
            datauser.get("Description"),
            datauser.get("ISBN"),
            datauser.get("PublishYear"),
            datauser.get("Language"),
            datauser.get("DocumentType"),
            datauser.get("publisher_id"),
            datauser.get("category_id"),
            email_user,
            datauser.get("image"),
            datauser.get("document"),
            datauser.get("IsPublic", 1),
            books_id
        ))
        conn.commit()

        # ✅ 7. Cập nhật tác giả
        cursor.execute("DELETE FROM book_authors WHERE book_id = %s", (books_id,))
        for author_id in author_ids:
            cursor.execute("""
                INSERT INTO book_authors (book_id, author_id)
                VALUES (%s, %s)
            """, (books_id, author_id))
        conn.commit()

        # ✅ 8. Lấy lại dữ liệu sau khi cập nhật
        cursor.execute("""
            SELECT 
                b.books_id, b.Title, b.Description, b.ISBN, b.PublishYear, b.Language,
                b.DocumentType, b.UploadDate, b.UploadedBy, b.IsPublic, b.image,
                c.category_name, p.publisher_name,
                GROUP_CONCAT(a.author_name SEPARATOR ', ') AS authors
            FROM books b
            LEFT JOIN categories c ON b.category_id = c.category_id
            LEFT JOIN publishers p ON b.publisher_id = p.publisher_id
            LEFT JOIN book_authors ba ON b.books_id = ba.book_id
            LEFT JOIN authors a ON ba.author_id = a.author_id
            WHERE b.books_id = %s
            GROUP BY b.books_id
        """, (books_id,))
        updated_book = cursor.fetchone()

        return jsonify({
            "success": True,
            "message": "Cập nhật thông tin sách thành công.",
            "updated_book": updated_book
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()

@app.route("/api/view_count", methods=["POST"])
def view_count():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"success": False, "message": "Dữ liệu JSON không hợp lệ."}), 400

    # ✅ 1. Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    # ✅ 2. Lấy ID sách (SỬA ĐOẠN NÀY)
    # Frontend gửi: { "datauser": { "books_id": 123 } }
    # Nên ta cần lấy 'datauser' trước, hoặc fallback về 'data' nếu gửi phẳng
    datauser = data.get("datauser", {}) 
    
    # Ưu tiên lấy từ datauser, nếu không có thì thử lấy trực tiếp từ root data
    books_id = datauser.get("books_id") if datauser else data.get("books_id")


    if not books_id:
        return jsonify({
            "success": False,
            "message": "Thiếu books_id."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ 3. Tăng view_count
        cursor.execute("""
            UPDATE books 
            SET view_count = view_count + 1 
            WHERE books_id = %s
        """, (books_id,))
        
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({
                "success": False, 
                "message": "Không tìm thấy sách với ID này."
            }), 404

        # ✅ 4. Lấy số view mới trả về
        cursor.execute("SELECT view_count FROM books WHERE books_id = %s", (books_id,))
        result = cursor.fetchone()
        new_view_count = result['view_count'] if result else 0

        return jsonify({
            "success": True,
            "message": "Đã tăng lượt xem thành công.",
            "view_count": new_view_count
        }), 200

    except Exception as e:
        conn.rollback()
        print(f"Error: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()


@app.route("/api/get_authors_and_categories", methods=["POST"])
def get_authors_and_categories():
    data = request.get_json()
    
    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Lấy danh sách tác giả
        cursor.execute("""
            SELECT 
                author_id,
                author_name,
                biography,
                birth_year,
                death_year
            FROM authors
            ORDER BY author_name ASC
        """)
        authors = cursor.fetchall()

        # ✅ Lấy danh sách thể loại
        cursor.execute("""
            SELECT 
                category_id,
                category_name,
                description
            FROM categories
            ORDER BY category_name ASC
        """)
        categories = cursor.fetchall()

        return jsonify({
            "success": True,
            "message": "Lấy dữ liệu thành công.",
            "data": {
                "authors": authors,
                "categories": categories
            }
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()


@app.route("/api/get_publishers", methods=["POST"])
def get_publishers():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT 
                publisher_id,
                publisher_name,
                address,
                phone,
                email
            FROM publishers
            ORDER BY publisher_name ASC
        """)
        publishers = cursor.fetchall()

        return jsonify({
            "success": True,
            "message": "Lấy danh sách nhà xuất bản thành công.",
            "data": publishers
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()



@app.route("/api/get_news", methods=["POST"])
def get_news():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    token = data.get("token")
    role_id = None
    email_user = None

    # ✅ Giải mã token
    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
            email_user = decoded.get("email")
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token hết hạn."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token không hợp lệ."
            }), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    # ✅ Kiểm tra quyền truy cập
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền truy cập dữ liệu này."
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Lấy toàn bộ dữ liệu từ bảng news
        cursor.execute("SELECT * FROM news")
        news_data = cursor.fetchall()

        return jsonify({
            "status": 200,
            "success": True,
            "data": news_data
        }), 200

    except Exception as e:
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()



@app.route("/api/add_authors", methods=["POST"])
def add_author():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    # ✅ Lấy dữ liệu người dùng gửi lên
    datauser = data.get("datauser")

    if not datauser:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu dữ liệu datauser."
        }), 400

    # ✅ Giải mã token
    token = data.get("token")
    role_id = None
    email_user = None

    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
            email_user = decoded.get("email")
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token hết hạn."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Token không hợp lệ."}), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    # ✅ Chỉ role_id = 1 hoặc 2 được phép thêm tác giả
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền thêm tác giả."
        }), 403

    # ✅ Lấy thông tin tác giả từ datauser
    author_name = datauser.get("author_name")
    biography = datauser.get("biography")
    birth_year = datauser.get("birth_year")
    death_year = datauser.get("death_year")

    # ✅ Kiểm tra dữ liệu bắt buộc
    if not author_name:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu tên tác giả (author_name)."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Thêm dữ liệu vào bảng authors
        cursor.execute("""
            INSERT INTO authors (author_name, biography, birth_year, death_year)
            VALUES (%s, %s, %s, %s)
        """, (author_name, biography, birth_year, death_year))
        conn.commit()

        author_id = cursor.lastrowid

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Thêm tác giả thành công.",
            "author_id": author_id
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()


@app.route("/api/get_user", methods=["POST"])
def get_user():
    data = request.get_json()

    #   Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
        }), 403

    token = data.get("token")
    role_id = None
    email_user = None

    #   Giải mã token
    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
            email_user = decoded.get("email")
        except jwt.ExpiredSignatureError:
            return jsonify({
                "success": False,
                "message": "Token hết hạn."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "success": False,
                "message": "Token không hợp lệ."
            }), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    #   Chỉ role_id = 1 mới có quyền xem danh sách user
    if role_id != 1:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền xem danh sách người dùng."
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        #   Lấy toàn bộ dữ liệu bảng users
        cursor.execute("SELECT id, name, email, role, created_at FROM users")
        result = cursor.fetchall()

        return jsonify({
            "status": 200,
            "success": True,
            "data": result
        }), 200

    except Exception as e:
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()

@app.route("/api/edit_email_admin", methods=["POST"])
def edit_email_admin():
    data = request.get_json()

    #   Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
        }), 403

    #   Giải mã token
    token = data.get("token")
    role_id = None
    email_user = None

    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
            email_user = decoded.get("email")
        except jwt.ExpiredSignatureError:
            return jsonify({
                "success": False,
                "message": "Token hết hạn."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "success": False,
                "message": "Token không hợp lệ."
            }), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    #   Chỉ role_id = 1 được phép chỉnh sửa email
    if role_id != 1:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền thay đổi email người dùng."
        }), 403

    #   Lấy dữ liệu người dùng gửi lên
    datauser = data.get("datauser")
    if not datauser:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu dữ liệu datauser."
        }), 400

    old_email = datauser.get("oldEmail")
    new_email = datauser.get("newEmail")

    #   Kiểm tra email
    if not old_email or not new_email:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu email cũ hoặc email mới."
        }), 400

    #   Nếu email mới giống email cũ → từ chối
    if old_email == new_email:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Email mới phải khác email cũ."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        #   Kiểm tra xem email cũ có tồn tại không
        cursor.execute("SELECT * FROM users WHERE email = %s", (old_email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({
                "status": 404,
                "success": False,
                "message": "Không tìm thấy người dùng với email cũ."
            }), 404

        #   Kiểm tra nếu email mới đã tồn tại
        cursor.execute("SELECT * FROM users WHERE email = %s", (new_email,))
        exists = cursor.fetchone()
        if exists:
            return jsonify({
                "status": 400,
                "success": False,
                "message": "Email mới đã tồn tại trong hệ thống."
            }), 400

        #   Cập nhật email
        cursor.execute("UPDATE users SET email = %s WHERE email = %s", (new_email, old_email))
        conn.commit()

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Cập nhật email thành công."
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()

@app.route("/api/edit_role_admin", methods=["POST"])
def edit_role_admin():
    data = request.get_json()

    # 1️⃣ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
        }), 403

    # 2️⃣ Giải mã token
    token = data.get("token")
    role_id = None

    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token hết hạn."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Token không hợp lệ."}), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    # 3️⃣ Chỉ role_id = 1 được phép chỉnh sửa role
    if role_id != 1:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền thay đổi role người dùng."
        }), 403

    # 4️⃣ Lấy dữ liệu
    datauser = data.get("datauser")
    if not datauser:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu dữ liệu datauser."
        }), 400

    email = datauser.get("email")
    new_role = datauser.get("newRole")

    if not email or new_role is None:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu email hoặc role mới."
        }), 400

    # 5️⃣ Không cho phép đổi quyền tài khoản đặc biệt
    if email == "hhuydhv@gmail.com":
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Không được phép thay đổi quyền của tài khoản hệ thống."
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 6️⃣ Kiểm tra user có tồn tại
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({
                "status": 404,
                "success": False,
                "message": "Không tìm thấy người dùng."
            }), 404

        # 7️⃣ Không được thay đổi nếu role cũ == role mới
        if user["role"] == new_role:
            return jsonify({
                "status": 400,
                "success": False,
                "message": "Quyền mới phải khác quyền hiện tại."
            }), 400

        # 8️⃣ Nếu user này đang là admin → kiểm tra xem còn admin nào khác không
        if user["role"] == 1:
            cursor.execute("SELECT COUNT(*) AS total FROM users WHERE role = 1")
            admin_count = cursor.fetchone()["total"]

            if admin_count <= 1:
                return jsonify({
                    "status": 403,
                    "success": False,
                    "message": "Hệ thống phải có ít nhất 1 tài khoản Admin. Không thể thay đổi role của admin duy nhất."
                }), 403

        # 9️⃣ Cập nhật role
        cursor.execute("UPDATE users SET role = %s WHERE email = %s", (new_role, email))
        conn.commit()

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Cập nhật role thành công."
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi server: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()


@app.route("/api/edit_pass_admin", methods=["POST"])
def edit_pass_admin():
    data = request.get_json()

    #   Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    #   Lấy token
    token = data.get("token")
    role_id = None

    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token hết hạn."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token không hợp lệ."
            }), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    #   Chỉ admin (role_id = 1) được phép đổi mật khẩu
    if role_id != 1:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền thay đổi mật khẩu người dùng khác."
        }), 403

    #   Lấy dữ liệu người dùng cần cập nhật
    datauser = data.get("datauser", {})
    email = datauser.get("email")
    new_pass = datauser.get("newPassword")

    if not email or not new_pass:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu thông tin email hoặc mật khẩu mới."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        #   Mã hóa mật khẩu mới trước khi lưu
        hashed_pass = new_pass

        #   Cập nhật mật khẩu
        cursor.execute("""
            UPDATE users
            SET pass = %s
            WHERE email = %s
        """, (hashed_pass, email))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({
                "status": 404,
                "success": False,
                "message": "Không tìm thấy người dùng với email này."
            }), 404

        return jsonify({
            "status": 200,
            "success": True,
            "message": f"Đổi mật khẩu cho {email} thành công."
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()


@app.route("/api/del_user_admin", methods=["POST"])
def del_user_admin():
    data = request.get_json()

    #   Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    #   Lấy token
    token = data.get("token")
    role_id = None

    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token hết hạn."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token không hợp lệ."
            }), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    #   Chỉ Admin mới có quyền xóa user
    if role_id != 1:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền xóa người dùng."
        }), 403

    #   Lấy dữ liệu người dùng cần xóa
    datauser = data.get("datauser", {})
    email = datauser.get("email")

    if not email:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu thông tin email cần xóa."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        #   Xóa người dùng theo email
        cursor.execute("DELETE FROM users WHERE email = %s", (email,))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({
                "status": 404,
                "success": False,
                "message": "Không tìm thấy người dùng với email này."
            }), 404

        return jsonify({
            "status": 200,
            "success": True,
            "message": f"Đã xóa người dùng có email: {email}"
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()

@app.route("/api/del_authors", methods=["POST"])
def del_authors():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    # ✅ Lấy token
    token = data.get("token")
    role_id = None

    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token hết hạn."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token không hợp lệ."
            }), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    # ✅ Chỉ Admin (role_id = 1) có quyền xóa tác giả
    if role_id != 1:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền xóa tác giả."
        }), 403

    # ✅ Lấy dữ liệu người dùng gửi lên
    datauser = data.get("datauser", {})
    author_id = datauser.get("author_id")

    if not author_id:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu thông tin author_id cần xóa."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # ✅ Xóa tác giả theo author_id
        cursor.execute("DELETE FROM authors WHERE author_id = %s", (author_id,))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({
                "status": 404,
                "success": False,
                "message": "Không tìm thấy tác giả với ID này."
            }), 404

        return jsonify({
            "status": 200,
            "success": True,
            "message": f"Đã xóa tác giả có ID: {author_id}"
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()


@app.route("/api/edit_authors", methods=["POST"])
def edit_authors():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    # ✅ Giải mã token
    token = data.get("token")
    role_id = None

    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token hết hạn."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token không hợp lệ."
            }), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    # ✅ Chỉ role_id = 1 hoặc 2 được phép chỉnh sửa tác giả
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền chỉnh sửa thông tin tác giả."
        }), 403

    # ✅ Lấy dữ liệu người dùng gửi lên
    datauser = data.get("datauser")
    if not datauser:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu dữ liệu datauser."
        }), 400

    author_id = datauser.get("author_id")
    author_name = datauser.get("author_name")
    biography = datauser.get("biography")
    birth_year = datauser.get("birth_year")
    death_year = datauser.get("death_year")

    # ✅ Kiểm tra dữ liệu bắt buộc
    if not author_id or not author_name:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu thông tin bắt buộc (author_id hoặc author_name)."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Kiểm tra tác giả có tồn tại không
        cursor.execute("SELECT * FROM authors WHERE author_id = %s", (author_id,))
        author = cursor.fetchone()

        if not author:
            return jsonify({
                "status": 404,
                "success": False,
                "message": "Không tìm thấy tác giả với ID này."
            }), 404

        # ✅ Cập nhật thông tin tác giả (xử lý None cho death_year)
        cursor.execute("""
            UPDATE authors
            SET author_name = %s,
                biography = %s,
                birth_year = %s,
                death_year = %s
            WHERE author_id = %s
        """, (author_name, biography, birth_year, death_year, author_id))
        conn.commit()

        # ✅ Lấy lại dữ liệu sau khi cập nhật để trả về
        cursor.execute("SELECT * FROM authors WHERE author_id = %s", (author_id,))
        updated_author = cursor.fetchone()

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Cập nhật thông tin tác giả thành công.",
            "updated_author": updated_author
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()



@app.route("/api/add_publishers", methods=["POST"])
def add_publishers():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    # ✅ Lấy dữ liệu người dùng gửi lên
    datauser = data.get("datauser")
    if not datauser:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu dữ liệu datauser."
        }), 400

    token = data.get("token")
    role_id = None
    email_user = None

    # ✅ Giải mã token
    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
            email_user = decoded.get("email")
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token hết hạn."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Token không hợp lệ."}), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    # ✅ Chỉ role_id = 1 hoặc 2 được phép thêm
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền thêm nhà xuất bản."
        }), 403

    # ✅ Lấy thông tin từ datauser
    publisher_name = datauser.get("publisher_name")
    address = datauser.get("address")
    phone = datauser.get("phone")
    email = datauser.get("email")

    # ✅ Kiểm tra dữ liệu bắt buộc
    if not publisher_name:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Tên nhà xuất bản là bắt buộc."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Kiểm tra trùng tên
        cursor.execute("SELECT * FROM publishers WHERE publisher_name = %s", (publisher_name,))
        existing = cursor.fetchone()
        if existing:
            cursor.close()
            conn.close()
            return jsonify({
                "status": 409,
                "success": False,
                "message": "Nhà xuất bản đã tồn tại trong hệ thống."
            }), 409

        # ✅ Thêm nhà xuất bản mới
        cursor.execute("""
            INSERT INTO publishers (publisher_name, address, phone, email)
            VALUES (%s, %s, %s, %s)
        """, (publisher_name, address, phone, email))
        conn.commit()

        publisher_id = cursor.lastrowid

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Thêm nhà xuất bản thành công.",
            "publisher_id": publisher_id
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()

@app.route("/api/del_publishers", methods=["POST"])
def del_publishers():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    # ✅ Lấy token và giải mã
    token = data.get("token")
    role_id = None

    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token hết hạn."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token không hợp lệ."
            }), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    # ✅ Chỉ Admin (role_id = 1) hoặc Thủ thư (role_id = 2) được phép xóa
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền xóa nhà xuất bản."
        }), 403

    # ✅ Lấy dữ liệu người dùng gửi lên
    datauser = data.get("datauser", {})
    publisher_id = datauser.get("publisher_id")

    if not publisher_id:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu thông tin publisher_id cần xóa."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # ✅ Kiểm tra xem publisher có tồn tại không
        cursor.execute("SELECT * FROM publishers WHERE publisher_id = %s", (publisher_id,))
        existing = cursor.fetchone()

        if not existing:
            cursor.close()
            conn.close()
            return jsonify({
                "status": 404,
                "success": False,
                "message": "Không tìm thấy nhà xuất bản với ID này."
            }), 404

        # ✅ Xóa nhà xuất bản
        cursor.execute("DELETE FROM publishers WHERE publisher_id = %s", (publisher_id,))
        conn.commit()

        return jsonify({
            "status": 200,
            "success": True,
            "message": f"Đã xóa nhà xuất bản có ID: {publisher_id}"
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()

@app.route("/api/edit_publishers", methods=["POST"])
def edit_publishers():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    # ✅ Giải mã token
    token = data.get("token")
    role_id = None

    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token hết hạn."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token không hợp lệ."
            }), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    # ✅ Chỉ role_id = 1 hoặc 2 được phép chỉnh sửa nhà xuất bản
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền chỉnh sửa thông tin nhà xuất bản."
        }), 403

    # ✅ Lấy dữ liệu người dùng gửi lên
    datauser = data.get("datauser")
    if not datauser:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu dữ liệu datauser."
        }), 400

    publisher_id = datauser.get("publisher_id")
    publisher_name = datauser.get("publisher_name")
    address = datauser.get("address")
    phone = datauser.get("phone")
    email = datauser.get("email")

    # ✅ Kiểm tra dữ liệu bắt buộc
    if not publisher_id or not publisher_name:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu thông tin bắt buộc (publisher_id hoặc publisher_name)."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Kiểm tra nhà xuất bản có tồn tại không
        cursor.execute("SELECT * FROM publishers WHERE publisher_id = %s", (publisher_id,))
        publisher = cursor.fetchone()

        if not publisher:
            return jsonify({
                "status": 404,
                "success": False,
                "message": "Không tìm thấy nhà xuất bản với ID này."
            }), 404

        # ✅ Kiểm tra tên nhà xuất bản trùng (trừ chính nó)
        cursor.execute("""
            SELECT * FROM publishers 
            WHERE publisher_name = %s AND publisher_id != %s
        """, (publisher_name, publisher_id))
        duplicate = cursor.fetchone()
        if duplicate:
            return jsonify({
                "status": 409,
                "success": False,
                "message": "Tên nhà xuất bản đã tồn tại."
            }), 409

        # ✅ Cập nhật thông tin nhà xuất bản
        cursor.execute("""
            UPDATE publishers
            SET publisher_name = %s,
                address = %s,
                phone = %s,
                email = %s
            WHERE publisher_id = %s
        """, (publisher_name, address, phone, email, publisher_id))
        conn.commit()

        # ✅ Lấy lại dữ liệu sau khi cập nhật để trả về
        cursor.execute("SELECT * FROM publishers WHERE publisher_id = %s", (publisher_id,))
        updated_publisher = cursor.fetchone()

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Cập nhật thông tin nhà xuất bản thành công.",
            "updated_publisher": updated_publisher
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()

@app.route("/api/del_categories", methods=["POST"])
def del_categories():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if not data or data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ hoặc thiếu dữ liệu."
        }), 403

    # ✅ Giải mã token
    token = data.get("token")
    role_id = None

    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token hết hạn."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token không hợp lệ."
            }), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    # ✅ Chỉ role_id = 1 hoặc 2 được phép xóa
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền xóa danh mục."
        }), 403

    # ✅ Lấy dữ liệu người dùng gửi lên
    datauser = data.get("datauser", None)

    # Có thể client gửi thẳng category_id hoặc gói trong object
    if isinstance(datauser, int):
        category_id = datauser
    elif isinstance(datauser, dict):
        category_id = datauser.get("category_id")
    else:
        category_id = None

    if not category_id:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu thông tin category_id cần xóa."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # ✅ Kiểm tra danh mục có tồn tại không
        cursor.execute("SELECT category_id FROM categories WHERE category_id = %s", (category_id,))
        existing = cursor.fetchone()
        if not existing:
            return jsonify({
                "status": 404,
                "success": False,
                "message": "Không tìm thấy danh mục với ID này."
            }), 404

        # ✅ Kiểm tra xem có sách nào thuộc danh mục này không
        cursor.execute("SELECT COUNT(*) FROM books WHERE category_id = %s", (category_id,))
        count_books = cursor.fetchone()[0]
        if count_books > 0:
            return jsonify({
                "status": 409,
                "success": False,
                "message": "Không thể xóa danh mục vì đang có sách thuộc danh mục này."
            }), 409

        # ✅ Thực hiện xóa
        cursor.execute("DELETE FROM categories WHERE category_id = %s", (category_id,))
        conn.commit()

        return jsonify({
            "status": 200,
            "success": True,
            "message": f"Đã xóa danh mục có ID: {category_id}"
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()


@app.route("/api/add_categories", methods=["POST"])
def add_categories():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    # ✅ Lấy dữ liệu người dùng gửi lên
    datauser = data.get("datauser")
    if not datauser:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu dữ liệu datauser."
        }), 400

    token = data.get("token")
    role_id = None
    email_user = None

    # ✅ Giải mã token
    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
            email_user = decoded.get("email")
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token hết hạn."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token không hợp lệ."
            }), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    # ✅ Chỉ role_id = 1 hoặc 2 được phép thêm
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền thêm danh mục."
        }), 403

    # ✅ Lấy thông tin từ datauser
    category_name = datauser.get("category_name")
    description = datauser.get("description")

    # ✅ Kiểm tra dữ liệu bắt buộc
    if not category_name:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Tên danh mục là bắt buộc."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Kiểm tra trùng tên danh mục
        cursor.execute("SELECT * FROM categories WHERE category_name = %s", (category_name,))
        existing = cursor.fetchone()
        if existing:
            cursor.close()
            conn.close()
            return jsonify({
                "status": 409,
                "success": False,
                "message": "Danh mục này đã tồn tại trong hệ thống."
            }), 409

        # ✅ Thêm danh mục mới
        cursor.execute("""
            INSERT INTO categories (category_name, description)
            VALUES (%s, %s)
        """, (category_name, description))
        conn.commit()

        category_id = cursor.lastrowid

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Thêm danh mục thành công.",
            "category_id": category_id
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()

@app.route("/api/edit_categories", methods=["POST"])
def edit_categories():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    # ✅ Giải mã token
    token = data.get("token")
    role_id = None

    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token hết hạn."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "status": 401,
                "success": False,
                "message": "Token không hợp lệ."
            }), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    # ✅ Chỉ role_id = 1 hoặc 2 được phép chỉnh sửa danh mục
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền chỉnh sửa danh mục."
        }), 403

    # ✅ Lấy dữ liệu từ client
    datauser = data.get("datauser")
    if not datauser:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu dữ liệu datauser."
        }), 400

    category_id = datauser.get("category_id")
    category_name = datauser.get("category_name")
    description = datauser.get("description")

    # ✅ Kiểm tra dữ liệu bắt buộc
    if not category_id or not category_name:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu thông tin bắt buộc (category_id hoặc category_name)."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Kiểm tra danh mục có tồn tại không
        cursor.execute("SELECT * FROM categories WHERE category_id = %s", (category_id,))
        existing_category = cursor.fetchone()
        if not existing_category:
            return jsonify({
                "status": 404,
                "success": False,
                "message": "Không tìm thấy danh mục với ID này."
            }), 404

        # ✅ Kiểm tra trùng tên (trừ chính nó)
        cursor.execute("""
            SELECT * FROM categories 
            WHERE category_name = %s AND category_id != %s
        """, (category_name, category_id))
        duplicate = cursor.fetchone()
        if duplicate:
            return jsonify({
                "status": 409,
                "success": False,
                "message": "Tên danh mục đã tồn tại trong hệ thống."
            }), 409

        # ✅ Cập nhật thông tin danh mục
        cursor.execute("""
            UPDATE categories
            SET category_name = %s,
                description = %s
            WHERE category_id = %s
        """, (category_name, description, category_id))
        conn.commit()

        # ✅ Lấy lại thông tin sau khi cập nhật
        cursor.execute("SELECT * FROM categories WHERE category_id = %s", (category_id,))
        updated_category = cursor.fetchone()

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Cập nhật danh mục thành công.",
            "updated_category": updated_category
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()

@app.route("/api/get_borrow_return", methods=["POST"])
def get_borrow_return():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    # ✅ Giải mã token
    token = data.get("token")
    if not token:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
        }), 401

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        role_id = decoded.get("role")
        email_user = decoded.get("email")
    except jwt.ExpiredSignatureError:
        return jsonify({"success": False, "message": "Token hết hạn."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"success": False, "message": "Token không hợp lệ."}), 401

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Tự động cập nhật trạng thái "Quá hạn"
        cursor.execute("""
            UPDATE borrow_return
            SET status = 'Quá hạn'
            WHERE status = 'Đang mượn'
              AND return_date < CURDATE()
              AND due_date IS NULL
        """)
        conn.commit()

        # ✅ Admin (1) & Thủ thư (2): xem toàn bộ
        if role_id in [1, 2]:
            cursor.execute("""
                SELECT 
                    br.borrow_id,
                    br.user_id,
                    u.name AS user_name,
                    b.Title AS book_title,
                    br.borrow_date,
                    br.due_date,
                    br.return_date,
                    br.status,
                    br.notes,
                    br.last_updated_by
                FROM borrow_return br
                JOIN users u ON br.user_id = u.id
                JOIN books b ON br.books_id = b.books_id
                ORDER BY br.borrow_date DESC
            """)
        else:
            # ✅ Người dùng thường chỉ xem mượn của chính họ
            cursor.execute("""
                SELECT 
                    br.borrow_id,
                    b.Title AS book_title,
                    br.borrow_date,
                    br.due_date,
                    br.return_date,
                    br.status,
                    br.notes,
                    br.last_updated_by
                FROM borrow_return br
                JOIN users u ON br.user_id = u.id
                JOIN books b ON br.books_id = b.books_id
                WHERE u.email = %s
                ORDER BY br.borrow_date DESC
            """, (email_user,))

        rows = cursor.fetchall()

        if not rows:
            return jsonify({
                "status": 404,
                "success": False,
                "message": "Không có dữ liệu mượn/trả."
            }), 404

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Lấy danh sách mượn/trả thành công (đã cập nhật quá hạn).",
            "data": rows
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/add_borrow_return", methods=["POST"])
def add_borrow_return():
    data = request.get_json()
    if data.get("api_key") != API_KEY:
        return jsonify({"status": 403, "success": False, "message": "API key không hợp lệ."}), 403

    datauser = data.get("datauser")
    if not datauser:
        return jsonify({"status": 400, "success": False, "message": "Thiếu dữ liệu datauser."}), 400

    token = data.get("token")
    if not token:
        return jsonify({"status": 401, "success": False, "message": "Thiếu token xác thực."}), 401

    # --------------------------------------
    # 1. Giải mã token
    # --------------------------------------
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        role_id = decoded.get("role")
        email_user = decoded.get("email")
        name_user = decoded.get("name") or email_user
    except jwt.ExpiredSignatureError:
        return jsonify({"success": False, "message": "Token hết hạn."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"success": False, "message": "Token không hợp lệ."}), 401

    # --------------------------------------
    # 2. Kiểm tra quyền
    # --------------------------------------
    if role_id not in [1, 2]:  # 1 = Admin, 2 = Thủ thư
        return jsonify({"status": 403, "success": False, "message": "Bạn không có quyền thêm bản ghi mượn sách."}), 403

    # --------------------------------------
    # 3. Lấy dữ liệu từ client
    # --------------------------------------
    user_name = datauser.get("user_name")
    book_title = datauser.get("book_title")
    borrow_date = datauser.get("borrow_date")
    return_date = datauser.get("return_date")
    status = datauser.get("status", "Đang mượn")

    if not user_name or not book_title or not borrow_date:
        return jsonify({"status": 400, "success": False, "message": "Thiếu thông tin bắt buộc."}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # --------------------------------------
        # 4. Tìm user_id
        # --------------------------------------
        cursor.execute("SELECT id FROM users WHERE name = %s LIMIT 1", (user_name,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"status": 404, "success": False, "message": "Không tìm thấy người dùng."}), 404

        user_id = user["id"]

        # --------------------------------------
        # 5. Tìm books_id (chuẩn hóa LOWER)
        # --------------------------------------
        cursor.execute("SELECT books_id, available_copies FROM books WHERE LOWER(Title) = LOWER(%s) LIMIT 1",
                       (book_title,))
        book = cursor.fetchone()

        if not book:
            return jsonify({"status": 404, "success": False, "message": "Không tìm thấy sách."}), 404

        books_id = book["books_id"]
        available = book["available_copies"]

        # --------------------------------------
        # 6. Kiểm tra số lượng sách còn
        # --------------------------------------
        if available <= 0:
            return jsonify({
                "status": 400,
                "success": False,
                "message": "Sách đã hết, không thể mượn."
            }), 400

        # --------------------------------------
        # 7. Kiểm tra user đã mượn cuốn này nhưng chưa trả không
        # --------------------------------------
        cursor.execute("""
            SELECT * FROM borrow_return 
            WHERE user_id = %s AND books_id = %s AND status = 'Đang mượn'
        """, (user_id, books_id))
        already = cursor.fetchone()

        if already:
            return jsonify({
                "status": 409,
                "success": False,
                "message": "Bạn đang mượn cuốn sách này và chưa trả."
            }), 409

        # --------------------------------------
        # 8. Thêm bản ghi mượn sách
        # --------------------------------------
        cursor.execute("""
            INSERT INTO borrow_return (user_id, books_id, borrow_date, return_date, status, last_updated_by)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, books_id, borrow_date, return_date, status, name_user))

        # --------------------------------------
        # 9. Cập nhật thống kê sách
        # --------------------------------------
        cursor.execute("""
            UPDATE books 
            SET borrow_count = borrow_count + 1,
                available_copies = GREATEST(available_copies - 1, 0)
            WHERE books_id = %s
        """, (books_id,))

        conn.commit()

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Thêm bản ghi mượn sách thành công."
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"status": 500, "success": False, "message": f"Lỗi máy chủ: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()



@app.route("/api/edit_borrow_return", methods=["POST"])
def edit_borrow_return():
    data = request.get_json()

    # -------------------------------
    # 1. Kiểm tra API key & token
    # -------------------------------
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    datauser = data.get("datauser")
    if not datauser:
        return jsonify({"status": 400, "success": False, "message": "Thiếu dữ liệu datauser."}), 400

    token = data.get("token")
    if not token:
        return jsonify({"status": 401, "success": False, "message": "Thiếu token xác thực."}), 401

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        role_id = decoded.get("role")
        email_user = decoded.get("email")
        name_user = decoded.get("name") or email_user
    except jwt.ExpiredSignatureError:
        return jsonify({"success": False, "message": "Token hết hạn."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"success": False, "message": "Token không hợp lệ."}), 401

    # Chỉ Admin hoặc Thủ thư được sửa
    if role_id not in [1, 2]:
        return jsonify({"status": 403, "success": False, "message": "Bạn không có quyền sửa thông tin mượn sách."}), 403

    # -------------------------------
    # 2. Lấy dữ liệu từ client
    # -------------------------------
    borrow_id = datauser.get("borrow_id")
    user_name = datauser.get("user_name")
    book_title = datauser.get("book_title")
    borrow_date = datauser.get("borrow_date")
    due_date = datauser.get("due_date") or None
    return_date = datauser.get("return_date") or None
    status = datauser.get("status")

    if not borrow_id:
        return jsonify({"status": 400, "success": False, "message": "Thiếu borrow_id."}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # -------------------------------
        # 3. Lấy bản ghi cũ
        # -------------------------------
        cursor.execute("SELECT * FROM borrow_return WHERE borrow_id = %s", (borrow_id,))
        old = cursor.fetchone()

        if not old:
            return jsonify({"status": 404, "success": False, "message": "Không tìm thấy bản ghi mượn."}), 404

        old_books_id = old["books_id"]
        old_status = old["status"]

        # -------------------------------
        # 4. Lấy user_id mới
        # -------------------------------
        cursor.execute("SELECT id FROM users WHERE LOWER(name) = LOWER(%s) LIMIT 1", (user_name,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"status": 404, "success": False, "message": "Không tìm thấy người dùng."}), 404

        user_id = user["id"]

        # -------------------------------
        # 5. Lấy books_id mới
        # -------------------------------
        cursor.execute("SELECT books_id, available_copies FROM books WHERE LOWER(Title) = LOWER(%s) LIMIT 1",
                       (book_title,))
        book = cursor.fetchone()

        if not book:
            return jsonify({"status": 404, "success": False, "message": "Không tìm thấy sách."}), 404

        books_id = book["books_id"]
        available = book["available_copies"]

        # -------------------------------
        # 6. Nếu đổi sang SÁCH KHÁC → kiểm tra tồn kho
        # -------------------------------
        if books_id != old_books_id:
            if available <= 0:
                return jsonify({
                    "status": 400,
                    "success": False,
                    "message": "Sách mới đã hết, không thể đổi sang cuốn này."
                }), 400

            # Trả lại 1 bản cho sách cũ
            cursor.execute("""
                UPDATE books
                SET available_copies = available_copies + 1
                WHERE books_id = %s
            """, (old_books_id,))

            # Lấy 1 bản từ sách mới
            cursor.execute("""
                UPDATE books
                SET available_copies = available_copies - 1,
                    borrow_count = borrow_count + 1
                WHERE books_id = %s
            """, (books_id,))

        # -------------------------------
        # 7. Nếu đổi STATUS
        # -------------------------------
        if old_status != status:

            # Đang mượn → Đã trả
            if old_status == "Đang mượn" and status == "Đã trả":
                cursor.execute("""
                    UPDATE books 
                    SET available_copies = available_copies + 1
                    WHERE books_id = %s
                """, (books_id,))

            # Đã trả → Đang mượn
            if old_status == "Đã trả" and status == "Đang mượn":

                # Kiểm tra tồn kho
                if available <= 0:
                    return jsonify({
                        "status": 400,
                        "success": False,
                        "message": "Sách đã hết, không thể chuyển lại thành 'Đang mượn'."
                    }), 400

                cursor.execute("""
                    UPDATE books 
                    SET available_copies = available_copies - 1,
                        borrow_count = borrow_count + 1
                    WHERE books_id = %s
                """, (books_id,))

        # -------------------------------
        # 8. Cập nhật bản ghi borrow_return
        # -------------------------------
        cursor.execute("""
            UPDATE borrow_return
            SET user_id = %s,
                books_id = %s,
                borrow_date = %s,
                due_date = %s,
                return_date = %s,
                status = %s,
                last_updated_by = %s
            WHERE borrow_id = %s
        """, (user_id, books_id, borrow_date, due_date, return_date, status, name_user, borrow_id))

        conn.commit()

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Cập nhật thông tin mượn sách thành công."
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"status": 500, "success": False, "message": f"Lỗi máy chủ: {str(e)}"}), 500

    finally:
        cursor.close()
        conn.close()



@app.route("/api/return_book", methods=["POST"])
def return_book():
    data = request.get_json()

    if data.get("api_key") != API_KEY:
        return jsonify({"status": 403, "message": "API key không hợp lệ."}), 403

    borrow_id = data.get("borrow_id")
    return_date = data.get("return_date")

    if not borrow_id or not return_date:
        return jsonify({"status": 400, "message": "Thiếu thông tin borrow_id hoặc return_date."}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Lấy bản ghi mượn
        cursor.execute("SELECT * FROM borrow_return WHERE borrow_id = %s", (borrow_id,))
        br = cursor.fetchone()
        if not br:
            return jsonify({"status": 404, "message": "Không tìm thấy bản ghi mượn."}), 404

        due_date = br["due_date"]
        books_id = br["books_id"]

        # ✅ Tính tiền phạt nếu trễ (2000 VNĐ/ngày trễ)
        fine_amount = 0
        if due_date and return_date > str(due_date):
            cursor.execute("SELECT DATEDIFF(%s, %s) AS days_late", (return_date, due_date))
            days_late = cursor.fetchone()["days_late"]
            fine_amount = max(days_late * 2000, 0)

        # ✅ Cập nhật trạng thái, ngày trả, tiền phạt
        cursor.execute("""
            UPDATE borrow_return
            SET return_date = %s,
                status = 'Đã trả',
                fine_amount = %s
            WHERE borrow_id = %s
        """, (return_date, fine_amount, borrow_id))

        # ✅ Tăng lại số sách có sẵn
        cursor.execute("""
            UPDATE books
            SET available_copies = available_copies + 1
            WHERE books_id = %s
        """, (books_id,))

        conn.commit()
        return jsonify({
            "status": 200,
            "success": True,
            "message": "Cập nhật trả sách thành công.",
            "fine_amount": fine_amount
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"status": 500, "message": f"Lỗi máy chủ: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/book_view", methods=["POST"])
def book_view():
    data = request.get_json()
    books_id = data.get("books_id")

    if data.get("api_key") != API_KEY:
        return jsonify({"status": 403, "message": "API key không hợp lệ."}), 403

    if not books_id:
        return jsonify({"status": 400, "message": "Thiếu books_id."}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Tăng view_count mỗi lần xem
        cursor.execute("""
            UPDATE books
            SET view_count = view_count + 1
            WHERE books_id = %s
        """, (books_id,))
        conn.commit()

        cursor.execute("SELECT books_id, Title, view_count FROM books WHERE books_id = %s", (books_id,))
        book = cursor.fetchone()

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Cập nhật lượt xem thành công.",
            "data": book
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"status": 500, "message": f"Lỗi máy chủ: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/api/get_statistics", methods=["POST"])
def get_statistics():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ."
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1️⃣ Top 10 sách được mượn nhiều nhất
        cursor.execute("""
            SELECT 
                b.books_id, 
                b.Title AS book_title, 
                b.image,
                b.borrow_count 
            FROM books b
            ORDER BY b.borrow_count DESC 
            LIMIT 10
        """)
        top_books = cursor.fetchall()

        # 2️⃣ Top bạn đọc tích cực
        cursor.execute("""
            SELECT 
                u.id AS user_id,
                u.name AS user_name,
                u.email,
                u.borrow_count
            FROM users u
            ORDER BY u.borrow_count DESC
            LIMIT 10
        """)
        top_readers = cursor.fetchall()

        # 3️⃣ Biểu đồ mượn theo tháng (book_statistics)
        cursor.execute("""
            SELECT 
                DATE_FORMAT(stat_date, '%Y-%m') AS month,
                SUM(borrow_count) AS total_borrow,
                SUM(return_count) AS total_return
            FROM book_statistics
            GROUP BY month
            ORDER BY month ASC
        """)
        monthly_borrow = cursor.fetchall()

        # 4️⃣ Sách được đánh giá cao nhất
        cursor.execute("""
            SELECT 
                b.books_id,
                b.Title AS book_title,
                b.image,
                ROUND(AVG(r.rating), 2) AS avg_rating,
                COUNT(r.review_id) AS total_reviews
            FROM bookreview r
            JOIN books b ON r.books_id = b.books_id
            WHERE r.isActive = 1 AND r.is_approved = 1
            GROUP BY b.books_id
            HAVING total_reviews >= 1
            ORDER BY avg_rating DESC, total_reviews DESC
            LIMIT 10
        """)
        top_rated_books = cursor.fetchall()

        # 5️⃣ Tỷ lệ thể loại được mượn nhiều nhất
        cursor.execute("""
            SELECT 
                c.category_name,
                COUNT(br.books_id) AS total_borrowed,
                ROUND(
                    (COUNT(br.books_id) / (SELECT COUNT(*) FROM borrow_return)) * 100,
                    2
                ) AS percent_borrowed
            FROM borrow_return br
            JOIN books b ON br.books_id = b.books_id
            JOIN categories c ON b.category_id = c.category_id
            GROUP BY c.category_name
            ORDER BY total_borrowed DESC
        """)
        category_ratio = cursor.fetchall()

        # 6️⃣ Tổng số sách
        cursor.execute("SELECT COUNT(*) AS total_books FROM books WHERE IsPublic = 1")
        total_books_result = cursor.fetchone()
        total_books = total_books_result["total_books"] if total_books_result else 0

        # 7️⃣ Tổng số tài khoản
        cursor.execute("SELECT COUNT(*) AS total_users FROM users")
        total_users_result = cursor.fetchone()
        total_users = total_users_result["total_users"] if total_users_result else 0

        # 8️⃣ Số người đang mượn sách
        cursor.execute("""
            SELECT COUNT(DISTINCT user_id) AS active_borrowers 
            FROM borrow_return 
            WHERE status = 'Đang mượn' AND return_date IS NULL
        """)
        active_borrowers_result = cursor.fetchone()
        active_borrowers = active_borrowers_result["active_borrowers"] if active_borrowers_result else 0

        # ✅ Tổng hợp kết quả
        result = {
            "top_books": top_books,
            "top_readers": top_readers,
            "monthly_borrow": monthly_borrow,
            "top_rated_books": top_rated_books,
            "category_ratio": category_ratio,
            "total_books": total_books,
            "total_users": total_users,
            "active_borrowers": active_borrowers
        }

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Lấy báo cáo thống kê thành công.",
            "data": result
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/update_book_filepath", methods=["POST"])
def update_book_filepath():
    data = request.get_json()

    # 1. API key check
    if data.get("api_key") != API_KEY:
        return jsonify({"success": False, "message": "API key không hợp lệ."}), 403

    # 2. Token decoding and role check
    token = data.get("token")
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        role_id = decoded.get("role")
        if role_id not in [1, 2]:
            return jsonify({"success": False, "message": "Bạn không có quyền cập nhật sách."}), 403
    except Exception as e:
        return jsonify({"success": False, "message": f"Lỗi token: {e}"}), 401

    # 3. Get data from datauser
    datauser = data.get("datauser")
    if not datauser:
        return jsonify({"success": False, "message": "Thiếu dữ liệu datauser."}), 400

    books_id = datauser.get("books_id")
    image_path = datauser.get("image")
    file_path = datauser.get("file")

    if not books_id:
        return jsonify({"success": False, "message": "Thiếu books_id."}), 400
    
    if not image_path and not file_path:
        return jsonify({"success": False, "message": "Thiếu đường dẫn file (image hoặc file)."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if image_path:
            cursor.execute("UPDATE books SET image = %s WHERE books_id = %s", (image_path, books_id))
        
        if file_path:
            cursor.execute("UPDATE books SET file = %s WHERE books_id = %s", (file_path, books_id))

        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({"success": False, "message": "Không tìm thấy sách với ID này."}), 404

        return jsonify({"success": True, "message": "Cập nhật đường dẫn file thành công."}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Lỗi server: {str(e)}"}), 500

    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG)
