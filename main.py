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

from datetime import datetime, timedelta  # ✅ import đúng

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
    print(datauser.get("password"))
    print(user["pass"])
    print(password)
    if user["pass"] != password:
        return make_response(401, "Thông tin đăng nhập không đúng")

    # ✅ Tạo JWT token hợp lệ (15 ngày)
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
    print(datauser)
    email = datauser.get("email")

    if not email:
        return jsonify({"status": 400, "message": "Thiếu email"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ✅ Kiểm tra email có tồn tại trong bảng users
    cursor.execute("SELECT id, name FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({"status": 404, "message": "Email không tồn tại trong hệ thống"}), 404

    # ✅ Tạo token ngẫu nhiên 32 ký tự
    token = secrets.token_hex(16)  # 32 ký tự hex

    # ✅ Tính thời gian hết hạn (10 phút)
    exp_time = datetime.now() + timedelta(minutes=10)

    # ✅ Lưu token vào bảng tempusers
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

    # ✅ Bắt buộc có datauser
    if "datauser" not in data:
        return jsonify({"status": 400, "message": "Thiếu datauser"}), 400

    # ✅ Kiểm tra api_key ngoài datauser
    if data.get("api_key") != API_KEY:
        return jsonify({"status": 403, "message": "API key không hợp lệ"}), 403

    datauser = data["datauser"]

    # ✅ Lấy token từ body
    token = datauser.get("token")
    if not token:
        return jsonify({"status": 400, "message": "Thiếu token"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ✅ Kiểm tra token trong bảng tempusers
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

    # ✅ Kiểm tra thời hạn: không được quá 20 phút kể từ exp_time
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

    # ✅ Thành công
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

    # ✅ Bắt buộc có datauser
    if "datauser" not in data:
        return jsonify({"status": 400, "message": "Thiếu datauser"}), 400

    # ✅ Kiểm tra api_key ngoài datauser
    if data.get("api_key") != API_KEY:
        return jsonify({"status": 403, "message": "API key không hợp lệ"}), 403

    datauser = data["datauser"]
    password = datauser.get("password")
    token = datauser.get("token")

    if not password or not token:
        return jsonify({"status": 400, "message": "Thiếu password hoặc token"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ✅ Kiểm tra token có tồn tại không
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

    # ✅ Kiểm tra token còn hạn
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

    # ✅ Mã hoá mật khẩu (nếu cần bảo mật)
    # hashed_password = generate_password_hash(password)  # nếu có werkzeug.security
    hashed_password = hhuy.hash_key(password) 

    # ✅ Cập nhật mật khẩu trong bảng users
    cursor.execute("UPDATE users SET pass = %s WHERE id = %s", (hashed_password, user_id))
    conn.commit()

    # ✅ (Tuỳ chọn) Xoá token sau khi sử dụng
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

    # ✅ Lấy dữ liệu từ bảng books (có join tác giả, thể loại, NXB)
    cursor.execute("""
        SELECT 
            b.books_id,
            b.Title,
            b.Description,
            a.author_name AS Author,
            c.category_name AS Category,
            b.ISBN,
            b.PublishYear,
            p.publisher_name AS Publisher,
            b.Language,
            b.DocumentType,
            b.UploadDate,
            b.UploadedBy,
            b.image,
            b.rate
        FROM books b
        LEFT JOIN authors a ON b.author_id = a.author_id
        LEFT JOIN categories c ON b.category_id = c.category_id
        LEFT JOIN publishers p ON b.publisher_id = p.publisher_id
        WHERE b.IsPublic = 1
        ORDER BY b.UploadDate DESC
    """)

    books = cursor.fetchall()

    cursor.close()
    conn.close()

    # ✅ Trường hợp không có sách
    if not books:
        return jsonify({
            "status": 404,
            "success": False,
            "message": "Không có sách nào trong hệ thống."
        }), 404

    # ✅ Thành công
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

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
        }), 403

    datauser = data.get("datauser")
    token = data.get("token")

    # ✅ Giải mã token (nếu có)
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

    # ✅ Lấy dữ liệu từ datauser
    books_id = datauser.get("books_id")
    rating = datauser.get("rating")  # Có thể None
    comment = datauser.get("comment")

    # ✅ Kiểm tra tối thiểu: phải có books_id
    if not books_id:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu thông tin bắt buộc: books_id"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # ✅ Thêm dữ liệu (user_id và rating có thể NULL)
        cursor.execute("""
            INSERT INTO bookreview (user_id, books_id, rating, comment, review_date, isActive)
            VALUES (%s, %s, %s, %s, NOW(), 0)
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



@app.route("/api/show_book_reviews", methods=["POST"])
def show_book_reviews():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
        }), 403

    datauser = data.get("datauser")
    books_id = datauser.get("booksId") if datauser else None

    # ✅ Kiểm tra đầu vào
    if not books_id:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu books_id"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Lấy dữ liệu đánh giá từ bảng bookreview
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

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Lấy danh sách đánh giá thành công!",
            "data": reviews
        }), 200

    except Exception as e:
        print(e)
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

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
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
                "success": False,
                "message": "Token hết hạn."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "success": False,
                "message": "Token không hợp lệ."
            }), 401

    # ✅ Nếu không có role_id thì từ chối
    if role_id is None:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu thông tin role trong token."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ role_id = 1 → Lấy toàn bộ sách
        if role_id == 1:
            cursor.execute("SELECT * FROM books")
            result = cursor.fetchall()

        # ✅ role_id = 2 → Lấy sách theo email người dùng
        elif role_id == 2:
            if not email_user:
                return jsonify({
                    "status": 400,
                    "success": False,
                    "message": "Không tìm thấy email trong token."
                }), 400
            cursor.execute("SELECT * FROM books WHERE email = %s", (email_user,))
            result = cursor.fetchall()

        # ✅ role_id = 3 → Không có quyền xem
        elif role_id == 3:
            return jsonify({
                "status": 403,
                "success": False,
                "message": "Bạn không có quyền truy cập dữ liệu này."
            }), 403

        # ✅ Trả kết quả
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


@app.route("/api/del_book_admin", methods=["POST"])
def del_book_admin():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
        }), 403

    # ✅ Lấy thông tin người dùng gửi lên
    datauser = data.get("datauser")
    if not datauser:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu dữ liệu datauser"
        }), 400

    books_id = datauser.get("books_id")
    if not books_id:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu mã sách (books_id)"
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

    # ✅ Kiểm tra role
    if role_id not in [1, 2, 3]:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Role không hợp lệ."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ role_id = 1 → Có thể xóa bất kỳ sách nào
        if role_id == 1:
            cursor.execute("DELETE FROM books WHERE books_id = %s", (books_id,))
            conn.commit()
            return jsonify({
                "status": 200,
                "success": True,
                "message": f"Đã xóa sách có ID {books_id}."
            }), 200

        # ✅ role_id = 2 → Chỉ được xóa sách do chính người đó thêm
        elif role_id == 2:
            cursor.execute("SELECT email FROM books WHERE books_id = %s", (books_id,))
            book = cursor.fetchone()

            if not book:
                return jsonify({
                    "status": 404,
                    "success": False,
                    "message": "Không tìm thấy sách cần xóa."
                }), 404

            if book["email"] != email_user:
                return jsonify({
                    "status": 403,
                    "success": False,
                    "message": "Bạn không có quyền xóa sách này."
                }), 403

            cursor.execute("DELETE FROM books WHERE books_id = %s", (books_id,))
            conn.commit()
            return jsonify({
                "status": 200,
                "success": True,
                "message": f"Đã xóa sách có ID {books_id} của bạn."
            }), 200

        # ✅ role_id = 3 → Không có quyền xóa
        elif role_id == 3:
            return jsonify({
                "status": 403,
                "success": False,
                "message": "Bạn không có quyền xóa sách."
            }), 403

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
@app.route("/api/get_authors_and_categories", methods=["POST"])
def get_authors_and_categories():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
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

    # ✅ Kiểm tra role
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền truy cập dữ liệu này."
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Lấy toàn bộ dữ liệu bảng authors
        cursor.execute("SELECT * FROM authors")
        authors = cursor.fetchall()

        # ✅ Lấy toàn bộ dữ liệu bảng categories
        cursor.execute("SELECT * FROM categories")
        categories = cursor.fetchall()

        return jsonify({
            "status": 200,
            "success": True,
            "authors": authors,
            "categories": categories
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


@app.route("/api/add_book_admin1", methods=["POST"])
def add_book_admin():
    data = request.get_json()

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
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

    # ✅ Chỉ role_id = 1 và 2 được phép thêm
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền thêm sách."
        }), 403

    # ✅ Lấy thông tin sách từ datauser
    title = datauser.get("Title")
    publish_year = datauser.get("PublishYear")
    language = datauser.get("Language")
    document_type = datauser.get("DocumentType")
    author_id = datauser.get("author_id")
    category_id = datauser.get("category_id")

    # ✅ Kiểm tra dữ liệu bắt buộc
    if not all([title, publish_year, language, document_type, author_id, category_id]):
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu thông tin bắt buộc để thêm sách."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Thêm sách vào bảng books
        cursor.execute("""
            INSERT INTO books (Title, PublishYear, Language, DocumentType, author_id, category_id, email)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (title, publish_year, language, document_type, author_id, category_id, email_user))
        conn.commit()

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Thêm sách thành công."
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

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
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

    # ✅ Chỉ role_id = 1 mới có quyền xem danh sách user
    if role_id != 1:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền xem danh sách người dùng."
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Lấy toàn bộ dữ liệu bảng users
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

    # ✅ Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
        }), 403

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

    # ✅ Chỉ role_id = 1 được phép chỉnh sửa email
    if role_id != 1:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền thay đổi email người dùng."
        }), 403

    # ✅ Lấy dữ liệu người dùng gửi lên
    datauser = data.get("datauser")
    if not datauser:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu dữ liệu datauser."
        }), 400

    old_email = datauser.get("oldEmail")
    new_email = datauser.get("newEmail")

    # ✅ Kiểm tra email
    if not old_email or not new_email:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu email cũ hoặc email mới."
        }), 400

    # ✅ Nếu email mới giống email cũ → từ chối
    if old_email == new_email:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Email mới phải khác email cũ."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Kiểm tra xem email cũ có tồn tại không
        cursor.execute("SELECT * FROM users WHERE email = %s", (old_email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({
                "status": 404,
                "success": False,
                "message": "Không tìm thấy người dùng với email cũ."
            }), 404

        # ✅ Kiểm tra nếu email mới đã tồn tại
        cursor.execute("SELECT * FROM users WHERE email = %s", (new_email,))
        exists = cursor.fetchone()
        if exists:
            return jsonify({
                "status": 400,
                "success": False,
                "message": "Email mới đã tồn tại trong hệ thống."
            }), 400

        # ✅ Cập nhật email
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



@app.route("/api/edit_pass_admin", methods=["POST"])
def edit_pass_admin():
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

    # ✅ Chỉ admin (role_id = 1) được phép đổi mật khẩu
    if role_id != 1:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền thay đổi mật khẩu người dùng khác."
        }), 403

    # ✅ Lấy dữ liệu người dùng cần cập nhật
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
        # ✅ Mã hóa mật khẩu mới trước khi lưu
        hashed_pass = new_pass

        # ✅ Cập nhật mật khẩu
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

    # ✅ Chỉ Admin mới có quyền xóa user
    if role_id != 1:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền xóa người dùng."
        }), 403

    # ✅ Lấy dữ liệu người dùng cần xóa
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
        # ✅ Xóa người dùng theo email
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




if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG)
