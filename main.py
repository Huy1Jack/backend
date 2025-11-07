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
    print(datauser)
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

    #   Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    #   Lấy dữ liệu từ bảng books (có join tác giả, thể loại, NXB)
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

    #   Trường hợp không có sách
    if not books:
        return jsonify({
            "status": 404,
            "success": False,
            "message": "Không có sách nào trong hệ thống."
        }), 404

    #   Thành công
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

    #   Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
        }), 403

    datauser = data.get("datauser")
    books_id = datauser.get("booksId") if datauser else None

    #   Kiểm tra đầu vào
    if not books_id:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu books_id"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        #   Lấy dữ liệu đánh giá từ bảng bookreview
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
            return jsonify({"success": False, "message": "Token hết hạn."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Token không hợp lệ."}), 401
    else:
        return jsonify({
            "status": 401,
            "success": False,
            "message": "Thiếu token xác thực."
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
            cursor.execute("""
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
                    c.category_name,
                    p.publisher_name,
                    GROUP_CONCAT(a.author_name SEPARATOR ', ') AS authors
                FROM books b
                LEFT JOIN categories c ON b.category_id = c.category_id
                LEFT JOIN publishers p ON b.publisher_id = p.publisher_id
                LEFT JOIN book_authors ba ON b.books_id = ba.book_id
                LEFT JOIN authors a ON ba.author_id = a.author_id
                GROUP BY b.books_id
                ORDER BY b.books_id DESC
            """)
            result = cursor.fetchall()

        # ✅ role_id = 2 → Lấy sách do chính người dùng upload
        elif role_id == 2:
            cursor.execute("""
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
                    c.category_name,
                    p.publisher_name,
                    GROUP_CONCAT(a.author_name SEPARATOR ', ') AS authors
                FROM books b
                LEFT JOIN categories c ON b.category_id = c.category_id
                LEFT JOIN publishers p ON b.publisher_id = p.publisher_id
                LEFT JOIN book_authors ba ON b.books_id = ba.book_id
                LEFT JOIN authors a ON ba.author_id = a.author_id
                WHERE b.UploadedBy = %s
                GROUP BY b.books_id
                ORDER BY b.books_id DESC
            """, (email_user,))
            result = cursor.fetchall()

        # ✅ role_id = 3 → Không có quyền xem
        else:
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

    #   Kiểm tra API key
    if data.get("api_key") != API_KEY:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "API key không hợp lệ"
        }), 403

    #   Lấy thông tin người dùng gửi lên
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

    #   Kiểm tra role
    if role_id not in [1, 2, 3]:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Role không hợp lệ."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        #   role_id = 1 → Có thể xóa bất kỳ sách nào
        if role_id == 1:
            cursor.execute("DELETE FROM books WHERE books_id = %s", (books_id,))
            conn.commit()
            return jsonify({
                "status": 200,
                "success": True,
                "message": f"Đã xóa sách có ID {books_id}."
            }), 200

        #   role_id = 2 → Chỉ được xóa sách do chính người đó thêm
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

        #   role_id = 3 → Không có quyền xóa
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

    #   Kiểm tra role
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền truy cập dữ liệu này."
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        #   Lấy toàn bộ dữ liệu bảng authors
        cursor.execute("SELECT * FROM authors")
        authors = cursor.fetchall()

        #   Lấy toàn bộ dữ liệu bảng categories
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

@app.route("/api/get_publishers", methods=["POST"])
def get_publishers():
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

    # ✅ Kiểm tra role hợp lệ
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền truy cập dữ liệu này."
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Lấy toàn bộ dữ liệu từ bảng publishers
        cursor.execute("SELECT * FROM publishers")
        publishers = cursor.fetchall()

        return jsonify({
            "status": 200,
            "success": True,
            "publishers": publishers
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


@app.route("/api/add_book_admin1", methods=["POST"])
def add_book_admin():
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
            "message": "Bạn không có quyền thêm sách."
        }), 403

    # ✅ Lấy thông tin sách từ datauser
    title = datauser.get("Title")
    description = datauser.get("Description")
    isbn = datauser.get("ISBN")
    publish_year = datauser.get("PublishYear")
    language = datauser.get("Language")
    document_type = datauser.get("DocumentType")
    publisher_id = datauser.get("publisher_id")
    category_id = datauser.get("category_id")
    author_ids = datauser.get("author_ids")  # Danh sách nhiều tác giả [1,2,3,...]
    image = datauser.get("image")
    is_public = datauser.get("IsPublic", 1)

    # ✅ Kiểm tra dữ liệu bắt buộc
    if not all([title, publish_year, language, document_type, publisher_id, category_id]):
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu thông tin bắt buộc để thêm sách."
        }), 400

    # ✅ Kiểm tra danh sách tác giả
    if not author_ids or not isinstance(author_ids, list):
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Danh sách tác giả không hợp lệ (phải là mảng)."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Thêm vào bảng books
        cursor.execute("""
            INSERT INTO books 
            (Title, Description, ISBN, PublishYear, Language, DocumentType, publisher_id, category_id, UploadedBy, image, IsPublic)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            title, description, isbn, publish_year, language, document_type,
            publisher_id, category_id, email_user, image, is_public
        ))
        conn.commit()

        # ✅ Lấy id sách vừa thêm
        book_id = cursor.lastrowid

        # ✅ Thêm nhiều tác giả vào bảng book_authors
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


@app.route("/api/edit_book_admin", methods=["POST"])
def edit_book_admin():
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
    email_user = None

    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
            email_user = decoded.get("email")
        except jwt.ExpiredSignatureError:
            return jsonify({"status": 401, "success": False, "message": "Token hết hạn."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"status": 401, "success": False, "message": "Token không hợp lệ."}), 401
    else:
        return jsonify({"status": 401, "success": False, "message": "Thiếu token xác thực."}), 401

    # ✅ Chỉ role_id = 1 hoặc 2 được phép chỉnh sửa
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền chỉnh sửa sách."
        }), 403

    # ✅ Lấy dữ liệu từ client
    datauser = data.get("datauser")
    if not datauser:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu dữ liệu datauser."
        }), 400

    # ✅ Lấy các thông tin cần cập nhật
    books_id = datauser.get("books_id")
    title = datauser.get("Title")
    description = datauser.get("Description")
    isbn = datauser.get("ISBN")
    publish_year = datauser.get("PublishYear")
    language = datauser.get("Language")
    document_type = datauser.get("DocumentType")
    publisher_id = datauser.get("publisher_id")
    category_id = datauser.get("category_id")
    author_ids = datauser.get("author_ids")  # Mảng [1, 2, 3]
    image = datauser.get("image")
    is_public = datauser.get("IsPublic", 1)

    # ✅ Kiểm tra dữ liệu bắt buộc
    if not books_id or not title:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu books_id hoặc tiêu đề sách."
        }), 400

    if not author_ids or not isinstance(author_ids, list) or len(author_ids) == 0:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Danh sách tác giả không hợp lệ (phải là mảng và không rỗng)."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Kiểm tra sách tồn tại không
        cursor.execute("SELECT * FROM books WHERE books_id = %s", (books_id,))
        book = cursor.fetchone()
        if not book:
            return jsonify({
                "status": 404,
                "success": False,
                "message": "Không tìm thấy sách với ID này."
            }), 404

        # ✅ Cập nhật thông tin bảng books
        cursor.execute("""
            UPDATE books
            SET Title = %s,
                Description = %s,
                ISBN = %s,
                PublishYear = %s,
                Language = %s,
                DocumentType = %s,
                publisher_id = %s,
                category_id = %s,
                UploadedBy = %s,
                image = %s,
                IsPublic = %s
            WHERE books_id = %s
        """, (
            title, description, isbn, publish_year, language, document_type,
            publisher_id, category_id, email_user, image, is_public, books_id
        ))
        conn.commit()

        # ✅ Xóa toàn bộ liên kết tác giả cũ
        cursor.execute("DELETE FROM book_authors WHERE book_id = %s", (books_id,))
        conn.commit()

        # ✅ Thêm mới danh sách tác giả
        for author_id in author_ids:
            cursor.execute("""
                INSERT INTO book_authors (book_id, author_id)
                VALUES (%s, %s)
            """, (books_id, author_id))
        conn.commit()

        # ✅ Lấy lại dữ liệu sách sau cập nhật
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
            "status": 200,
            "success": True,
            "message": "Cập nhật thông tin sách thành công.",
            "updated_book": updated_book
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
    email_user = None

    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            role_id = decoded.get("role")
            email_user = decoded.get("email")
        except jwt.ExpiredSignatureError:
            return jsonify({"status": 401, "success": False, "message": "Token hết hạn."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"status": 401, "success": False, "message": "Token không hợp lệ."}), 401
    else:
        return jsonify({"status": 401, "success": False, "message": "Thiếu token xác thực."}), 401

    # ✅ Chỉ role_id = 1 hoặc 2 được phép chỉnh sửa
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền chỉnh sửa sách."
        }), 403

    # ✅ Lấy dữ liệu người dùng gửi lên
    datauser = data.get("datauser")
    if not datauser:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu dữ liệu datauser."
        }), 400

    # ✅ Lấy thông tin cần cập nhật
    books_id = datauser.get("books_id")
    title = datauser.get("Title")
    description = datauser.get("Description")
    isbn = datauser.get("ISBN")
    publish_year = datauser.get("PublishYear")
    language = datauser.get("Language")
    document_type = datauser.get("DocumentType")
    publisher_id = datauser.get("publisher_id")
    category_id = datauser.get("category_id")
    author_ids = datauser.get("author_ids")  # Danh sách nhiều tác giả [1,2,3,...]
    image = datauser.get("image")
    is_public = datauser.get("IsPublic", 1)

    # ✅ Kiểm tra dữ liệu bắt buộc
    if not books_id or not title:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu books_id hoặc Title để cập nhật."
        }), 400

    if not author_ids or not isinstance(author_ids, list):
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Danh sách tác giả không hợp lệ (phải là mảng)."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Kiểm tra xem sách có tồn tại không
        cursor.execute("SELECT * FROM books WHERE books_id = %s", (books_id,))
        book = cursor.fetchone()
        if not book:
            return jsonify({
                "status": 404,
                "success": False,
                "message": "Không tìm thấy sách với ID này."
            }), 404

        # ✅ Cập nhật thông tin sách
        cursor.execute("""
            UPDATE books 
            SET Title = %s,
                Description = %s,
                ISBN = %s,
                PublishYear = %s,
                Language = %s,
                DocumentType = %s,
                publisher_id = %s,
                category_id = %s,
                UploadedBy = %s,
                image = %s,
                IsPublic = %s
            WHERE books_id = %s
        """, (
            title, description, isbn, publish_year, language, document_type,
            publisher_id, category_id, email_user, image, is_public, books_id
        ))
        conn.commit()

        # ✅ Xóa toàn bộ liên kết tác giả cũ
        cursor.execute("DELETE FROM book_authors WHERE book_id = %s", (books_id,))
        conn.commit()

        # ✅ Thêm lại danh sách tác giả mới
        for author_id in author_ids:
            cursor.execute("""
                INSERT INTO book_authors (book_id, author_id)
                VALUES (%s, %s)
            """, (books_id, author_id))
        conn.commit()

        # ✅ Lấy lại dữ liệu sách sau khi cập nhật
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
            "status": 200,
            "success": True,
            "message": "Cập nhật thông tin sách thành công.",
            "updated_book": updated_book
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
            return jsonify({"status": 401, "success": False, "message": "Token hết hạn."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"status": 401, "success": False, "message": "Token không hợp lệ."}), 401
    else:
        return jsonify({"status": 401, "success": False, "message": "Thiếu token xác thực."}), 401

    # ✅ Chỉ role_id = 1 hoặc 2 được phép chỉnh sửa
    if role_id not in [1, 2]:
        return jsonify({
            "status": 403,
            "success": False,
            "message": "Bạn không có quyền chỉnh sửa sách."
        }), 403

    # ✅ Lấy dữ liệu người dùng gửi lên
    datauser = data.get("datauser")
    if not datauser:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu dữ liệu datauser."
        }), 400

    # ✅ Lấy thông tin cập nhật
    books_id = datauser.get("books_id")
    title = datauser.get("Title")
    description = datauser.get("Description")
    isbn = datauser.get("ISBN")
    publish_year = datauser.get("PublishYear")
    language = datauser.get("Language")
    document_type = datauser.get("DocumentType")
    is_public = datauser.get("IsPublic", 1)
    image = datauser.get("image")
    uploaded_by = datauser.get("UploadedBy")

    category_name = datauser.get("category_name")
    publisher_name = datauser.get("publisher_name")
    author_names = datauser.get("authors")  # Chuỗi: "A, B, C"

    if not books_id or not title:
        return jsonify({
            "status": 400,
            "success": False,
            "message": "Thiếu books_id hoặc tiêu đề sách."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Lấy publisher_id theo tên
        publisher_id = None
        if publisher_name:
            cursor.execute("SELECT publisher_id FROM publishers WHERE publisher_name = %s", (publisher_name,))
            pub = cursor.fetchone()
            if pub:
                publisher_id = pub["publisher_id"]
            else:
                cursor.execute("INSERT INTO publishers (publisher_name) VALUES (%s)", (publisher_name,))
                conn.commit()
                publisher_id = cursor.lastrowid

        # ✅ Lấy category_id theo tên
        category_id = None
        if category_name:
            cursor.execute("SELECT category_id FROM categories WHERE category_name = %s", (category_name,))
            cat = cursor.fetchone()
            if cat:
                category_id = cat["category_id"]
            else:
                cursor.execute("INSERT INTO categories (category_name) VALUES (%s)", (category_name,))
                conn.commit()
                category_id = cursor.lastrowid

        # ✅ Cập nhật thông tin bảng books
        cursor.execute("""
            UPDATE books
            SET Title = %s,
                Description = %s,
                ISBN = %s,
                PublishYear = %s,
                Language = %s,
                DocumentType = %s,
                UploadedBy = %s,
                IsPublic = %s,
                image = %s,
                publisher_id = %s,
                category_id = %s
            WHERE books_id = %s
        """, (
            title, description, isbn, publish_year, language, document_type,
            uploaded_by, is_public, image, publisher_id, category_id, books_id
        ))
        conn.commit()

        # ✅ Xử lý danh sách tác giả
        if author_names:
            author_list = [a.strip() for a in author_names.split(",") if a.strip()]

            # Xóa toàn bộ liên kết cũ
            cursor.execute("DELETE FROM book_authors WHERE book_id = %s", (books_id,))
            conn.commit()

            # Thêm lại từng tác giả
            for name in author_list:
                cursor.execute("SELECT author_id FROM authors WHERE author_name = %s", (name,))
                author = cursor.fetchone()
                if author:
                    author_id = author["author_id"]
                else:
                    cursor.execute("INSERT INTO authors (author_name) VALUES (%s)", (name,))
                    conn.commit()
                    author_id = cursor.lastrowid

                cursor.execute(
                    "INSERT INTO book_authors (book_id, author_id) VALUES (%s, %s)",
                    (books_id, author_id)
                )
            conn.commit()

        # ✅ Lấy lại dữ liệu sau khi cập nhật
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
            "status": 200,
            "success": True,
            "message": "Cập nhật thông tin sách thành công.",
            "updated_book": updated_book
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
        print("🔥 Lỗi xóa danh mục:", e)
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
        print("🔥 Lỗi thêm danh mục:", e)
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
        print("🔥 Lỗi khi cập nhật danh mục:", e)
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500

    finally:
        cursor.close()
        conn.close()

# ===============================
# 📚 GET BORROW_RETURN
# ===============================
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

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Bước 1: Cập nhật trạng thái 'Quá hạn' tự động
        cursor.execute("""
            UPDATE borrow_return
            SET status = 'Quá hạn'
            WHERE status = 'Đang mượn'
              AND return_date IS NOT NULL
              AND return_date < CURDATE()
        """)
        conn.commit()

        # ✅ Bước 2: Truy vấn danh sách sau khi cập nhật
        if role_id in [1, 2]:
            cursor.execute("""
                SELECT br.borrow_id,
                       u.name AS user_name,
                       b.Title AS book_title,
                       br.borrow_date,
                       br.return_date,
                       br.status,
                       br.last_updated_by
                FROM borrow_return br
                JOIN users u ON br.user_id = u.id
                JOIN books b ON br.books_id = b.books_id
                ORDER BY br.borrow_date DESC
            """)
        else:
            cursor.execute("""
                SELECT br.borrow_id,
                       b.Title AS book_title,
                       br.borrow_date,
                       br.return_date,
                       br.status,
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
        print(e)
        return jsonify({
            "status": 500,
            "success": False,
            "message": f"Lỗi máy chủ: {str(e)}"
        }), 500
    finally:
        cursor.close()
        conn.close()



# ===============================
# 📚 ADD BORROW_RETURN
# ===============================
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

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        role_id = decoded.get("role")
        email_user = decoded.get("email")
        name_user = decoded.get("name") or email_user
    except jwt.ExpiredSignatureError:
        return jsonify({"success": False, "message": "Token hết hạn."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"success": False, "message": "Token không hợp lệ."}), 401

    if role_id not in [1, 2]:
        return jsonify({"status": 403, "success": False, "message": "Bạn không có quyền thêm bản ghi mượn sách."}), 403

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
        # ✅ Tìm user_id và books_id
        cursor.execute("SELECT id FROM users WHERE name = %s LIMIT 1", (user_name,))
        user = cursor.fetchone()
        cursor.execute("SELECT books_id FROM books WHERE Title = %s LIMIT 1", (book_title,))
        book = cursor.fetchone()

        if not user or not book:
            return jsonify({"status": 404, "success": False, "message": "Không tìm thấy người dùng hoặc sách."}), 404

        user_id = user["id"]
        books_id = book["books_id"]

        # ✅ Thêm dữ liệu + tên người cập nhật
        cursor.execute("""
            INSERT INTO borrow_return (user_id, books_id, borrow_date, return_date, status, last_updated_by)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, books_id, borrow_date, return_date, status, name_user))
        conn.commit()

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Thêm bản ghi mượn sách thành công."
        }), 200

    except Exception as e:
        conn.rollback()
        print(e)
        return jsonify({"status": 500, "success": False, "message": f"Lỗi máy chủ: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()


# ===============================
# 📚 EDIT BORROW_RETURN
# ===============================
@app.route("/api/edit_borrow_return", methods=["POST"])
def edit_borrow_return():
    data = request.get_json()
    if data.get("api_key") != API_KEY:
        return jsonify({"status": 403, "success": False, "message": "API key không hợp lệ."}), 403

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

    if role_id not in [1, 2]:
        return jsonify({"status": 403, "success": False, "message": "Bạn không có quyền sửa thông tin mượn sách."}), 403

    borrow_id = datauser.get("borrow_id")
    user_name = datauser.get("user_name")
    book_title = datauser.get("book_title")
    borrow_date = datauser.get("borrow_date")
    return_date = datauser.get("return_date")
    status = datauser.get("status")

    if not borrow_id:
        return jsonify({"status": 400, "success": False, "message": "Thiếu borrow_id."}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ✅ Kiểm tra record tồn tại
        cursor.execute("SELECT * FROM borrow_return WHERE borrow_id = %s", (borrow_id,))
        record = cursor.fetchone()
        if not record:
            return jsonify({"status": 404, "success": False, "message": "Không tìm thấy bản ghi mượn này."}), 404

        # ✅ Tìm user_id và books_id
        cursor.execute("SELECT id FROM users WHERE name = %s LIMIT 1", (user_name,))
        user = cursor.fetchone()
        cursor.execute("SELECT books_id FROM books WHERE Title = %s LIMIT 1", (book_title,))
        book = cursor.fetchone()

        if not user or not book:
            return jsonify({"status": 404, "success": False, "message": "Không tìm thấy người dùng hoặc sách."}), 404

        user_id = user["id"]
        books_id = book["books_id"]

        # ✅ Cập nhật bản ghi
        cursor.execute("""
            UPDATE borrow_return
            SET user_id = %s,
                books_id = %s,
                borrow_date = %s,
                return_date = %s,
                status = %s,
                last_updated_by = %s
            WHERE borrow_id = %s
        """, (user_id, books_id, borrow_date, return_date, status, name_user, borrow_id))
        conn.commit()

        return jsonify({
            "status": 200,
            "success": True,
            "message": "Cập nhật thông tin mượn sách thành công."
        }), 200

    except Exception as e:
        conn.rollback()
        print(e)
        return jsonify({"status": 500, "success": False, "message": f"Lỗi máy chủ: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG)
