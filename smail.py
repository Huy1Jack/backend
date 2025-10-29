# mailer.py
import os
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage
from typing import Dict, Any

# Load .env
load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "True").lower() in ("1", "true", "yes")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER)
FROM_NAME = os.getenv("FROM_NAME", "No-Reply")


def _build_html(name: str, link: str, content: str) -> str:
    """
    Tạo HTML đẹp với CSS nội tuyến.
    - name: tên người nhận để chào
    - link: liên kết cho hành động (data)
    - content: mô tả hành động (ví dụ: 'đặt lại mật khẩu')
    """
    safe_name = name or "Bạn"
    safe_content = content or "thực hiện hành động"
    html = f"""\
<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{safe_content}</title>
</head>
<body style="margin:0;padding:0;background:#f4f6f8;font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial;">
  <table role="presentation" width="100%" style="border-collapse:collapse;">
    <tr>
      <td align="center" style="padding:30px 10px;">
        <table role="presentation" style="width:600px;max-width:100%;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 10px 30px rgba(17,24,39,0.08);">
          <tr>
            <td style="padding:28px 36px 8px 36px;">
              <h1 style="margin:0;font-size:20px;color:#0f172a;">Xin chào {safe_name},</h1>
              <p style="margin:12px 0 18px;color:#475569;line-height:1.5;">
                Vui lòng nhấp vào nút bên dưới để <strong>{safe_content}</strong>.
              </p>
              <p style="text-align:center;margin:22px 0;">
                <a href="{link}"
                   style="display:inline-block;padding:12px 22px;border-radius:10px;text-decoration:none;font-weight:600;background:linear-gradient(90deg,#2563eb,#7c3aed);color:#ffffff;box-shadow:0 6px 18px rgba(37,99,235,0.24);">
                  {safe_content}
                </a>
              </p>
              <p style="margin:6px 0 0;color:#94a3b8;font-size:13px;">
                Nếu nút không hoạt động, hãy sao chép dán đường dẫn sau vào trình duyệt:
              </p>
              <p style="word-break:break-all;color:#334155;font-size:13px;margin:6px 0 0;"><a href="{link}" style="color:#2563eb;text-decoration:none;">{link}</a></p>
            </td>
          </tr>
          <tr>
            <td style="background:#f8fafc;padding:18px 36px;border-top:1px solid #eef2f7;color:#64748b;font-size:13px;">
              <div>Trân trọng,<br><strong>{FROM_NAME}</strong></div>
            </td>
          </tr>
        </table>
        <p style="color:#94a3b8;font-size:12px;margin-top:14px;">Email này được gửi tự động. Vui lòng không trả lời.</p>
      </td>
    </tr>
  </table>
</body>
</html>
"""
    return html


def send_mail(name: str, email: str, data: str, content: str) -> Dict[str, Any]:
    """
    Gửi mail HTML.
    - name: tên người nhận (để chào)
    - email: địa chỉ email người nhận
    - data: liên kết (URL) mà người nhận sẽ click
    - content: mô tả hành động (ví dụ 'đặt lại mật khẩu')
    Trả về dict: {"success": bool, "message": str}
    """
    if not all([SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, FROM_EMAIL]):
        return {"success": False, "message": "Cấu hình SMTP thiếu trong .env"}

    if not email:
        return {"success": False, "message": "Thiếu email người nhận"}

    # Tạo message
    msg = EmailMessage()
    subject = f"{content} — {FROM_NAME}"
    msg['Subject'] = subject
    msg['From'] = f"{FROM_NAME} <{FROM_EMAIL}>"
    msg['To'] = email

    html_content = _build_html(name, data, content)
    # Plain fallback text
    plain_text = f"Xin chào {name or 'Bạn'},\n\nVui lòng mở liên kết sau để {content}:\n{data}\n\nNếu không gửi yêu cầu, hãy bỏ qua email này."

    msg.set_content(plain_text)
    msg.add_alternative(html_content, subtype='html')

    try:
        if SMTP_USE_TLS:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20)

        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        return {"success": True, "message": "Email đã được gửi"}
    except Exception as e:
        return {"success": False, "message": f"Lỗi khi gửi email: {e}"}
