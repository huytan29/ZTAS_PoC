from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

ROOT = Path(r"E:\ZTAS_PoC")
OUT = ROOT / "output" / "pdf" / "ZTAS_Quy_trinh_kiem_thu_va_kich_ban_thu_nghiem.pdf"
OUT.parent.mkdir(parents=True, exist_ok=True)
font = r"C:\Windows\Fonts\arial.ttf"
bold = r"C:\Windows\Fonts\arialbd.ttf"
pdfmetrics.registerFont(TTFont("Arial", font))
pdfmetrics.registerFont(TTFont("ArialBold", bold))

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="VNTitle", parent=styles["Title"], fontName="ArialBold", fontSize=21, leading=27, textColor=colors.HexColor("#102A4C"), alignment=TA_CENTER, spaceAfter=14))
styles.add(ParagraphStyle(name="VNHeading", parent=styles["Heading2"], fontName="ArialBold", fontSize=13, leading=17, textColor=colors.HexColor("#1F5EA8"), spaceBefore=12, spaceAfter=6))
styles.add(ParagraphStyle(name="VNBody", parent=styles["BodyText"], fontName="Arial", fontSize=9.2, leading=13, spaceAfter=5))
styles.add(ParagraphStyle(name="VNSmall", parent=styles["BodyText"], fontName="Arial", fontSize=7.4, leading=9.3))

def p(text, style="VNBody"):
    return Paragraph(text, styles[style])

def table(rows, widths):
    data = [[p(c, "VNSmall") for c in row] for row in rows]
    t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#173A63")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "ArialBold"),
        ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#AAB9C9")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 5), ("RIGHTPADDING", (0,0), (-1,-1), 5),
        ("TOPPADDING", (0,0), (-1,-1), 5), ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F3F7FB")]),
    ]))
    return t

story = [p("ZTAS - QUY TRÌNH KIỂM THỬ VÀ KỊCH BẢN THỬ NGHIỆM", "VNTitle"),
         p("Tài liệu phục vụ demo, kiểm thử chấp nhận và đánh giá luận văn thạc sĩ", "VNBody"), Spacer(1, 8)]
story += [p("1. Mục tiêu và phạm vi", "VNHeading"),
          p("Xác minh ZTAS áp dụng Zero Trust cho truy cập tài liệu: xác thực tài khoản, ràng buộc thiết bị, RBAC/PBAC 5 cấp, Step-up MFA, HTTPS nội bộ, audit log tập trung và thu hồi quyền."),
          table([["Hạng mục", "Tiêu chí đạt"], ["Môi trường", "01 server ZTAS + OPA + Caddy HTTPS; tối thiểu Windows, Ubuntu VM và macOS client."], ["Tài khoản", "Guest, Employee, Manager, Engineer, Admin; mỗi tài khoản có Account Key riêng."], ["Tài liệu", "5 vùng: Công khai, Nội bộ, Mật/Nhạy cảm, Bí mật, Hạn chế đặc biệt."], ["Bằng chứng", "Ảnh màn hình, audit log, kết quả API/HTTPS, thời gian phản hồi và bảng PASS/FAIL."]], [3*cm, 13.5*cm]),
          p("2. Chuẩn bị trước khi kiểm thử", "VNHeading"),
          p("1) Khởi động server bằng <b>mingw32-make deploy</b>. 2) Kiểm tra /health trả status UP. 3) Tạo tài khoản và Account Key. 4) Chuẩn bị mỗi loại tài liệu trong đúng phân vùng. 5) Chụp trạng thái Dashboard và xóa/đánh dấu log cũ trước khi chạy test.")]

scenarios = [
("TC-01", "HTTPS hợp lệ", "Client đã được cấp CA", "Mở https://ztas.ptit:8443/health", "Không cảnh báo chứng chỉ; status UP."),
("TC-02", "Thiết bị mới", "Tài khoản + Account Key hợp lệ", "Gửi yêu cầu tại connect-device", "PENDING; admin thấy yêu cầu và duyệt được."),
("TC-03", "Sai Account Key", "Thiết bị mới", "Nhập sai Key", "Từ chối; không tạo thiết bị được cấp quyền; có audit log."),
("TC-04", "Ràng buộc account-device", "Account A gán máy A", "Dùng Account A ở máy B", "Từ chối đọc tài liệu; không dùng fallback thiết bị khác."),
("TC-05", "Role cấp thấp", "Guest", "Mở Cấp 1 rồi Cấp 2", "Cấp 1 PERMIT; Cấp 2 DENY."),
("TC-06", "Kế thừa cấp quyền", "Manager", "Mở Cấp 1, 2, 3, 4", "PERMIT Cấp 1-3; DENY Cấp 4."),
("TC-07", "Admin", "Admin đã xác thực", "Mở mọi vùng", "Đọc Cấp 1-5 theo policy admin."),
("TC-08", "Step-up MFA", "Manager mở Cấp 3", "Yêu cầu và xác nhận MFA", "Chưa MFA: DENY/STEP-UP; hợp lệ: PERMIT."),
("TC-09", "Khóa MFA", "Thiết bị có MFA", "Nhập sai 3 lần", "Khóa ngay lần thứ 3; admin mới gỡ khóa được."),
("TC-10", "Thu hồi", "Thiết bị/MFA đã cấp", "Admin thu hồi rồi tải lại", "Các lần truy cập tiếp theo DENY; audit log đầy đủ."),
("TC-11", "Audit 5 ngày", "Có log cũ", "Chạy retention và lưu riêng log", "Log quá 5 ngày bị xóa; snapshot lưu riêng còn tồn tại."),
("TC-12", "Đổi mạng", "Server đổi IPv4 cùng LAN", "Khởi động lại deploy/Locator", "Hostname hoặc Locator đưa client đến server; HTTPS vẫn được kiểm tra."),
]
story += [PageBreak(), p("3. Kịch bản kiểm thử chức năng và an ninh", "VNHeading"), table([["ID", "Kịch bản", "Tiền điều kiện", "Thao tác", "Kết quả mong đợi"]] + scenarios, [1.2*cm, 3*cm, 3.1*cm, 5*cm, 5.2*cm])]
story += [PageBreak(), p("4. Kịch bản demo trình bày", "VNHeading"),
          p("Kịch bản 10 phút: (1) mở Dashboard và trạng thái OPA/HTTPS; (2) tạo/cấp Account Key; (3) Ubuntu VM gửi yêu cầu thiết bị; (4) admin duyệt và gán role Manager; (5) chứng minh Manager đọc Cấp 1-3 nhưng Cấp 4 bị chặn; (6) thực hiện MFA tại Cấp 3; (7) nhập sai MFA ba lần; (8) admin gỡ khóa hoặc thu hồi thiết bị; (9) mở Nhật ký để đối chiếu toàn bộ chuỗi sự kiện."),
          p("5. Mẫu ghi nhận kết quả", "VNHeading"),
          table([["ID", "Ngày/Người test", "Kết quả", "Bằng chứng", "Ghi chú"], ["TC-__", "____", "PASS / FAIL", "Ảnh, log ID, thời gian", "____"], ["TC-__", "____", "PASS / FAIL", "Ảnh, log ID, thời gian", "____"], ["TC-__", "____", "PASS / FAIL", "Ảnh, log ID, thời gian", "____"]], [2*cm, 3.5*cm, 2*cm, 6*cm, 4*cm]),
          p("Kết luận: chỉ công nhận PASS khi kết quả giao diện/API và audit log cùng chứng minh đúng quyết định policy.", "VNBody")]

def footer(canvas, doc):
    canvas.saveState(); canvas.setFont("Arial", 8); canvas.setFillColor(colors.HexColor("#60758C")); canvas.drawString(1.5*cm, 1.1*cm, "ZTAS PoC - Tài liệu kiểm thử"); canvas.drawRightString(A4[0]-1.5*cm, 1.1*cm, f"Trang {doc.page}"); canvas.restoreState()

SimpleDocTemplate(str(OUT), pagesize=A4, rightMargin=1.5*cm, leftMargin=1.5*cm, topMargin=1.5*cm, bottomMargin=1.8*cm).build(story, onFirstPage=footer, onLaterPages=footer)
print(OUT)
