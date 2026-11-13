# Kết nối thiết bị bằng Account Key

Luồng này thay thế việc người dùng phải chạy `curl` với Enrollment Code. Thiết
bị mới chỉ cần trình duyệt và ba thông tin do quản trị viên cấp: tên đăng nhập,
mật khẩu và Account Key.

## Phía Admin

1. Đăng nhập Dashboard, vào **Tài khoản** và tạo user với role phù hợp.
2. Sau khi tạo, hộp thoại hiện **Account Key** đúng một lần. Lưu key và gửi
   cho đúng người dùng qua kênh an toàn.
3. Với user cũ hoặc khi key bị lộ, chọn **Cấp lại key**. Key cũ bị vô hiệu hóa
   ngay lập tức.

Mật khẩu khởi tạo của PoC vẫn là `ptit@123`; cần đổi trước khi dùng ngoài lab.
Account Key không phải Device Key và không được lưu trong Git, log hay ảnh chụp
màn hình.

## Phía máy mới

1. Mở `http://<IP-may-chu-ZTAS>:8020/connect-device`.
2. Nhập **tên đăng nhập**, **mật khẩu** và **Account Key**.
3. Bấm **Gửi yêu cầu kết nối**. Trang giữ một phiên chờ ngắn hạn nhưng chưa
   thể đọc dữ liệu khi Admin chưa duyệt.

Trang tự tạo một ID cục bộ cho trình duyệt và gửi tên nền tảng, loại hệ điều
hành suy ra từ trình duyệt, User-Agent và IP TCP tới Server. Trình duyệt web
không được phép đọc hostname, serial, MAC hoặc phần cứng chi tiết của máy;
những thông tin đó cần một ZTAS Agent cài trên máy nếu muốn thu thập thật.

## Phê duyệt và đọc tài liệu

1. Admin vào **Thiết bị** → **Yêu cầu kết nối chờ phê duyệt**.
2. Kiểm tra tài khoản, IP nguồn, nền tảng và thông tin máy khách.
3. Chọn **Phân loại & cấp quyền**, đặt trust/location và phê duyệt.
4. Ngay khi cấp phát thành công, trang máy mới tự nhận trạng thái phê duyệt,
   tự tạo ngữ cảnh đọc và chuyển thẳng tới **Tài liệu**. User không cần tải lại
   Dashboard hoặc nhập lại thông tin. Phiên chờ có hiệu lực 15 phút; hết thời
   gian này thì gửi lại yêu cầu với ba thông tin ban đầu.
5. Quyền đọc vẫn theo role: guest 1; employee 1–2; manager 1–3; engineer 1–4;
   admin 1–5.

Server yêu cầu đồng thời đúng username, password và Account Key trước khi tạo
yêu cầu chờ duyệt. Key được tạo ngẫu nhiên, chỉ hiển thị một lần và Server chỉ
lưu PBKDF2 hash của key.

> Với triển khai thật, phải đặt ZTAS sau HTTPS. HTTP chỉ phù hợp mạng lab; nếu
> không, password và Account Key có thể bị nghe lén trên đường truyền.
