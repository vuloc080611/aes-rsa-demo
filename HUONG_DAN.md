# Web demo RSA và AES – Nhóm 01, DHHTTT20B_TCTA

Web tĩnh chạy hoàn toàn trên trình duyệt: không backend, không cần cài đặt, không cần mạng.
Lõi thuật toán tự viết bằng JavaScript; Web Crypto API (thư viện chuẩn của trình duyệt) chỉ dùng để đối chứng.

## 1. Cách mở

| Cách | Làm gì | Ghi chú |
|---|---|---|
| Nhanh nhất | Nhấp đúp `index.html` | Chạy được. Riêng sinh khóa RSA sẽ chạy trên luồng chính (trang có thể dừng khoảng 1 giây) vì trình duyệt chặn Web Worker khi mở bằng `file://` |
| Khuyên dùng khi demo | VS Code → cài extension **Live Server** → chuột phải `index.html` → *Open with Live Server* | Sinh khóa chạy trong Web Worker, giao diện không bị đứng |
| Có link gửi thầy | Đưa thư mục lên GitHub → *Settings → Pages* → chọn nhánh `main` | Được link dạng `https://<tên>.github.io/rsa-aes-demo/` |

Đã kiểm tra trên Chromium (Chrome, Edge) bằng cả hai cách mở `file://` và `http://localhost`.

## 2. Cấu trúc thư mục

```
rsa-aes-demo/
├── index.html                 Trang chính: header, thanh điều hướng bên trái, 6 trang, footer
├── css/style.css, fonts.css   Giao diện; font Be Vietnam Pro, JetBrains Mono lưu sẵn trong assets/fonts
├── js/
│   ├── core/                  ← TOÀN BỘ THUẬT TOÁN, TỰ CÀI ĐẶT
│   │   ├── utils.js           UTF-8, hex, Base64, BigInt ↔ byte, số ngẫu nhiên
│   │   ├── sha256.js          SHA-256 (FIPS 180-4)
│   │   ├── kdf.js             HMAC-SHA256 (RFC 2104), PBKDF2 (RFC 8018)
│   │   ├── aes.js             GF(2⁸), S-box tự tính, 4 phép biến đổi, mở rộng khóa 128/192/256
│   │   ├── modes.js           PKCS#7, ECB, CBC, CTR (+ bản xử lý file lớn có tiến độ)
│   │   ├── rsa.js             Euclid mở rộng, lũy thừa modulo, Miller–Rabin, sinh khóa, CRT
│   │   ├── oaep.js            RSAES-OAEP (RFC 8017)
│   │   ├── hybrid.js          Mã hóa lai văn bản
│   │   └── filecrypt.js       ỨNG DỤNG: file .enc, mật khẩu, khóa công khai, lưu/nạp khóa
│   ├── lib/webcrypto.js       Chỉ để ĐỐI CHIẾU kết quả ở tab Kiểm thử
│   ├── worker/rsa-keygen.worker.js
│   ├── app.js, ui-*.js        Giao diện (không chứa thuật toán)
├── tests/                     QUnit: 29 nhóm, 187 phép kiểm tra
└── vendor/                    Bootstrap, jQuery, QUnit (chỉ giao diện và kiểm thử)
```

## 3. Thang điểm của thầy và cách trình bày

Thang chấm cho mỗi thuật toán: dùng AI 1/5, dùng framework 2/5, code tay nhưng ứng dụng chưa cao 3/5,
code tay và ứng dụng cao 4/5, thêm thuyết trình tốt 5/5. Khi trình bày:

- **Code tay**: mọi thuật toán nằm trong `js/core/`, không gọi thư viện mật mã nào. Ứng dụng mã hóa file
  không dùng Web Crypto ở bất kỳ bước nào; SHA-256, HMAC, PBKDF2 cũng tự viết.
- **Bootstrap, jQuery, QUnit** không cài thuật toán: chỉ dựng giao diện và chạy kiểm thử.
- **Web Crypto** chỉ dùng để so kết quả (tab Kiểm thử, khung đối chiếu ở tab AES, RSA).
- **Tính ứng dụng**: mã hóa file bất kỳ bằng mật khẩu, gửi file cho người khác bằng khóa công khai,
  lưu/nạp khóa RSA, phát hiện sai mật khẩu và file bị sửa.
- Phần thuật toán do AI hỗ trợ viết; nhóm cần đọc hiểu từng hàm và trả lời trung thực nếu được hỏi.

## 4. Kịch bản demo (khoảng 7 phút)

1. **Trang Mã hóa file → Mã hóa file bằng mật khẩu**: chọn file báo cáo, nhập mật khẩu, *Mã hóa và tải file .enc*.
   Chọn file .enc vừa tải, nhập sai mật khẩu → báo "Thẻ HMAC không khớp". Nhập đúng → tải lại đúng file gốc.
   Chỉ vào sơ đồ "Bên trong file .enc": salt, số vòng PBKDF2, IV, bản mã, thẻ HMAC.
2. **Trang Mã hóa file → Gửi file bằng khóa công khai**: *Sinh cặp khóa 2048 bit*, *Tải khóa công khai*. Mã hóa một file
   cho người nhận. Nạp file khóa riêng rồi giải mã. Nói: chỉ khóa công khai thì mã hóa được, không giải mã được.
3. **RSA từng bước**: ví dụ 61, 53, 17 → 2790, bảng Euclid, bình phương–nhân, CRT.
4. **AES từng bước**: *Nạp ví dụ FIPS 197*, bấm *Chạy* để xem State qua từng bước.
5. **Kiểm thử**: 29/29 nhóm đạt; *Đo tốc độ* để so code tay với Web Crypto.

Định dạng file .enc: `N01ENC | phiên bản | loại | chế độ | độ dài khóa | (số vòng PBKDF2 + salt) hoặc
(khóa phiên bọc RSA-OAEP) | IV | bản mã | HMAC-SHA256`. Tên file được mã hóa cùng nội dung.

## 5. Kiểm thử

Mở `tests/test.html` (hoặc tab *Kiểm thử*): 29 nhóm, 187 phép kiểm tra. Dữ liệu chuẩn được dùng:
- **NIST FIPS 197-upd1**:
  - Phụ lục A.1: mở rộng khóa.
  - Phụ lục B: bản mã và 5 trạng thái trung gian.
  - Phụ lục C.1–C.3: AES-128, AES-192, AES-256.
- **NIST SP 800-38A Phụ lục F**: ECB, CBC, CTR × khóa 128/192/256 × 4 khối = 36 vector, kiểm tra cả mã hóa lẫn giải mã.
- **RSA**:
  - Ví dụ số 61/53/17.
  - Toàn bộ 3233 thông điệp của khóa mẫu (kể cả m không nguyên tố cùng nhau với n).
  - Miller–Rabin với số Carmichael (561, 41041, 825265).
  - Sinh khóa 512 bit.
- **OAEP**: khứ hồi, phát hiện bản mã bị sửa, giải mã chéo hai chiều với Web Crypto.
- **Web Crypto**: AES-CBC và AES-CTR trùng từng byte.
- **SHA-256** (FIPS 180-4: "abc", chuỗi rỗng, 448 bit, một triệu chữ a), **HMAC** (RFC 4231), **PBKDF2** (vector chuẩn).
- **File .enc**: khứ hồi CBC/CTR, sai mật khẩu và sửa 1 bit đều bị HMAC phát hiện, khóa riêng khác không mở được.

Lưu ý: Web Crypto trên Chrome/Edge không hỗ trợ AES-192, nên AES-192 được đối chiếu bằng dữ liệu NIST thay vì Web Crypto.

## 6. Giới hạn cần nói rõ khi bảo vệ

- Đây là bản học tập. Code tay ưu tiên dễ đọc, chưa chống tấn công kênh phụ: thời gian chạy phụ thuộc dữ liệu, có thể bị tấn công thời gian (timing attack).
- Tab AES từng bước dùng CBC/CTR thuần (chưa xác thực) để minh họa; ứng dụng mã hóa file thì đã thêm HMAC.
- RSA thuần (tab số nhỏ) chỉ để minh họa. Văn bản thật luôn mã hóa bằng OAEP.

## 7. Nguồn tham chiếu

NIST FIPS 197-upd1 (2023), NIST SP 800-38A (2001), RFC 8017 PKCS #1 v2.2 (2016), RFC 5652 §6.3 (PKCS#7 padding), FIPS 186-5 (2023), W3C Web Cryptography API.
