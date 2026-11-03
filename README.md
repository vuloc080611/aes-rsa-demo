# RSA & AES Crypto Lab

Ứng dụng web tương tác dùng để minh họa, kiểm thử và trực quan hóa các thuật toán mật mã RSA và AES.

Đây là bài tập lớn môn **Nhập môn An toàn thông tin** của **Nhóm 01 – DHHTTT20B_TCTA**, Trường Đại học Công nghiệp TP. Hồ Chí Minh.

> Toàn bộ quá trình mã hóa, giải mã và sinh khóa được thực hiện trực tiếp trên trình duyệt. File, mật khẩu và khóa riêng không được gửi đến máy chủ.

---

## Tính năng chính

### Mã hóa file bằng mật khẩu

- Hỗ trợ AES-128, AES-192 và AES-256.
- Chế độ AES-CBC và AES-CTR.
- Dẫn xuất khóa từ mật khẩu bằng PBKDF2.
- Kiểm tra tính toàn vẹn bằng HMAC-SHA256.
- Tên file và nội dung đều được đặt bên trong file `.enc`.
- Phát hiện mật khẩu sai hoặc file đã bị chỉnh sửa.

### Gửi file bằng khóa công khai

Ứng dụng sử dụng mô hình mã hóa lai:

1. Sinh khóa phiên AES ngẫu nhiên.
2. Mã hóa nội dung file bằng AES.
3. Mã hóa khóa phiên bằng RSA-OAEP.
4. Đóng gói dữ liệu thành file `.enc`.
5. Chỉ người giữ khóa riêng RSA mới có thể giải mã.

### RSA từng bước

- Tạo khóa từ các giá trị `p`, `q` và `e`.
- Tính:

  - `n = p × q`
  - `φ(n)`
  - Khóa riêng `d`
  - Mã hóa `c = mᵉ mod n`
  - Giải mã `m = cᵈ mod n`

- Thuật toán Euclid mở rộng.
- Lũy thừa modular bình phương–nhân.
- Kiểm tra số nguyên tố Miller–Rabin.
- Tối ưu giải mã bằng định lý số dư Trung Hoa – CRT.
- Sinh khóa RSA 512, 1024 hoặc 2048 bit.
- Mã hóa văn bản bằng RSA-OAEP với SHA-256.

> Khóa 512 và 1024 bit chỉ được cung cấp để quan sát và so sánh tốc độ. Khi demo mã hóa thực tế nên sử dụng RSA 2048 bit.

### AES từng bước

- AES-128, AES-192 và AES-256.
- Hiển thị quá trình mở rộng khóa.
- Trực quan hóa ma trận State 4×4.
- Theo dõi từng phép biến đổi:

  - AddRoundKey
  - SubBytes
  - ShiftRows
  - MixColumns

- Hỗ trợ:

  - ECB
  - CBC
  - CTR
  - Mã hóa một block 16 byte

### Trực quan hóa

- Thí nghiệm hiệu ứng Avalanche.
- Thay đổi một bit của bản rõ hoặc khóa.
- Theo dõi số bit thay đổi sau từng vòng AES.
- Minh họa sự khác biệt giữa ECB và CBC bằng hình ảnh.
- Biểu đồ kết quả được tạo trực tiếp bằng SVG.

### Mã hóa lai văn bản

- Sinh khóa AES ngẫu nhiên.
- Mã hóa văn bản bằng AES.
- Bọc khóa phiên bằng RSA-OAEP.
- Hiển thị từng thành phần của gói dữ liệu mã hóa.
- Giải mã và kiểm tra lại nội dung ban đầu.

### Kiểm thử và hiệu năng

- So sánh tốc độ code tự cài đặt với Web Crypto API.
- Kiểm thử bằng QUnit.
- Hiện có:

  - 29 test case
  - 187 assertion
  - Các vector chuẩn NIST và RFC

- Dashboard kiểm thử hiển thị:

  - Tổng số test
  - Tổng assertion
  - Số lỗi
  - Thời gian chạy
  - Chi tiết từng test

---

## Giao diện

Project sử dụng giao diện theo phong cách **Cybersecurity Command Center**:

- Dark cyber-lab theme.
- Màu riêng cho AES, RSA và Hybrid.
- Animated cryptographic network.
- HUD, telemetry và scanline effects.
- Chuyển cảnh giữa các module.
- Responsive cho desktop, tablet và mobile.
- Hỗ trợ `prefers-reduced-motion`.
- Màu chữ được tối ưu độ tương phản để trình chiếu.

---

## Công nghệ sử dụng

| Công nghệ | Mục đích |
|---|---|
| HTML5 | Cấu trúc giao diện |
| CSS3 | Theme, responsive và animation |
| JavaScript | Thuật toán và tương tác |
| Bootstrap 5 | Layout và component giao diện |
| jQuery | Xử lý sự kiện UI |
| QUnit | Kiểm thử thuật toán |
| Web Crypto API | Đối chiếu và đo hiệu năng |

Bootstrap và jQuery chỉ được dùng cho giao diện. Các thuật toán mật mã chính được tự cài đặt trong thư mục `js/core/`.

---

## Cấu trúc thư mục

```text
rsa-aes-demo/
├── assets/
│   ├── fonts/
│   ├── favicon.svg
│   └── logo_iuh.png
│
├── css/
│   ├── fonts.css
│   ├── style.css
│   └── redesign.css
│
├── js/
│   ├── core/
│   │   ├── aes.js
│   │   ├── filecrypt.js
│   │   ├── hybrid.js
│   │   ├── kdf.js
│   │   ├── modes.js
│   │   ├── oaep.js
│   │   ├── rsa.js
│   │   ├── sha256.js
│   │   └── utils.js
│   │
│   ├── lib/
│   │   └── webcrypto.js
│   │
│   ├── app.js
│   ├── ui-aes.js
│   ├── ui-app.js
│   ├── ui-effects.js
│   ├── ui-more.js
│   ├── ui-shell.js
│   └── ui-visual.js
│
├── tests/
│   ├── test.html
│   ├── test-theme.css
│   ├── test-ui.js
│   └── tests.js
│
├── vendor/
│   ├── bootstrap.bundle.min.js
│   ├── bootstrap.min.css
│   ├── jquery-3.7.1.min.js
│   ├── qunit-2.21.0.css
│   └── qunit-2.21.0.js
│
├── HUONG_DAN.md
└── index.html
```

---

## Cách chạy project

Project không yêu cầu cài package hoặc build source code.

### Cách 1: Mở trực tiếp

Clone repository:

```bash
git clone <URL_REPOSITORY_CUA_BAN>
cd rsa-aes-demo
```

Sau đó mở file:

```text
index.html
```

bằng Chrome, Edge hoặc Firefox.

### Cách 2: Chạy bằng local server

Khuyến nghị sử dụng local server để tránh một số giới hạn của trình duyệt đối với `file://`.

Nếu đã cài Python:

```bash
python -m http.server 8080
```

Trên Windows cũng có thể dùng:

```powershell
py -m http.server 8080
```

Sau đó truy cập:

```text
http://localhost:8080
```

---

## Cách sử dụng

### Mã hóa file bằng mật khẩu

1. Mở trang **Mã hóa file**.
2. Chọn file cần mã hóa.
3. Nhập mật khẩu có ít nhất 8 ký tự.
4. Chọn độ dài khóa AES.
5. Chọn chế độ CBC hoặc CTR.
6. Nhấn **Mã hóa và tải file `.enc`**.

Để giải mã:

1. Chọn file `.enc`.
2. Nhập đúng mật khẩu.
3. Nhấn **Giải mã file `.enc`**.

### Gửi file bằng RSA

Người nhận:

1. Sinh cặp khóa RSA 2048 bit.
2. Tải khóa công khai và khóa riêng.
3. Gửi khóa công khai cho người gửi.
4. Giữ bí mật khóa riêng.

Người gửi:

1. Nạp khóa công khai của người nhận.
2. Chọn file cần gửi.
3. Nhấn **Mã hóa cho người nhận**.
4. Gửi file `.enc` cho người nhận.

Người nhận dùng khóa riêng để giải mã file.

### Xem thuật toán

Sử dụng các trang:

- **RSA từng bước**
- **AES từng bước**
- **Trực quan**
- **Mã hóa lai văn bản**

để quan sát dữ liệu trung gian và từng phép biến đổi của thuật toán.

---

## Chạy kiểm thử

Mở trực tiếp:

```text
tests/test.html
```

Hoặc khi đang chạy local server:

```text
http://localhost:8080/tests/test.html
```

Bạn cũng có thể mở trang **Kiểm thử và hiệu năng** trong ứng dụng rồi nhấn **Chạy kiểm thử**.

Bộ kiểm thử bao gồm:

- AES GF(2⁸) và S-box.
- AES key expansion.
- AES-128, AES-192 và AES-256.
- ECB, CBC và CTR.
- Padding PKCS#7.
- RSA modular arithmetic.
- Euclid mở rộng.
- Miller–Rabin.
- CRT.
- RSA-OAEP.
- SHA-256.
- HMAC-SHA256.
- PBKDF2.
- Mã hóa lai.
- Định dạng file `.enc`.
- Giải mã chéo với Web Crypto API.

---

## Tiêu chuẩn tham khảo

- [NIST FIPS 197 – Advanced Encryption Standard](https://doi.org/10.6028/NIST.FIPS.197-upd1)
- [NIST SP 800-38A – Block Cipher Modes](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [NIST FIPS 180-4 – Secure Hash Standard](https://doi.org/10.6028/NIST.FIPS.180-4)
- [RFC 8017 – RSA Cryptography Specifications](https://www.rfc-editor.org/rfc/rfc8017)
- [RFC 8018 – Password-Based Cryptography](https://www.rfc-editor.org/rfc/rfc8018)
- [RFC 4231 – HMAC-SHA Test Cases](https://www.rfc-editor.org/rfc/rfc4231)

---

## Lưu ý bảo mật

Project được xây dựng nhằm mục đích học tập, minh họa và kiểm chứng thuật toán.

Không nên sử dụng code mật mã tự cài đặt của project trong hệ thống production hoặc để bảo vệ dữ liệu thực sự quan trọng.

Một số lưu ý:

- Mật khẩu và khóa riêng chỉ được giữ trong bộ nhớ của trang.
- Tải lại trang sẽ xóa trạng thái hiện tại.
- Không chia sẻ file khóa riêng.
- Không commit khóa riêng hoặc dữ liệu nhạy cảm lên GitHub.
- RSA 512 và 1024 bit không an toàn cho sử dụng thực tế.
- Mật khẩu 8 ký tự chỉ là giới hạn tối thiểu của giao diện; nên sử dụng mật khẩu dài và khó đoán.
- Trong ứng dụng production nên sử dụng thư viện mật mã đã được kiểm toán.

---

## Thành viên thực hiện

| Thành viên |
|---|
| Vũ Lộc |
| Trần Bùi Đức Minh |
| Nguyễn Thanh Huy |
| Nguyễn Đức Mạnh |

**Lớp:** DHHTTT20B_TCTA  
**Nhóm:** 01  
**Môn học:** Nhập môn An toàn thông tin  
**Trường:** Đại học Công nghiệp TP. Hồ Chí Minh

---

## Mục đích học tập

Project giúp người học:

- Hiểu sự khác nhau giữa mật mã đối xứng và bất đối xứng.
- Quan sát cách AES biến đổi dữ liệu qua từng vòng.
- Hiểu quá trình tạo khóa và mã hóa của RSA.
- Hiểu lý do hệ thống thực tế kết hợp RSA và AES.
- Kiểm chứng thuật toán bằng dữ liệu chuẩn.
- Nhận biết hạn chế của ECB.
- So sánh code JavaScript tự cài đặt với Web Crypto API.

---

## Tuyên bố

Project được phát triển phục vụ mục đích học tập và trình diễn trong môn **Nhập môn An toàn thông tin**.

Không có dữ liệu nào được gửi đến máy chủ trong quá trình sử dụng ứng dụng.
