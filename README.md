# Misasef23-eng

Một ứng dụng đơn giản viết bằng **C++** hỗ trợ **dịch thuật** và **mã hóa / giải mã văn bản** theo chuẩn bảo mật **AES-256 GCM**. Đây là dự án thực hành cá nhân nhằm tìm hiểu và áp dụng cơ chế mã hóa đối xứng trong C++.

---

## ✨ Tính năng chính

- **Dịch thuật văn bản**: Hỗ trợ chuyển đổi ngôn ngữ nhanh chóng và tiện lợi.
- **Mã hóa AES-256 GCM**: Bảo vệ nội dung văn bản bằng thuật toán mã hóa tiên tiến AES-256 ở chế độ GCM (Galois/Counter Mode).
- **Giải mã an toàn**: Xác thực tính toàn vẹn và giải mã nội dung chính xác với khóa an toàn.
- **Thao tác đơn giản**: Giao diện / Terminal trực quan, dễ sử dụng cho các tác vụ mã hóa và dịch thuật.

---

## 🛠 Công nghệ sử dụng

- **Ngôn ngữ**: C++ (C++17 trở lên)
- **Thư viện mã hóa**: OpenSSL / Crypto++ (AES-256 GCM)
- **Quản lý dự án**: CMake

---

## 🚀 Hướng dẫn cài đặt & Chạy ứng dụng

### 1. Yêu cầu hệ thống
- Trình biên dịch C++ hỗ trợ C++17 trở lên (GCC, Clang, hoặc MSVC)
- CMake (phiên bản 3.15 trở lên)
- Thư viện OpenSSL hoặc Crypto++ đã cài đặt trên máy

### 2. Biên dịch dự án bằng CMake

```bash
# Clone repository về máy
git clone https://github.com/Misasef23-eng/mahoaAES256GCM.git
cd LexCrypt

# Tạo thư mục build và cấu hình CMake
mkdir build && cd build
cmake ..

# Biên dịch chương trình
cmake --build .
```

### 3. Chạy chương trình

```bash
# Trên Linux/macOS:
./LexCrypt

# Trên Windows (Command Prompt / PowerShell):
.\Debug\LexCrypt.exe
```

---

## 🔒 Cơ chế mã hóa AES-256 GCM

Dự án sử dụng **AES-256 GCM**, một chuẩn mã hóa đối xứng mạnh mẽ cung cấp cả **Tính bảo mật (Confidentiality)** và **Tính xác thực (Authenticity)**:
- **Key size**: 256-bit.
- **Nonce/IV**: 12 bytes ngẫu nhiên cho mỗi lần mã hóa.
- **Auth Tag**: 16 bytes đảm bảo dữ liệu không bị thay đổi hoặc can thiệp.

---

## 📜 Giấy phép (License)

Dự án này được phát hành dưới giấy phép [MIT License](LICENSE). Bạn có thể tự do sử dụng, chỉnh sửa và phát triển thêm cho mục đích học tập.