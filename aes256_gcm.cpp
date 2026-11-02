#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

constexpr int KEY_LEN = 32;    // 256 bits
constexpr int NONCE_LEN = 12;  // 96 bits: recommended for GCM
constexpr int TAG_LEN = 16;    // 128-bit authentication tag

using Bytes = std::vector<unsigned char>;
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

std::string toHex(const Bytes& data) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned char byte : data)
        out << std::setw(2) << static_cast<unsigned int>(byte);
    return out.str();
}

bool randomBytes(Bytes& output) {
    return RAND_bytes(output.data(), static_cast<int>(output.size())) == 1;
}

bool encryptGCM(const Bytes& plaintext, const Bytes& key,
                const Bytes& nonce, Bytes& ciphertext, Bytes& tag) {
    CipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return false;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1)
        return false;
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        return false;

    ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int written = 0;
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &written,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1)
        return false;

    int finalWritten = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + written, &finalWritten) != 1)
        return false;
    ciphertext.resize(static_cast<size_t>(written + finalWritten));

    tag.resize(TAG_LEN);
    return EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data()) == 1;
}

bool decryptGCM(const Bytes& ciphertext, const Bytes& key,
                const Bytes& nonce, const Bytes& tag, Bytes& plaintext) {
    CipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return false;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1)
        return false;
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        return false;

    plaintext.resize(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int written = 0;
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(ctx.get(), plaintext.data(), &written,
                          ciphertext.data(), static_cast<int>(ciphertext.size())) != 1)
        return false;

    // Set the expected tag before DecryptFinal_ex verifies authenticity.
    Bytes tagCopy = tag;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tagCopy.size()), tagCopy.data()) != 1)
        return false;

    int finalWritten = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + written, &finalWritten) != 1) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        plaintext.clear();
        return false; // Authentication failed: do not use the plaintext.
    }

    plaintext.resize(static_cast<size_t>(written + finalWritten));
    return true;
}

int main() {
    std::string input;
    std::cout << "Nhap plaintext: ";
    std::getline(std::cin, input);

    Bytes plaintext(input.begin(), input.end());
    Bytes key(KEY_LEN), nonce(NONCE_LEN), ciphertext, tag;

    if (!randomBytes(key) || !randomBytes(nonce)) {
        std::cerr << "Khong the tao key/nonce ngau nhien.\n";
        return 1;
    }

    if (!encryptGCM(plaintext, key, nonce, ciphertext, tag)) {
        std::cerr << "Ma hoa that bai.\n";
        return 1;
    }

    std::cout << "\n=== KET QUA MA HOA ===\n";
    std::cout << "Key (hex):        " << toHex(key) << '\n';
    std::cout << "Nonce (hex):      " << toHex(nonce) << '\n';
    std::cout << "Ciphertext (hex): " << toHex(ciphertext) << '\n';
    std::cout << "Auth Tag (hex):   " << toHex(tag) << '\n';

    Bytes recovered;
    std::cout << "\n=== GIAI MA ===\n";
    if (decryptGCM(ciphertext, key, nonce, tag, recovered))
        std::cout << "Plaintext:        " << std::string(recovered.begin(), recovered.end()) << '\n';
    else
        std::cout << "Giai ma/xac thuc that bai.\n";

    // Demonstrate GCM integrity: modify one ciphertext byte and verify rejection.
    Bytes tampered = ciphertext;
    Bytes tamperedTag = tag;
    if (!tampered.empty()) tampered[0] ^= 0x01;
    else tamperedTag[0] ^= 0x01;

    Bytes ignored;
    std::cout << "\n=== KIEM TRA DU LIEU BI SUA ===\n";
    if (decryptGCM(tampered, key, nonce, tamperedTag, ignored))
        std::cout << "Canh bao: du lieu da duoc chap nhan.\n";
    else
        std::cout << "Thanh cong: phat hien du lieu bi thay doi (Authentication failed).\n";

    OPENSSL_cleanse(key.data(), key.size());
    OPENSSL_cleanse(recovered.data(), recovered.size());
    return 0;
}
