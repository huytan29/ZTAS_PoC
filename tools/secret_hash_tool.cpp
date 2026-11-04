#include <openssl/evp.h>
#include <openssl/rand.h>

#include <iostream>
#include <string>

namespace {

std::string hex_encode(
    const unsigned char* input,
    std::size_t length
) {
    static constexpr char digits[] =
        "0123456789abcdef";

    std::string output;
    output.reserve(length * 2);

    for (std::size_t index = 0; index < length; ++index) {
        output.push_back(
            digits[(input[index] >> 4) & 0x0f]
        );

        output.push_back(
            digits[input[index] & 0x0f]
        );
    }

    return output;
}

} // namespace

int main() {
    constexpr int iterations = 310000;

    std::cout << "Nhap password: ";

    std::string secret;
    std::getline(std::cin, secret);

    if (secret.empty()) {
        std::cerr << "Secret khong duoc rong.\n";
        return 1;
    }

    unsigned char salt[16];

    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        std::cerr << "Khong tao duoc salt.\n";
        return 1;
    }

    unsigned char derived[32];

    if (PKCS5_PBKDF2_HMAC(
            secret.c_str(),
            static_cast<int>(secret.size()),
            salt,
            sizeof(salt),
            iterations,
            EVP_sha256(),
            sizeof(derived),
            derived
        ) != 1) {
        std::cerr << "Khong tao duoc PBKDF2 hash.\n";
        return 1;
    }

    std::cout
        << "pbkdf2_sha256$"
        << iterations
        << "$"
        << hex_encode(salt, sizeof(salt))
        << "$"
        << hex_encode(derived, sizeof(derived))
        << "\n";

    return 0;
}
