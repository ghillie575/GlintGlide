#include <encoder.h>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <vector>
#include <string>
namespace ghillie575
{
    namespace glintglide
    {
        std::vector<unsigned char> hexToBytes(const std::string &hex)
        {
            std::vector<unsigned char> bytes;
            for (size_t i = 0; i < hex.length(); i += 2)
            {
                std::string byteStr = hex.substr(i, 2);
                bytes.push_back(std::stoi(byteStr, nullptr, 16));
            }
            return bytes;
        }
        std::string encryptAES(const std::string &plaintext, const std::string &key, const std::vector<unsigned char> &iv)
        {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
                return "";

            std::vector<unsigned char> keyBytes(32, 0);
            std::copy(key.begin(), key.end(), keyBytes.begin());

            EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, keyBytes.data(), iv.data());

            std::vector<unsigned char> encrypted(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
            int outLen1 = 0;
            EVP_EncryptUpdate(ctx, encrypted.data(), &outLen1, (unsigned char *)plaintext.data(), plaintext.size());

            int outLen2 = 0;
            EVP_EncryptFinal_ex(ctx, encrypted.data() + outLen1, &outLen2);

            EVP_CIPHER_CTX_free(ctx);

            encrypted.resize(outLen1 + outLen2);

            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (auto c : encrypted)
                ss << std::setw(2) << (int)c;

            return ss.str();
        }
        std::string decryptAES(const std::string &encryptedHex, const std::string &key, const std::vector<unsigned char> &iv)
        {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
                return "";

            std::vector<unsigned char> keyBytes(32, 0);
            std::copy(key.begin(), key.end(), keyBytes.begin());

            std::vector<unsigned char> encryptedBytes;
            for (size_t i = 0; i < encryptedHex.length(); i += 2)
            {
                std::string byteStr = encryptedHex.substr(i, 2);
                encryptedBytes.push_back(std::stoi(byteStr, nullptr, 16));
            }

            EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, keyBytes.data(), iv.data());

            std::vector<unsigned char> decrypted(encryptedBytes.size());
            int outLen1 = 0;
            EVP_DecryptUpdate(ctx, decrypted.data(), &outLen1, encryptedBytes.data(), encryptedBytes.size());

            int outLen2 = 0;
            EVP_DecryptFinal_ex(ctx, decrypted.data() + outLen1, &outLen2);

            EVP_CIPHER_CTX_free(ctx);

            decrypted.resize(outLen1 + outLen2);
            return std::string(decrypted.begin(), decrypted.end());
        }
        std::string encode(const std::string &input, const std::string &key)
        {
            std::vector<unsigned char> iv = hexToBytes(ENCODER_IV);
            std::string result = encryptAES(input, key, iv);
            return encryptAES(result, ENCODER_KEY, iv);
        }
        std::string decode(const std::string &input, const std::string &key)
        {
            std::vector<unsigned char> iv = hexToBytes(ENCODER_IV);
            std::string result = decryptAES(input, ENCODER_KEY, iv);
            std::string decoded = decryptAES(result, key, iv);
            return decoded;
        }
    }
}