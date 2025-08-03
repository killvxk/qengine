/*
    This header provides a unified interface for encryption, decryption, and hashing in qengine.
    It supports both hardware-accelerated (AES-NI, CRC32C) and software-based (polyc128, QHASH) algorithms,
    with automatic feature detection and secure key/IV management.
*/

#pragma region Header Guard

#ifndef QCIPHER_PROVIDER_HXX
#define QCIPHER_PROVIDER_HXX

#pragma endregion

#pragma region Imports

#include "../qhash/qhash.hpp"

#pragma endregion

/*
    Configuration Macros:
    - QDEFAULT_INTRINSIC_AES: If defined, use AES-128 CTR when available (faster, but less secure than polyc128).
    - QFALLBACK_SOFTWARE_CRC32C: If defined, use software CRC32C if hardware is unavailable (faster than QHASH).
    - QDEFAULT_INTRINSIC_CRC32C: If defined, always use hardware CRC32C for hash digests.
*/

namespace qengine{

    namespace qcipher_provider {

#pragma region Available Ciphers

        /*
            Digest and cipher type enums for selecting algorithms at runtime.
            CRC32C is preferred for performance; QHASH is legacy.
        */
        typedef enum qdigest_type : std::uint8_t {
            hw_CRC32C   = 0, // Hardware-accelerated CRC32C
            sw_CRC32C   = 1, // Software CRC32C (SSE-optimized)
            QHASH32     = 2  // Legacy QHASH32
        };

        typedef enum qcipher_type : std::uint8_t {
            aes128      = 0, // AES-128 CTR mode
            polyc128    = 1  // polyc128 stream cipher
        };

#pragma endregion

#pragma region Globals

        // AES-128 context and key/IV storage (used if AES is selected and available)
        inline                  aes128_ctr      aes;
        alignas(0x10) inline    std::uint32_t   _aes128_key[4];
        inline                  std::uint64_t   _aes128_iv  = 0xFFFFFFFFFFFFFFFFu;

        // Current cipher and digest mode (default: polyc128 and software CRC32C)
        inline                  qcipher_type     _cipher_provider_mode           = polyc128;
        inline                  qdigest_type     _digest_provider_mode           = sw_CRC32C;
        inline                  bool             _is_qcipher_provider_initiated  = false;

        inline std::mutex qcipher_provider_mtx;

#pragma endregion

#pragma region Hardware Feature Auto-Detection

        // Detects CPU features and initializes cipher/digest modes and keys accordingly.
        struct _auto_detect_host_features {

            // Generates a secure random AES-128 key and IV using polyc128's random generator.
            static __compelled_inline void __stackcall generate_secure_aes128_key() nex {

                std::random_device r;

                imut __m128i r128_key = polyc128::_auto_init_polyc128::generate_secure_rand128(r() * INT16_MAX);

                imut __m128i r128_iv = polyc128::_auto_init_polyc128::generate_secure_rand128(r() * UINT16_MAX);

                reinterpret_cast<std::uint32_t*>(&_aes128_iv)[0] = _mm_extract_epi32(r128_iv, 2);

                reinterpret_cast<std::uint32_t*>(&_aes128_iv)[1] = _mm_extract_epi32(r128_iv, 3);

                _mm_store_si128(reinterpret_cast<__m128i*>(_aes128_key), r128_key);
                // Obfuscate key/IV in memory for additional security
                polycXOR::polycXOR_algo(_aes128_key, sizeof(_aes128_key));

                polycXOR::polycXOR_algo(&_aes128_iv, sizeof(std::uint64_t));
            }

            // Constructor: Detects hardware features and sets up cipher/digest modes and keys.
            __compelled_inline __stackcall _auto_detect_host_features() nex {

                static std::once_flag flag;

                std::call_once(

                    flag,

                    []() -> void {
                        
                        std::lock_guard<std::mutex> lock(qcipher_provider_mtx);

                        /*
                            Key generation for polyc128 occurs automatically. This block is for AES/CRC preference when available.
                        */
                        accelmem::cpu_check_simd(); // Detect SIMD and crypto features
#ifdef QDEFAULT_INTRINSIC_AES
                        if (accelmem::g_is_aes_ni) {

                            _cipher_provider_mode = aes128;

                            if (_cipher_provider_mode == aes128)
                                generate_secure_aes128_key();

                            aes = aes128_ctr(_aes128_key);

                            SECURE_ZERO_MEMORY(_aes128_key, sizeof(_aes128_key));

                            polycXOR::unregister_polyc_pointer(&_aes128_key);
                        }
#endif
#ifdef QDEFAULT_INTRINSIC_CRC32C
#ifdef QFALLBACK_SOFTWARE_CRC32C
                        if (accelmem::g_is_sse4_2)
                            _digest_provider_mode = hw_CRC32C;
                        else
                            _digest_provider_mode = sw_CRC32C;
#else
                        if (accelmem::g_is_sse4_2)
                            _digest_provider_mode = hw_CRC32C;
#endif
#endif
                        _is_qcipher_provider_initiated = true;
                    }
                );
            }
        };

#pragma endregion

        // Encrypts a range of bytes using the selected cipher and mode.
        static __compelled_inline imut bool __regcall cipher_encrypt_range(

            c_void              dst,

            imut c_void         src,

            imut std::uintptr_t offset,

            imut std::size_t    len
        ) nex {

            if (!dst || !src || !len)
                return false;

            std::lock_guard<std::mutex> lock(qcipher_provider_mtx);

            if(!_is_qcipher_provider_initiated)
                static _auto_detect_host_features _auto_init_cipher_interface;

            bool rcode = false;

            switch (_cipher_provider_mode) {

                case aes128: {
                    // De-obfuscate IV, encrypt, then re-obfuscate IV
                    polycXOR::polycXOR_algo(&_aes128_iv, sizeof(std::uint64_t));
                    rcode = aes.aes128_encrypt_range(reinterpret_cast<std::uint8_t*>(dst), reinterpret_cast<std::uint8_t*>(src), offset, len, _aes128_iv);
                    polycXOR::polycXOR_algo(&_aes128_iv, sizeof(std::uint64_t));
                    break;
                }
                case polyc128: {
                    rcode = polyc128::polyc128_encrypt_range(dst, src, offset, len);
                    break;
                }
                default: {
                    break;
                }
            }
            return rcode;
        }

        // Decrypts a range of bytes using the selected cipher and mode.
        static __compelled_inline imut bool __regcall cipher_decrypt_range(

            c_void dst,

            imut c_void src,

            imut std::uintptr_t offset,

            imut std::size_t len

        ) nex {
            if (!dst || !src || !len)
                return false;

            std::lock_guard<std::mutex> lock(qcipher_provider_mtx);

            if (!_is_qcipher_provider_initiated)
                static qcipher_provider::_auto_detect_host_features _auto_init_cipher_interface;

            bool rcode = false;
            switch (_cipher_provider_mode) {
                case aes128: {
                    // De-obfuscate IV, decrypt, then re-obfuscate IV
                    polycXOR::polycXOR_algo(&_aes128_iv, sizeof(std::uint64_t));
                    rcode = aes.aes128_decrypt_range(reinterpret_cast<std::uint8_t*>(dst), reinterpret_cast<std::uint8_t*>(src), offset, len, _aes128_iv);
                    polycXOR::polycXOR_algo(&_aes128_iv, sizeof(std::uint64_t));
                    break;
                }
                case polyc128: {
                    rcode = polyc128::polyc128_decrypt_range(dst, src, offset, len);
                    break;
                }
                default: {
                    break;
                }
            }
            return rcode;
        }

        // Encrypts a buffer (entire length) using the selected cipher.
        static __compelled_inline imut bool cipher_encrypt(
            c_void dst,
            imut c_void src,
            imut std::size_t len
        ) nex {
            return cipher_encrypt_range(dst, src, 0, len);
        }

        // Decrypts a buffer (entire length) using the selected cipher.
        static __compelled_inline imut bool cipher_decrypt(
            c_void dst,
            imut c_void src,
            imut std::size_t len
        ) nex {
            return cipher_decrypt_range(dst, src, 0, len);
        }

        // Computes a hash digest of the input using the selected digest mode.
        static __compelled_inline imut std::uint32_t __regcall hash_digest(
            imut c_void         src,
            imut std::size_t    len
        ) nex {

            if (!src || !len)
                return 0x0u;

            std::lock_guard<std::mutex> lock(qcipher_provider_mtx);

            if (!_is_qcipher_provider_initiated)
                static qcipher_provider::_auto_detect_host_features _auto_init_cipher_interface;

            volatile std::uint32_t digest = 0x0u;

            crc32 crc;
            // Lambda for quick CRC32C calculation
            auto quickcrc = [&crc, &src, &len]() -> volatile std::uint32_t {
                imut volatile std::uint32_t hash = crc.update_crc(reinterpret_cast<std::uint8_t*>(src), len);
                crc.reset_crc();
                return hash;
            };
            switch (_digest_provider_mode) {
                case hw_CRC32C:
                case sw_CRC32C: {
                    digest = quickcrc();
                    break;
                }
                case QHASH32: {
                    digest = qhash::qhash32(src, len);
                    break;
                }
                default: {
                    break;
                }
            }
            // For 32-bit digests, only the low bits are used (masking is visually explicit)
            return digest;
        }

        // Ensures hardware feature detection runs at startup
        inline qcipher_provider::_auto_detect_host_features _auto_init_cipher_interface;
    }
}

#pragma region Header Guard

#endif

#pragma endregion