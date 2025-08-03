/*
    This class is intended to allow for compiler-evaluated encryption of static/global integral constants so that these may not allow for signature-based detections on constant values.
*/
#pragma region Header Guard

#ifndef QPREPROCESS_H
#define QPREPROCESS_H

#pragma endregion

#pragma region Includes

#include "qstr.hpp" // Include string utilities for use in this header

#pragma endregion

#pragma region Algorithm Constants
// Define a platform-dependent constant for entropy injection into encryption key generation
#ifndef _WIN64
// 32-bit platform: Use a 32-bit entropy constant
inline const constexpr std::uint32_t UINTPTR_ENTROPIZE = 0xAAAAAAAAui32;
#else
// 64-bit platform: Use a 64-bit entropy constant
inline const constexpr std::uint64_t UINTPTR_ENTROPIZE = 0xAAAAAAAAAAAAAAAAui64;
#endif

#pragma endregion

#pragma region Key Construction
/*
    The encryption key is constructed to match the bit width of std::uintptr_t, which is the maximum primitive bit width for integral types on the platform.
    This key is generated at compile time using the __TIME__ macro and additional entropy, making it difficult to predict or signature-match.
*/
inline const constexpr std::uintptr_t _qpreprocess_key =
    __TIME__[7] +
    __TIME__[6] +
    __TIME__[5] +
    __TIME__[4] +
    __TIME__[3] +
    __TIME__[2] +
    __TIME__[1] +
    __TIME__[0] *
    ((4096 *                  // The math here is intended to create high entropy for use as a constexpr encryption key
    UINTPTR_ENTROPIZE) ^ UINTPTR_ENTROPIZE) /
    32;

#pragma endregion

#pragma region qconstexpr Macros
// Macro to XOR an immediate value with the compile-time generated key
#define QXOR(IMM) IMM ^ _qpreprocess_key

// Macro to declare a mutable (non-const) encrypted value, which can be modified after decryption
#define qmutexpr(TYPE, NAME, VALUE) inline TYPE NAME = static_cast<TYPE>(qengine::qtype_obj<TYPE>(QXOR(VALUE)))

// Macro to declare an immutable (const) encrypted value, which cannot be modified after decryption
#define qimutexpr(TYPE, NAME, VALUE) inline const TYPE NAME = static_cast<TYPE>(qengine::qtype_obj<TYPE>(static_cast<TYPE>(QXOR(VALUE))))

// Macro to declare a stack-allocated encrypted value using qtype_obj
#define qimutexpr_stack(TYPE, NAME, VALUE) inline qengine::qtype_obj<TYPE> NAME(QXOR(VALUE))

#pragma endregion

#pragma region Namespace qengine

namespace qengine {

#pragma endregion

#pragma region qtype_obj Class (Encrypted Constant Wrapper)
    // qtype_obj<T> is a template class that stores an encrypted value of type T.
    // The value is encrypted at compile time and decrypted at runtime when accessed.
    // This prevents static analysis from easily detecting constant values in binaries.
    template<typename T>
    class qtype_obj {

    private:

#pragma region Encrypted Data Storage
        // Stores the encrypted bytes of the value
        volatile std::uint8_t _data[sizeof(T)];
#pragma endregion

#pragma region Decryption Routine
        // Decrypts the stored value using the compile-time key
        inline T qcrypt_out() volatile noexcept {
            T data_inst = static_cast<T>(NULL);
            std::uint8_t* data_ui8_ptr = (std::uint8_t*)&data_inst;
            // Copy encrypted bytes into a local variable
            // Assumes little-endian layout for Windows platforms
            for (std::size_t i = 0; i < sizeof(T); ++i)
                data_ui8_ptr[i] = _data[i];
            // Decrypt by XORing with the key
            return std::move(data_inst) ^ _qpreprocess_key;
        }
#pragma endregion

#pragma region Encryption Routine (constexpr)
        // Encrypts the value at compile time and stores the bytes in _data
        constexpr inline void qcrypt_in(const T data) noexcept {
            /*
                Degrade the data to its lowest/base type during constexpr evaluation to prevent the compiler from predicting the value.
                Store bits from low to high order, and reconstruct the type before decryption.
            */
            for (std::size_t i = 0; i < sizeof(T); ++i)
                _data[i] = (data >> (i * 8)) & 0xFF;
        }
#pragma endregion

    public:

#pragma region Manual Destructor
        // Securely wipes the stored data from memory
        inline void wipe() noexcept {
            std::memset(const_cast<std::uint8_t*>((std::uint8_t*)&_data), 0x0u, sizeof(T));
        }
#pragma endregion

#pragma region Accessor
        // Returns the decrypted value
        inline const T get() volatile noexcept {
            return qcrypt_out();
        }
#pragma endregion

#pragma region Operator<T> Definition
        // Allows implicit conversion to T by returning the decrypted value
        inline operator T() volatile noexcept {
            return get();
        }
#pragma endregion

#pragma region Constructor / Destructor
        // Constructor: Encrypts the value at compile time
        constexpr inline qtype_obj(const T value, const bool is_instanced_decryption = true) noexcept {
            qcrypt_in(value);
        }
        // Destructor: Wipes the stored data
        inline ~qtype_obj() noexcept {
            wipe();
        }
#pragma endregion
    };
#pragma endregion

#pragma region Namespace End
}
#pragma endregion

#pragma region Header Guard
#endif
#pragma endregion