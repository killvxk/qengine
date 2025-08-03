#pragma once
#ifndef GMUTVEH_HXX
#define GMUTVEH_HXX

#include "gmutstruct.hxx"

#pragma intrinsic(memcpy, memmove, memset, memcmp)

namespace ghostmut {

	namespace gveh {

#pragma region Type Differentiation + Mutation Macros

#define GHOSTMUT_OP_SW_ALL(OPERATION, ARG1, ARG2, RESULT)                                       \
    switch ((ARG1).at) {                                                                       \
        case ghostmut::gstruct::i8:                                                            \
            (RESULT).rt = ghostmut::gstruct::i8;                                               \
            (RESULT).s0 = (ARG1).a0 OPERATION (ARG2).a0;                                       \
            break;                                                                             \
        case ghostmut::gstruct::u8:                                                            \
            (RESULT).rt = ghostmut::gstruct::u8;                                               \
            (RESULT).s1 = (ARG1).a1 OPERATION (ARG2).a1;                                       \
            break;                                                                             \
        case ghostmut::gstruct::i16:                                                           \
            (RESULT).rt = ghostmut::gstruct::i16;                                              \
            (RESULT).s2 = (ARG1).a2 OPERATION (ARG2).a2;                                       \
            break;                                                                             \
        case ghostmut::gstruct::u16:                                                           \
            (RESULT).rt = ghostmut::gstruct::u16;                                              \
            (RESULT).s3 = (ARG1).a3 OPERATION (ARG2).a3;                                       \
            break;                                                                             \
        case ghostmut::gstruct::i32:                                                           \
            (RESULT).rt = ghostmut::gstruct::i32;                                              \
            (RESULT).s4 = (ARG1).a4 OPERATION (ARG2).a4;                                       \
            break;                                                                             \
        case ghostmut::gstruct::u32:                                                           \
            (RESULT).rt = ghostmut::gstruct::u32;                                              \
            (RESULT).s5 = (ARG1).a5 OPERATION (ARG2).a5;                                       \
            break;                                                                             \
        case ghostmut::gstruct::i64:                                                           \
            (RESULT).rt = ghostmut::gstruct::i64;                                              \
            (RESULT).s6 = (ARG1).a6 OPERATION (ARG2).a6;                                       \
            break;                                                                             \
        case ghostmut::gstruct::u64:                                                           \
            (RESULT).rt = ghostmut::gstruct::u64;                                              \
            (RESULT).s7 = (ARG1).a7 OPERATION (ARG2).a7;                                       \
            break;                                                                             \
        case ghostmut::gstruct::f32:                                                           \
            (RESULT).rt = ghostmut::gstruct::f32;                                              \
            (RESULT).s8 = (ARG1).a8 OPERATION (ARG2).a8;                                       \
            break;                                                                             \
        case ghostmut::gstruct::f64:                                                           \
            (RESULT).rt = ghostmut::gstruct::f64;                                              \
            (RESULT).s9 = (ARG1).a9 OPERATION (ARG2).a9;                                       \
            break;                                                                             \
        case ghostmut::gstruct::f64_l:                                                         \
            (RESULT).rt = ghostmut::gstruct::f64_l;                                            \
            (RESULT).s10 = (ARG1).a10 OPERATION (ARG2).a10;                                    \
            break;                                                                             \
        case ghostmut::gstruct::_l:                                                            \
            (RESULT).rt = ghostmut::gstruct::_l;                                               \
            (RESULT).s11 = (ARG1).a11 OPERATION (ARG2).a11;                                     \
            break;                                                                             \
        case ghostmut::gstruct::_ul:                                                           \
            (RESULT).rt = ghostmut::gstruct::_ul;                                              \
            (RESULT).s12 = (ARG1).a12 OPERATION (ARG2).a12;                                     \
            break;                                                                             \
        case ghostmut::gstruct::_BOOL:                                                         \
            (RESULT).rt = ghostmut::gstruct::_BOOL;                                            \
            (RESULT).s13 = (ARG1).a13 OPERATION (ARG2).a13;                                    \
            break;                                                                             \
        default:                                                                               \
            break;                                                                              \
    }

#define GHOSTMUT_OP_SW_INTEGRAL(OPERATION, ARG1, ARG2, RESULT)                                  \
    switch ((ARG1).at) {                                                                      \
        case ghostmut::gstruct::i8:                                                           \
            (RESULT).rt = ghostmut::gstruct::i8;                                              \
            (RESULT).s0 = (ARG1).a0 OPERATION (ARG2).a0;                                      \
            break;                                                                            \
        case ghostmut::gstruct::u8:                                                           \
            (RESULT).rt = ghostmut::gstruct::u8;                                              \
            (RESULT).s1 = (ARG1).a1 OPERATION (ARG2).a1;                                      \
            break;                                                                            \
        case ghostmut::gstruct::i16:                                                          \
            (RESULT).rt = ghostmut::gstruct::i16;                                             \
            (RESULT).s2 = (ARG1).a2 OPERATION (ARG2).a2;                                      \
            break;                                                                            \
        case ghostmut::gstruct::u16:                                                          \
            (RESULT).rt = ghostmut::gstruct::u16;                                             \
            (RESULT).s3 = (ARG1).a3 OPERATION (ARG2).a3;                                      \
            break;                                                                            \
        case ghostmut::gstruct::i32:                                                          \
            (RESULT).rt = ghostmut::gstruct::i32;                                             \
            (RESULT).s4 = (ARG1).a4 OPERATION (ARG2).a4;                                      \
            break;                                                                            \
        case ghostmut::gstruct::u32:                                                          \
            (RESULT).rt = ghostmut::gstruct::u32;                                             \
            (RESULT).s5 = (ARG1).a5 OPERATION (ARG2).a5;                                      \
            break;                                                                            \
        case ghostmut::gstruct::i64:                                                          \
            (RESULT).rt = ghostmut::gstruct::i64;                                             \
            (RESULT).s6 = (ARG1).a6 OPERATION (ARG2).a6;                                      \
            break;                                                                            \
        case ghostmut::gstruct::u64:                                                          \
            (RESULT).rt = ghostmut::gstruct::u64;                                             \
            (RESULT).s7 = (ARG1).a7 OPERATION (ARG2).a7;                                      \
            break;                                                                            \
        case ghostmut::gstruct::_l:                                                           \
            (RESULT).rt = ghostmut::gstruct::_l;                                              \
            (RESULT).s11 = (ARG1).a11 OPERATION (ARG2).a11;                                    \
            break;                                                                            \
        case ghostmut::gstruct::_ul:                                                          \
            (RESULT).rt = ghostmut::gstruct::_ul;                                             \
            (RESULT).s12 = (ARG1).a12 OPERATION (ARG2).a12;                                    \
            break;                                                                            \
        case ghostmut::gstruct::_BOOL:                                                        \
            (RESULT).rt = ghostmut::gstruct::_BOOL;                                           \
            (RESULT).s13 = (ARG1).a13 OPERATION (ARG2).a13;                                   \
            break;                                                                            \
        default:                                                                              \
            break;                                                                              \
    }

#define GHOSTMUT_ASSIGNOP_SW_ALL(OPERATION, VPOPERATION, ARG1, ARG2, RESULT)                            \
    switch (cmut<std::uint32_t>((ARG1).at).get()) {                                                     \
        case ghostmut::gstruct::i8:                                                                   \
            (RESULT).rt = ghostmut::gstruct::i8;                                                      \
            (RESULT).s0 = ((ARG1).a0 OPERATION (ARG2).a0);                                              \
            *(volatile std::int8_t*)(ARG1).vequ_abs = (RESULT).s0;                                    \
            break;                                                                                     \
        case ghostmut::gstruct::u8:                                                                   \
            (RESULT).rt = ghostmut::gstruct::u8;                                                      \
            (RESULT).s1 = ((ARG1).a1 OPERATION (ARG2).a1);                                              \
            *(volatile std::uint8_t*)(ARG1).vequ_abs = (RESULT).s1;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::i16:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i16;                                                     \
            (RESULT).s2 = ((ARG1).a2 OPERATION (ARG2).a2);                                              \
            *(volatile std::int16_t*)(ARG1).vequ_abs = (RESULT).s2;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u16:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u16;                                                     \
            (RESULT).s3 = ((ARG1).a3 OPERATION (ARG2).a3);                                            \
            *(volatile std::uint16_t*)(ARG1).vequ_abs = (RESULT).s3;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::i32:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i32;                                                     \
            (RESULT).s4 = ((ARG1).a4 OPERATION (ARG2).a4);                                              \
            *(volatile std::int32_t*)(ARG1).vequ_abs = (RESULT).s4;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u32:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u32;                                                     \
            (RESULT).s5 = ((ARG1).a5 OPERATION (ARG2).a5);                                              \
            *(volatile std::uint32_t*)(ARG1).vequ_abs = (RESULT).s5;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::i64:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i64;                                                     \
            (RESULT).s6 = ((ARG1).a6 OPERATION (ARG2).a6);                                              \
            *(volatile std::int64_t*)(ARG1).vequ_abs = (RESULT).s6;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u64:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u64;                                                     \
            (RESULT).s7 = ((ARG1).a7 OPERATION (ARG2).a7);                                              \
            *(volatile std::uint64_t*)(ARG1).vequ_abs = (RESULT).s7;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::f32:                                                                  \
            (RESULT).rt = ghostmut::gstruct::f32;                                                     \
            (RESULT).s8 = ((ARG1).a8 OPERATION (ARG2).a8);                                              \
            *(volatile float*)(ARG1).vequ_abs = (RESULT).s8;                                          \
            break;                                                                                     \
        case ghostmut::gstruct::f64:                                                                  \
            (RESULT).rt = ghostmut::gstruct::f64;                                                     \
            (RESULT).s9 = ((ARG1).a9 OPERATION (ARG2).a9);                                              \
            *(volatile double*)(ARG1).vequ_abs = (RESULT).s9;                                         \
            break;                                                                                     \
        case ghostmut::gstruct::f64_l:                                                                \
            (RESULT).rt = ghostmut::gstruct::f64_l;                                                   \
            (RESULT).s10 = ((ARG1).a10 OPERATION (ARG2).a10);                                           \
            *(volatile long double*)(ARG1).vequ_abs = (RESULT).s10;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::_l:                                                                    \
            (RESULT).rt = ghostmut::gstruct::_l;                                                      \
            (RESULT).s11 = ((ARG1).a11 OPERATION (ARG2).a11);                                           \
            *(volatile long*)(ARG1).vequ_abs = (RESULT).s11;                                           \
            break;                                                                                     \
        case ghostmut::gstruct::_ul:                                                                   \
            (RESULT).rt = ghostmut::gstruct::_ul;                                                     \
            (RESULT).s12 = ((ARG1).a12 OPERATION (ARG2).a12);                                           \
            *(volatile unsigned long*)(ARG1).vequ_abs = (RESULT).s12;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::_BOOL:                                                                 \
            (RESULT).rt = ghostmut::gstruct::_BOOL;                                                   \
            (RESULT).s13 = ((ARG1).a13 OPERATION (ARG2).a13);                                           \
            *(volatile bool*)(ARG1).vequ_abs = (RESULT).s13;                                          \
            break;                                                                                     \
        default:                                                                                       \
            break;                                                                                      \
    }

#define GHOSTMUT_ASSIGNOP_SW_INTEGRAL(OPERATION, VPOPERATION, ARG1, ARG2, RESULT)                       \
    switch (cmut<std::uint32_t>((ARG1).at).get()) {                                                     \
        case ghostmut::gstruct::i8:                                                                   \
            (RESULT).rt = ghostmut::gstruct::i8;                                                      \
            (RESULT).s0 = ((ARG1).a0 OPERATION (ARG2).a0);                                              \
            *(volatile std::int8_t*)(ARG1).vequ_abs = (RESULT).s0;                                    \
            break;                                                                                     \
        case ghostmut::gstruct::u8:                                                                   \
            (RESULT).rt = ghostmut::gstruct::u8;                                                      \
            (RESULT).s1 = ((ARG1).a1 OPERATION (ARG2).a1);                                              \
            *(volatile std::uint8_t*)(ARG1).vequ_abs = (RESULT).s1;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::i16:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i16;                                                     \
            (RESULT).s2 = ((ARG1).a2 OPERATION (ARG2).a2);                                              \
            *(volatile std::int16_t*)(ARG1).vequ_abs = (RESULT).s2;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u16:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u16;                                                     \
            (RESULT).s3 = ((ARG1).a3 OPERATION (ARG2).a3);                                              \
            *(volatile std::uint16_t*)(ARG1).vequ_abs = (RESULT).s3;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::i32:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i32;                                                     \
            (RESULT).s4 = ((ARG1).a4 OPERATION (ARG2).a4);                                              \
            *(volatile std::int32_t*)(ARG1).vequ_abs = (RESULT).s4;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u32:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u32;                                                     \
            (RESULT).s5 = ((ARG1).a5 OPERATION (ARG2).a5);                                              \
            *(volatile std::uint32_t*)(ARG1).vequ_abs = (RESULT).s5;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::i64:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i64;                                                     \
            (RESULT).s6 = ((ARG1).a6 OPERATION (ARG2).a6);                                              \
            *(volatile std::int64_t*)(ARG1).vequ_abs = (RESULT).s6;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u64:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u64;                                                     \
            (RESULT).s7 = ((ARG1).a7 OPERATION (ARG2).a7);                                              \
            *(volatile std::uint64_t*)(ARG1).vequ_abs = (RESULT).s7;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::_l:                                                                    \
            (RESULT).rt = ghostmut::gstruct::_l;                                                      \
            (RESULT).s11 = ((ARG1).a11 OPERATION (ARG2).a11);                                            \
            *(volatile long*)(ARG1).vequ_abs = (RESULT).s11;                                           \
            break;                                                                                     \
        case ghostmut::gstruct::_ul:                                                                   \
            (RESULT).rt = ghostmut::gstruct::_ul;                                                     \
            (RESULT).s12 = ((ARG1).a12 OPERATION (ARG2).a12);                                            \
            *(volatile unsigned long*)(ARG1).vequ_abs = (RESULT).s12;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::_BOOL:                                                                 \
            (RESULT).rt = ghostmut::gstruct::_BOOL;                                                   \
            (RESULT).s10 = ((ARG1).a13 OPERATION (ARG2).a13);                                           \
            *(volatile bool*)(ARG1).vequ_abs = (RESULT).s13;                                          \
            break;                                                                                     \
        default:                                                                                       \
            printf("[-] ghostmut: Unhandled Argument 1 Type: %d\n", (ARG1).at);                       \
            break;                                                                                      \
    }

#define GHOSTMUT_ASSIGNOP_INC_ALL(ARG1, ARG2, RESULT)                                               \
    switch ((ARG1).at) {                                                                              \
        case ghostmut::gstruct::i8:                                                                   \
            (RESULT).rt = ghostmut::gstruct::i8;                                                      \
            (RESULT).s0 = ++((ARG1).a0);                                                            \
            *(volatile std::int8_t*)(ARG1).vequ_abs = (RESULT).s0;                                    \
            break;                                                                                     \
        case ghostmut::gstruct::u8:                                                                   \
            (RESULT).rt = ghostmut::gstruct::u8;                                                      \
            (RESULT).s1 = ++((ARG1).a1);                                                            \
            *(volatile std::uint8_t*)(ARG1).vequ_abs = (RESULT).s1;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::i16:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i16;                                                     \
            (RESULT).s2 = ++((ARG1).a2);                                                            \
            *(volatile std::int16_t*)(ARG1).vequ_abs = (RESULT).s2;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u16:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u16;                                                     \
            (RESULT).s3 = ++((ARG1).a3);                                                            \
            *(volatile std::uint16_t*)(ARG1).vequ_abs = (RESULT).s3;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::i32:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i32;                                                     \
            (RESULT).s4 = ++((ARG1).a4);                                                            \
            *(volatile std::int32_t*)(ARG1).vequ_abs = (RESULT).s4;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u32:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u32;                                                     \
            (RESULT).s5 = ++((ARG1).a5);                                                            \
            *(volatile std::uint32_t*)(ARG1).vequ_abs = (RESULT).s5;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::i64:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i64;                                                     \
            (RESULT).s6 = ++((ARG1).a6);                                                            \
            *(volatile std::int64_t*)(ARG1).vequ_abs = (RESULT).s6;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u64:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u64;                                                     \
            (RESULT).s7 = ++((ARG1).a7);                                                            \
            *(volatile std::uint64_t*)(ARG1).vequ_abs = (RESULT).s7;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::f32:                                                                  \
            (RESULT).rt = ghostmut::gstruct::f32;                                                     \
            (RESULT).s8 = ++((ARG1).a8);                                                            \
            *(volatile float*)(ARG1).vequ_abs = (RESULT).s8;                                          \
            break;                                                                                     \
        case ghostmut::gstruct::f64:                                                                  \
            (RESULT).rt = ghostmut::gstruct::f64;                                                     \
            (RESULT).s9 = ++((ARG1).a9);                                                            \
            *(volatile double*)(ARG1).vequ_abs = (RESULT).s9;                                         \
            break;                                                                                     \
        case ghostmut::gstruct::f64_l:                                                                \
            (RESULT).rt = ghostmut::gstruct::f64_l;                                                   \
            (RESULT).s10 = ++((ARG1).a10);                                                          \
            *(volatile long double*)(ARG1).vequ_abs = (RESULT).s10;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::_l:                                                                    \
            (RESULT).rt = ghostmut::gstruct::_l;                                                      \
            (RESULT).s11 = ++((ARG1).a11);                                                          \
            *(volatile long*)(ARG1).vequ_abs = (RESULT).s11;                                           \
            break;                                                                                     \
        case ghostmut::gstruct::_ul:                                                                   \
            (RESULT).rt = ghostmut::gstruct::_ul;                                                     \
            (RESULT).s12 = ++((ARG1).a12);                                                          \
            *(volatile unsigned long*)(ARG1).vequ_abs = (RESULT).s12;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::_BOOL:                                                                 \
            break;                                                                                     \
        default:                                                                                       \
            break;                                                                                      \
    }

#define GHOSTMUT_ASSIGNOP_DEC_ALL(ARG1, ARG2, RESULT)                                               \
    switch ((ARG1).at) {                                                                              \
        case ghostmut::gstruct::i8:                                                                   \
            (RESULT).rt = ghostmut::gstruct::i8;                                                      \
            (RESULT).s0 = --((ARG1).a0);                                                            \
            *(volatile std::int8_t*)(ARG1).vequ_abs = (RESULT).s0;                                    \
            break;                                                                                     \
        case ghostmut::gstruct::u8:                                                                   \
            (RESULT).rt = ghostmut::gstruct::u8;                                                      \
            (RESULT).s1 = --((ARG1).a1);                                                            \
            *(volatile std::uint8_t*)(ARG1).vequ_abs = (RESULT).s1;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::i16:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i16;                                                     \
            (RESULT).s2 = --((ARG1).a2);                                                             \
            *(volatile std::int16_t*)(ARG1).vequ_abs = (RESULT).s2;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u16:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u16;                                                     \
            (RESULT).s3 = --((ARG1).a3);                                                            \
            *(volatile std::uint16_t*)(ARG1).vequ_abs = (RESULT).s3;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::i32:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i32;                                                     \
            (RESULT).s4 = --((ARG1).a4);                                                            \
            *(volatile std::int32_t*)(ARG1).vequ_abs = (RESULT).s4;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u32:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u32;                                                     \
            (RESULT).s5 = --((ARG1).a5);                                                            \
            *(volatile std::uint32_t*)(ARG1).vequ_abs = (RESULT).s5;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::i64:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i64;                                                     \
            (RESULT).s6 = --((ARG1).a6);                                                            \
            *(volatile std::int64_t*)(ARG1).vequ_abs = (RESULT).s6;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u64:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u64;                                                     \
            (RESULT).s7 = --((ARG1).a7);                                                            \
            *(volatile std::uint64_t*)(ARG1).vequ_abs = (RESULT).s7;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::f32:                                                                  \
            (RESULT).rt = ghostmut::gstruct::f32;                                                     \
            (RESULT).s8 = --((ARG1).a8);                                                            \
            *(volatile float*)(ARG1).vequ_abs = (RESULT).s8;                                          \
            break;                                                                                     \
        case ghostmut::gstruct::f64:                                                                  \
            (RESULT).rt = ghostmut::gstruct::f64;                                                     \
            (RESULT).s9 = --((ARG1).a9);                                                            \
            *(volatile double*)(ARG1).vequ_abs = (RESULT).s9;                                         \
            break;                                                                                     \
        case ghostmut::gstruct::f64_l:                                                                \
            (RESULT).rt = ghostmut::gstruct::f64_l;                                                   \
            (RESULT).s10 = --((ARG1).a10);                                                          \
            *(volatile long double*)(ARG1).vequ_abs = (RESULT).s10;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::_l:                                                                    \
            (RESULT).rt = ghostmut::gstruct::_l;                                                      \
            (RESULT).s11 = --((ARG1).a11);                                                          \
            *(volatile long*)(ARG1).vequ_abs = (RESULT).s11;                                           \
            break;                                                                                     \
        case ghostmut::gstruct::_ul:                                                                   \
            (RESULT).rt = ghostmut::gstruct::_ul;                                                     \
            (RESULT).s12 = --((ARG1).a12);                                                              \
            *(volatile unsigned long*)(ARG1).vequ_abs = (RESULT).s12;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::_BOOL:                                                                 \
            break;                                                                                     \
        default:                                                                                       \
            break;                                                                                      \
    }

#define GHOSTMUT_ASSIGNOP_NOT_INTEGRAL(ARG1, ARG2, RESULT)                                          \
    switch ((ARG1).at) {                                                                              \
        case ghostmut::gstruct::i8:                                                                   \
            (RESULT).rt = ghostmut::gstruct::i8;                                                      \
            (RESULT).s0 = ~((ARG1).a0);                                                             \
            *(volatile std::int8_t*)(ARG1).vequ_abs = (RESULT).s0;                                    \
            break;                                                                                     \
        case ghostmut::gstruct::u8:                                                                   \
            (RESULT).rt = ghostmut::gstruct::u8;                                                      \
            (RESULT).s1 = ~((ARG1).a1);                                                             \
            *(volatile std::uint8_t*)(ARG1).vequ_abs = (RESULT).s1;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::i16:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i16;                                                     \
            (RESULT).s2 = ~((ARG1).a2);                                                             \
            *(volatile std::int16_t*)(ARG1).vequ_abs = (RESULT).s2;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u16:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u16;                                                     \
            (RESULT).s3 = ~((ARG1).a3);                                                             \
            *(volatile std::uint16_t*)(ARG1).vequ_abs = (RESULT).s3;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::i32:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i32;                                                     \
            (RESULT).s4 = ~((ARG1).a4);                                                              \
            *(volatile std::int32_t*)(ARG1).vequ_abs = (RESULT).s4;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u32:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u32;                                                     \
            (RESULT).s5 = ~((ARG1).a5);                                                              \
            *(volatile std::uint32_t*)(ARG1).vequ_abs = (RESULT).s5;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::i64:                                                                  \
            (RESULT).rt = ghostmut::gstruct::i64;                                                     \
            (RESULT).s6 = ~((ARG1).a6);                                                             \
            *(volatile std::int64_t*)(ARG1).vequ_abs = (RESULT).s6;                                   \
            break;                                                                                     \
        case ghostmut::gstruct::u64:                                                                  \
            (RESULT).rt = ghostmut::gstruct::u64;                                                     \
            (RESULT).s7 = ~((ARG1).a7);                                                             \
            *(volatile std::uint64_t*)(ARG1).vequ_abs = (RESULT).s7;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::f32:                                                                  \
            break;                                                                                     \
        case ghostmut::gstruct::f64:                                                                  \
            break;                                                                                     \
        case ghostmut::gstruct::f64_l:                                                                \
            break;                                                                                     \
        case ghostmut::gstruct::_l:                                                                    \
            (RESULT).rt = ghostmut::gstruct::_l;                                                      \
            (RESULT).s11 = ~((ARG1).a11);                                                            \
            *(volatile long*)(ARG1).vequ_abs = (RESULT).s11;                                           \
            break;                                                                                     \
        case ghostmut::gstruct::_ul:                                                                   \
            (RESULT).rt = ghostmut::gstruct::_ul;                                                     \
            (RESULT).s12 = ~((ARG1).a12);                                                               \
            *(volatile unsigned long*)(ARG1).vequ_abs = (RESULT).s12;                                  \
            break;                                                                                     \
        case ghostmut::gstruct::_BOOL:                                                                 \
            break;                                                                                     \
        default:                                                                                       \
            break;                                                                                      \
    }

#pragma endregion

		static __declspec(noinline) LONG CALLBACK ghostmut_veh(PEXCEPTION_POINTERS exception_p) noexcept {

			if (exception_p->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
				return cmut<LONG>(EXCEPTION_CONTINUE_SEARCH);
			/*
				This isn't a ghostmut Breakpoint
			*/
			if (ghostmut::gstruct::g_ghostmut_instruction == ghostmut::gstruct::ERR)
				return cmut<LONG>(EXCEPTION_CONTINUE_SEARCH);

            std::lock_guard<std::recursive_mutex> lock(ghostmut::gstruct::g_ghostmut_interrupt_mtx);

#ifdef ENABLE_VEH_LOGS
#ifdef _M_X64
			printf(QSTR("[+] ghostmut: VEH Mutation Indirection Initiated from Address: 0x%p\n"), exception_p->ContextRecord->Rip);
#else
            printf(QSTR("[+] ghostmut: VEH Mutation Indirection Initiated from Address: 0x%p\n"), exception_p->ContextRecord->Eip);
#endif
#endif

			if (ghostmut::gstruct::g_ghostmut_arg1.at == ghostmut::gstruct::g_ghostmut_arg2.at 
				&& ghostmut::gstruct::g_ghostmut_instruction < ghostmut::gstruct::ghostmut_insn_e::_MEMCOPY
                ) {

				/*
					Assignment Operation Indicated, Pointer Dereference to Occur,
                    Additional Condition for ADDASSIGN as Modulo Operation Yields False Return for it's Value
				*/
				if ((ghostmut::gstruct::g_ghostmut_instruction % 2 && ghostmut::gstruct::g_ghostmut_instruction < 20u) 
                    || ghostmut::gstruct::g_ghostmut_instruction == ghostmut::gstruct::ADDASSIGN
                    || ghostmut::gstruct::g_ghostmut_instruction == ghostmut::gstruct::INC
                    || ghostmut::gstruct::g_ghostmut_instruction == ghostmut::gstruct::DEC
                    || ghostmut::gstruct::g_ghostmut_instruction == ghostmut::gstruct::NOT
                    ) {

#ifdef ENABLE_VEH_LOGS
                    printf(QSTR("[+] ghostmut: MUTATE_ASSIGN Instruction Passed, Executing...\n"));
#endif

                    switch (cmut<std::uint32_t>(ghostmut::gstruct::g_ghostmut_instruction).get()) {

					    case ghostmut::gstruct::ADDASSIGN:
						    GHOSTMUT_ASSIGNOP_SW_ALL(+=, +, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
                            break;
					    case ghostmut::gstruct::SUBASSIGN:
                            GHOSTMUT_ASSIGNOP_SW_ALL(-=, -, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
						    break;
					    case ghostmut::gstruct::MULASSIGN:
						    GHOSTMUT_ASSIGNOP_SW_ALL(*=, *, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
						    break;
					    case ghostmut::gstruct::DIVASSIGN:
						    GHOSTMUT_ASSIGNOP_SW_ALL(/=, / , ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
						    break;
					    case ghostmut::gstruct::MODASSIGN:
						    GHOSTMUT_ASSIGNOP_SW_INTEGRAL(%=, %, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
						    break;
					    case ghostmut::gstruct::ANDASSIGN:
						    GHOSTMUT_ASSIGNOP_SW_INTEGRAL(&=, &, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
						    break;
					    case ghostmut::gstruct::ORASSIGN:
						    GHOSTMUT_ASSIGNOP_SW_INTEGRAL(|=, | , ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
						    break;
					    case ghostmut::gstruct::XORASSIGN:
						    GHOSTMUT_ASSIGNOP_SW_INTEGRAL(^=, ^, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
						    break;
					    case ghostmut::gstruct::SHLASSIGN:
						    GHOSTMUT_ASSIGNOP_SW_INTEGRAL(<<=, << , ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
						    break;
					    case ghostmut::gstruct::SHRASSIGN:
						    GHOSTMUT_ASSIGNOP_SW_INTEGRAL(>>=, >> , ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
						    break;
						case ghostmut::gstruct::INC:
                            GHOSTMUT_ASSIGNOP_INC_ALL(ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
							break;
						case ghostmut::gstruct::DEC:
                            GHOSTMUT_ASSIGNOP_DEC_ALL(ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
							break;
						case ghostmut::gstruct::NOT:
                            GHOSTMUT_ASSIGNOP_NOT_INTEGRAL(ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
							break;
					    default:
#ifdef ENABLE_VEH_LOGS
						    printf(QSTR("[!] ghostcall: Unhandled Assignment Instruction: %d\n"), ghostmut::gstruct::g_ghostmut_instruction);
#endif
                            break;
                    }

#undef GHOSTMUT_ASSIGNOP_SW_ALL

#undef GHOSTMUT_ASSIGNOP_SW_INTEGRAL

				}
				else {

#ifdef ENABLE_VEH_LOGS
                    printf(QSTR("[+] ghostmut: MUTATE Instruction Passed, Executing...\n"));
#endif

					switch (cmut<std::uint32_t>(ghostmut::gstruct::g_ghostmut_instruction).get()) {

						case ghostmut::gstruct::ADD:
							GHOSTMUT_OP_SW_ALL(+, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
							break;
						case ghostmut::gstruct::SUB:
							GHOSTMUT_OP_SW_ALL(-, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
							break;
						case ghostmut::gstruct::MUL:
							GHOSTMUT_OP_SW_ALL(*, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
							break;
						case ghostmut::gstruct::DIV:
							GHOSTMUT_OP_SW_ALL(/, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
							break;
						case ghostmut::gstruct::MOD:
							GHOSTMUT_OP_SW_INTEGRAL(%, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
							break;
						case ghostmut::gstruct::AND:
							GHOSTMUT_OP_SW_INTEGRAL(&, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
							break;
						case ghostmut::gstruct::OR:
							GHOSTMUT_OP_SW_INTEGRAL(|, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
							break;
						case ghostmut::gstruct::XOR:
							GHOSTMUT_OP_SW_INTEGRAL(^, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
							break;
						case ghostmut::gstruct::SHL:
							GHOSTMUT_OP_SW_INTEGRAL(<<, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
							break;
						case ghostmut::gstruct::SHR:
							GHOSTMUT_OP_SW_INTEGRAL(>>, ghostmut::gstruct::g_ghostmut_arg1, ghostmut::gstruct::g_ghostmut_arg2, ghostmut::gstruct::g_ghostmut_sum);
							break;
						default:
#ifdef ENABLE_VEH_LOGS
							printf(QSTR("[!] ghostcall: Unhandled Instruction: %d\n"), ghostmut::gstruct::g_ghostmut_instruction);
#endif
                            break;
					}
                    
#undef GHOSTMUT_OP_SW_ALL

#undef GHOSTMUT_OP_SW_INTEGRAL

				}
            }
            else if (ghostmut::gstruct::g_ghostmut_instruction >= ghostmut::gstruct::ghostmut_insn_e::_MEMCOPY) {

#ifdef ENABLE_VEH_LOGS
                printf(QSTR("[+] ghostmut: Primitive Memory Operation Passed, Initiating...\n"));
#endif

				DWORD x_perms = NULL;

                switch (ghostmut::gstruct::g_ghostmut_instruction) {

                    case ghostmut::gstruct::_MEMCOPY:

                        if (ghostmut::gstruct::g_ghostmut_arg1.a13)
                            if (!virtualprotect_rtImp_inst((void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_abs, ghostmut::gstruct::g_ghostmut_arg1.a_res2, ghostmut::gstruct::g_ghostmut_arg1.a12, &x_perms))
                                break;

                        ghostmut::gstruct::g_ghostmut_arg1.a_res = (std::uintptr_t)std::memcpy((void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_res, (void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_abs, ghostmut::gstruct::g_ghostmut_arg1.a_res2);

                        if (ghostmut::gstruct::g_ghostmut_arg1.a13)
                            if (!virtualprotect_rtImp_inst((void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_abs, ghostmut::gstruct::g_ghostmut_arg1.a_res2, ghostmut::gstruct::g_ghostmut_arg1.a12, &x_perms))
                                break;

#ifdef ENABLE_VEH_LOGS
                        printf(QSTR("[+] ghostmut: GHOSTMUT_MEMCPY Success, Exiting Conditional Block...\n"));
#endif

                        break;
                    case ghostmut::gstruct::_MEMMOVE:

                        if (ghostmut::gstruct::g_ghostmut_arg1.a13)
                            if (!virtualprotect_rtImp_inst((void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_abs, ghostmut::gstruct::g_ghostmut_arg1.a_res2, ghostmut::gstruct::g_ghostmut_arg1.a12, &x_perms))
                                break;

                        ghostmut::gstruct::g_ghostmut_arg1.a_res = (std::uintptr_t)std::memmove((void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_res, (void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_abs, ghostmut::gstruct::g_ghostmut_arg1.a_res2);

                        if (ghostmut::gstruct::g_ghostmut_arg1.a13)
                            if (!virtualprotect_rtImp_inst((void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_abs, ghostmut::gstruct::g_ghostmut_arg1.a_res2, ghostmut::gstruct::g_ghostmut_arg1.a12, &x_perms))
                                break;

#ifdef ENABLE_VEH_LOGS
                        printf(QSTR("[+] ghostmut: GHOSTMUT_MEMMOVE Success, Exiting Conditional Block...\n"));
#endif

                        break;
                    case ghostmut::gstruct::_MEMSET:

                        if (ghostmut::gstruct::g_ghostmut_arg1.a13)
                            if (!virtualprotect_rtImp_inst((void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_res, ghostmut::gstruct::g_ghostmut_arg1.a_res2, ghostmut::gstruct::g_ghostmut_arg1.a12, &x_perms))
                                break;

                        ghostmut::gstruct::g_ghostmut_arg1.a_res = (std::uintptr_t)std::memset((void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_res, (std::uint8_t)ghostmut::gstruct::g_ghostmut_arg1.vequ_abs, ghostmut::gstruct::g_ghostmut_arg1.a_res2);

                        if (ghostmut::gstruct::g_ghostmut_arg1.a13)
                            if (!virtualprotect_rtImp_inst((void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_res, ghostmut::gstruct::g_ghostmut_arg1.a_res2, ghostmut::gstruct::g_ghostmut_arg1.a12, &x_perms))
                                break;

#ifdef ENABLE_VEH_LOGS
                        printf(QSTR("[+] ghostmut: GHOSTMUT_MEMSET Success, Exiting Conditional Block...\n"));
#endif

                        break;
                    case ghostmut::gstruct::_MEMCMP:

                        if (ghostmut::gstruct::g_ghostmut_arg1.a13)
                            if (!virtualprotect_rtImp_inst((void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_abs, ghostmut::gstruct::g_ghostmut_arg1.a_res2, ghostmut::gstruct::g_ghostmut_arg1.a12, &x_perms))
                                break;

                        ghostmut::gstruct::g_ghostmut_arg1.a_res = (std::size_t)std::memcmp((void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_res, (void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_abs, ghostmut::gstruct::g_ghostmut_arg1.a_res2);

                        if (ghostmut::gstruct::g_ghostmut_arg1.a13)
                            if (!virtualprotect_rtImp_inst((void*)ghostmut::gstruct::g_ghostmut_arg1.vequ_abs, ghostmut::gstruct::g_ghostmut_arg1.a_res2, ghostmut::gstruct::g_ghostmut_arg1.a12, &x_perms))
                                break;

#ifdef ENABLE_VEH_LOGS
                        printf(QSTR("[+] ghostmut: GHOSTMUT_MEMCMP Success, Exiting Conditional Block...\n"));
#endif

                        break;
                    default:
#ifdef ENABLE_VEH_LOGS
                        printf(QSTR("[!] ghostmut: Unhandled Primitive Memory Operation: %d\n"), ghostmut::gstruct::g_ghostmut_instruction);
#endif
                        break;
                }
            }
            else {
				printf(QSTR("[!] ghostmut: Unhandled Instruction: %d\n"), ghostmut::gstruct::g_ghostmut_instruction);
            }

            /*
                Simulate Return Address pop from Stack
            */
#ifdef _M_X64
			exception_p->ContextRecord->Rip = *(DWORD64*)exception_p->ContextRecord->Rsp;

			exception_p->ContextRecord->Rsp += cmut<std::uintptr_t>(sizeof(DWORD64)).get();

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] ghostmut: Instruction Pointer Set to Caller Return Address: 0x%p\n"), *(DWORD64*)exception_p->ContextRecord->Rsp);
#endif

#else
			exception_p->ContextRecord->Eip = *(DWORD32*)exception_p->ContextRecord->Esp;

			exception_p->ContextRecord->Esp += sizeof(DWORD32);
#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] ghostmut: Instruction Pointer Set to Caller Return Address: 0x%p\n"), exception_p->ContextRecord->Esp);
#endif

#endif

#ifdef ENABLE_VEH_LOGS
            printf(QSTR("[+] ghostmut: VEH Mutation Completed, Returning to Caller...\n"));
#endif

			return cmut<LONG>(EXCEPTION_CONTINUE_EXECUTION);
        };

        static __compelled_inline imut bool __stackcall install_ghostmut_veh() noexcept {


            std::lock_guard<std::recursive_mutex> lock(ghostmut::gstruct::g_ghostmut_interrupt_mtx);

            static cmut<volatile bool> is_veh_installed = false;

            if (is_veh_installed.get())
                return true;

            if (!AddVectoredExceptionHandler(1, ghostmut_veh)) {

#ifdef ENABLE_VEH_LOGS
                printf(QSTR("[!] ghostmut: Failed to Install VEH Handler\n"));
#endif

                return cmut<bool>(false).get();
            }

            is_veh_installed = true;

#ifdef ENABLE_VEH_LOGS
            printf(QSTR("[+] ghostmut: VEH Handler Installed Successfully\n"));
#endif

            return is_veh_installed.get();
        }

#pragma region VEH Auto-Install 

        struct _auto_install_ghostmut_veh {


            __compelled_inline __stackcall _auto_install_ghostmut_veh() noexcept {

                // Redundant, but Looks more Uniform
                static std::once_flag flag;

                std::call_once(

                    flag,

                    []() -> void {

                        if (!install_ghostmut_veh()) {
#ifdef ENABLE_VEH_LOGS
                            printf(QSTR("[!] ghostmut: Auto Install of VEH Handler Failed\n"));
#endif
                        }
                    }

                );
            }
        };

        inline _auto_install_ghostmut_veh _auto_install_ghostmut_veh_Inst;

	} // namespace gveh

} // namespace ghostcall

#endif