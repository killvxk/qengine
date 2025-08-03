/*
    ghostmut, Like ghostcall, is Essentially another Mechanism of Achieving a Function Hook, with some Instruction Pseudo-Virtualization and Generalized Indirection About the Instruction in Question, 
    without the Typical Suspicious mov{reg, address}, jmp{reg} etc. Formations usually seen with Classic Trampolines. 

	Interrupt Breakpoints are Widely Accepted as non-malicious, and are used in Debugging, so they are a Perfect Candidate for a Function Hook Mechanism which Shouldn't Raise Major Concerns from:

    - Antivirus Software
	- Anticheat Software
    - Malware Analysis Software
	- Reverse Engineers
*/

#ifndef GMUTSTRUCT_HXX
#define GMUTSTRUCT_HXX

#include <ctime>
#include <cstdint>
#include <cstddef>
#include <random>
#include <vector>
#include <type_traits>

#include "../ghostcall/gcallveh.hxx"

#pragma pack(push, 1)

#define INT3 0xCCu

#pragma region ghostapi Setting Macros

#define GHOSTAPI_USE_INTERRUPT_PADDING  typedef struct gapi_use_ipadding{inline gapi_use_ipadding(){ghostmut::gstruct::g_ghostmut_mode.set(true); ghostcall::gstruct::g_ghostcall_mode.set(true);}}; inline gapi_use_ipadding gapi_use_ipadding_instance;

#define GHOSTAPI_USE_HEAP_ALLOC         typedef struct gapi_use_heapalloc{inline gapi_use_heapalloc(){ghostmut::gstruct::g_ghostmut_mode.set(false); ghostcall::gstruct::g_ghostcall_mode.set(false);}}; inline gapi_use_heapalloc gapi_use_heapalloc_instance;

#pragma endregion

/*
    Use same gstruct winapi defs in qengine implementation, simply use different thread local flags to indicate ghostmut as opposed to pdfn / ghostmut etc. 
*/
namespace ghostmut {

    namespace gstruct {

        typedef enum ghostmut_insn_e : std::uint8_t {

            ADD = 0, ADDASSIGN,

#define GINSN_ADD ghostmut::gstruct::ghostmut_insn_e::ADD
#define GINSN_ADDEQU ghostmut::gstruct::ghostmut_insn_e::ADDASSIGN

            SUB, SUBASSIGN,

#define GINSN_SUB ghostmut::gstruct::ghostmut_insn_e::SUB
#define GINSN_SUBEQU ghostmut::gstruct::ghostmut_insn_e::SUBASSIGN

            DIV, DIVASSIGN,

#define GINSN_DIV ghostmut::gstruct::ghostmut_insn_e::DIV
#define GINSN_DIVEQU ghostmut::gstruct::ghostmut_insn_e::DIVASSIGN

            MUL, MULASSIGN,

#define GINSN_MUL ghostmut::gstruct::ghostmut_insn_e::MUL
#define GINSN_MULEQU ghostmut::gstruct::ghostmut_insn_e::MULASSIGN

			MOD, MODASSIGN,

#define GINSN_MOD ghostmut::gstruct::ghostmut_insn_e::MOD
#define GINSN_MODEQU ghostmut::gstruct::ghostmut_insn_e::MODASSIGN

            AND, ANDASSIGN,

#define GINSN_AND ghostmut::gstruct::ghostmut_insn_e::AND
#define GINSN_ANDEQU ghostmut::gstruct::ghostmut_insn_e::ANDASSIGN

            OR, ORASSIGN,

#define GINSN_OR ghostmut::gstruct::ghostmut_insn_e::OR
#define GINSN_OREQU ghostmut::gstruct::ghostmut_insn_e::ORASSIGN

            XOR, XORASSIGN,

#define GINSN_XOR ghostmut::gstruct::ghostmut_insn_e::XOR
#define GINSN_XOREQU ghostmut::gstruct::ghostmut_insn_e::XORASSIGN

            SHL, SHLASSIGN,

#define GINSN_SHL ghostmut::gstruct::ghostmut_insn_e::SHL
#define GINSN_SHLEQU ghostmut::gstruct::ghostmut_insn_e::SHLASSIGN

            SHR, SHRASSIGN,

#define GINSN_SHR ghostmut::gstruct::ghostmut_insn_e::SHR
#define GINSN_SHREQU ghostmut::gstruct::ghostmut_insn_e::SHRASSIGN

            INC, DEC,

#define GINSN_INC ghostmut::gstruct::ghostmut_insn_e::INC
#define GINSN_DEC ghostmut::gstruct::ghostmut_insn_e::DEC

            NOT,

#define GINSN_NOT ghostmut::gstruct::ghostmut_insn_e::NOT

            _MEMCOPY,

#define GINSN_MEMCPY ghostmut::gstruct::ghostmut_insn_e::_MEMCOPY

            _MEMMOVE,

#define GINSN_MEMMOVE ghostmut::gstruct::ghostmut_insn_e::_MEMMOVE

            _MEMSET,

#define GINSN_MEMSET ghostmut::gstruct::ghostmut_insn_e::_MEMSET

            _MEMCMP,

#define GINSN_MEMCMP ghostmut::gstruct::ghostmut_insn_e::_MEMCMP

            ERR

#define GINSN_ERR ghostmut::gstruct::ghostmut_insn_e::ERR

        } ghostmut_insn_e;

        typedef enum ghostmut_t_e : std::uint8_t {

            i8,

            u8,

            i16,

            u16,

            i32,

            u32,

            i64,

            u64,

            f32,

            f64,

            f64_l,

            _l,

            _ul,

            _BOOL,

            // These are all Indirect Memory Commands, so as you can Hide Primitve Memory Operations (Copy (R / W), Move, Set)
            __MEMCOPY,

            __MEMMOVE,

			__MEMSET,

            __MEMCMP,

            _ERR
        };

        template<class T, class = void>
        struct ghostmut_t_to_e;

#define GHOSTMAP(TYPE, ENUM)                                    \
    template<> struct ghostmut_t_to_e<TYPE>{                    \
    static constexpr ghostmut_t_e value = ghostmut_t_e::ENUM;   \
};

        GHOSTMAP(std::int8_t, i8)       GHOSTMAP(std::uint8_t, u8)
        GHOSTMAP(std::int16_t, i16)     GHOSTMAP(std::uint16_t, u16)
        GHOSTMAP(std::int32_t, i32)     GHOSTMAP(std::uint32_t, u32)
        GHOSTMAP(std::int64_t, i64)     GHOSTMAP(std::uint64_t, u64)
        GHOSTMAP(float, f32)            GHOSTMAP(double, f64)
        GHOSTMAP(long double, f64_l)
        GHOSTMAP(long, _l)              GHOSTMAP(unsigned long, _ul)
        GHOSTMAP(bool, _BOOL)

        // e.g constexpr auto e = to_ghostmut_enum<std::uint32_t>();  // → ghostmut_t_e::u32

#undef GHOSTMAP
        
        /*
            a13 = VirtualProtect flag for Memory Operations;
			a12 = Protection flags (if Applicable)
            vequ_abs = Source Address of Memory Operation
			vequ_res = Destination of Memory Operation (if Applicable)
            a_res = Result of Memory Operation (if Applicable)
        */
        struct ghostmut_arg_t {

            // For MUTATEEQUAL operations
            volatile void*          vequ_abs;

			volatile void*          vequ_res;

			volatile std::uint64_t  a_res;

            volatile std::size_t    a_res2;

			volatile bool 	        b1; 

			volatile bool 	        b2;

            ghostmut_t_e            at;

            volatile std::int8_t    a0;

            volatile std::uint8_t   a1;

            volatile std::int16_t   a2;

            volatile std::uint16_t  a3;

            volatile std::int32_t   a4;

            volatile std::uint32_t  a5;

            volatile std::int64_t   a6;

            volatile std::uint64_t  a7;

            volatile float          a8;

            volatile double         a9;

            volatile long double    a10;

			volatile long           a11;

			volatile unsigned long  a12;

            volatile bool           a13;
		};

        /*
			ghostmut_arg_t Member Offsets, used to Translate ghostmut_t_e to the Correct Member Offset
        */
        std::uintptr_t ghostsmut_a_member_translate[]{

            offsetof(ghostmut_arg_t, a0),

			offsetof(ghostmut_arg_t, a1),

			offsetof(ghostmut_arg_t, a2),

			offsetof(ghostmut_arg_t, a3),

			offsetof(ghostmut_arg_t, a4),

			offsetof(ghostmut_arg_t, a5),

			offsetof(ghostmut_arg_t, a6),

			offsetof(ghostmut_arg_t, a7),

			offsetof(ghostmut_arg_t, a8),

			offsetof(ghostmut_arg_t, a9),

			offsetof(ghostmut_arg_t, a10),

			offsetof(ghostmut_arg_t, a11),

			offsetof(ghostmut_arg_t, a12),

			offsetof(ghostmut_arg_t, a13)
        };

        template<typename T>
        inline void ghost_write(volatile ghostmut_arg_t& arg, const ghostmut_t_e gt, volatile T& val) noexcept {
            
            auto* ptr = reinterpret_cast<volatile std::uint8_t*>(&arg);

            reinterpret_cast<volatile T*>(&ptr[ghostsmut_a_member_translate[gt]])[0] = val;
        };

        /*
			ghostmut Return Structure, used to Return Results of Operations, and also to Store the Result of Memory Operations
        */
        struct ghostmut_sum_t {

            ghostmut_t_e            rt;

            volatile std::int8_t    s0;

            volatile std::uint8_t   s1;

            volatile std::int16_t   s2;

            volatile std::uint16_t  s3;

            volatile std::int32_t   s4;

            volatile std::uint32_t  s5;

            volatile std::int64_t   s6;

            volatile std::uint64_t  s7;

            volatile float          s8;

            volatile double         s9;

            volatile long double    s10;

            volatile long           s11;

            volatile unsigned long  s12;

			volatile bool           s13;
        };

        /*
			ghostmut_sum_t Member Offsets, used to Translate ghostmut_t_e to the Correct Member Offset
        */
        const std::uintptr_t ghostmut_sum_member_translate[]{

			offsetof(ghostmut_sum_t, s0),

			offsetof(ghostmut_sum_t, s1),

			offsetof(ghostmut_sum_t, s2),

			offsetof(ghostmut_sum_t, s3),

			offsetof(ghostmut_sum_t, s4),

			offsetof(ghostmut_sum_t, s5),

			offsetof(ghostmut_sum_t, s6),

			offsetof(ghostmut_sum_t, s7),

			offsetof(ghostmut_sum_t, s8),

			offsetof(ghostmut_sum_t, s9),

			offsetof(ghostmut_sum_t, s10),

			offsetof(ghostmut_sum_t, s11),

			offsetof(ghostmut_sum_t, s12),

			offsetof(ghostmut_sum_t, s13)
		};

        template<typename T>
        inline volatile T& ghost_read(volatile ghostmut_sum_t& sum, const ghostmut_t_e gt) noexcept {

            auto* ptr = reinterpret_cast<volatile std::uint8_t*>(&sum);

            return reinterpret_cast<volatile T*>(&ptr[ghostmut_sum_member_translate[gt]])[0];
        };

#pragma region ghostmut Globals

        /*
            0 = HeapAlloc,
            1 = Interrupt Padding,
            2 = WINAPI
        */
        inline thread_local volatile std::uint8_t                       g_ghostmut_backup_u8 = NULL;

        inline std::recursive_mutex                                     g_ghostmut_interrupt_mtx;

#ifndef GHOSTMUT_USE_DYNALLOC
        inline cmut<volatile bool>                                      g_ghostmut_mode = true;
#else
        inline cmut<volatile bool>                                      g_ghostmut_mode = false;
#endif

        inline volatile thread_local ghostmut_insn_e                    g_ghostmut_instruction = ghostmut_insn_e::ERR;

        inline volatile thread_local ghostmut_arg_t                     g_ghostmut_arg1;

		inline volatile thread_local ghostmut_arg_t                     g_ghostmut_arg2;

		inline thread_local ghostmut_sum_t                              g_ghostmut_sum;

#pragma endregion

#pragma region Invokation Macros

#define GHOSTMUT_INSN(GVAR1, GVAR2, GINSTRUCTION) ghostmut::gstruct::ghostmut_invoke<decltype(GVAR1), decltype(GVAR2)>(GVAR1, GVAR2, GINSTRUCTION)

#define GHOSTMUT_MEMCPY(_DESTINATION, _SOURCE, _LEN) ghostmut::gstruct::ghostmut_invoke_memprim((void*)(_DESTINATION), (void*)(_SOURCE), _LEN, GINSN_MEMCPY)

#define GHOSTMUT_MEMCPY_VP(_DESTINATION, _SOURCE, _LEN, _VFLAGS, _VP_DESTINATION, _VP_SOURCE) ghostmut::gstruct::ghostmut_invoke_memprim((void*)(_DESTINATION), (void*)(_SOURCE), _LEN, GINSN_MEMCPY, true, _VFLAGS, _VP_DESTINATION, _VP_SOURCE)

#define GHOSTMUT_MEMMOVE(_DESTINATION, _SOURCE, _LEN) ghostmut::gstruct::ghostmut_invoke_memprim((void*)(_DESTINATION), (void*)(_SOURCE), _LEN, GINSN_MEMMOVE)

#define GHOSTMUT_MEMMOVE_VP(_DESTINATION, _SOURCE, _LEN, _VFLAGS, _VP_DESTINATION, _VP_SOURCE) ghostmut::gstruct::ghostmut_invoke_memprim((void*)(_DESTINATION), (void*)(_SOURCE), _LEN, GINSN_MEMMOVE, true, _VFLAGS, _VP_DESTINATION, _VP_SOURCE)

#define GHOSTMUT_MEMSET(_DESTINATION, _BYTE_SET, _LEN) ghostmut::gstruct::ghostmut_invoke_memprim((void*)(_DESTINATION), nullptr, _LEN, GINSN_MEMSET, false, NULL, false, false, _BYTE_SET)

#define GHOSTMUT_MEMSET_VP(_DESTINATION, _BYTE_SET, _LEN, _VFLAGS, _VP_DESTINATION, _VP_SOURCE) ghostmut::gstruct::ghostmut_invoke_memprim((void*)(_DESTINATION), nullptr, _LEN, GINSN_MEMSET, true, _VFLAGS, _VP_DESTINATION, _VP_SOURCE, _BYTE_SET)

#define GHOSTMUT_MEMCMP(_DESTINATION, _SOURCE, _LEN) ghostmut::gstruct::ghostmut_invoke_memprim((void*)(_DESTINATION), (void*)(_SOURCE), _LEN, GINSN_MEMCMP)

#define GHOSTMUT_MEMCMP_VP(_DESTINATION, _SOURCE, _LEN, _VFLAGS, _VP_DESTINATION, _VP_SOURCE) ghostmut::gstruct::ghostmut_invoke_memprim((void*)(_DESTINATION), (void*)(_SOURCE), _LEN, GINSN_MEMCMP, true, _VFLAGS, _VP_DESTINATION, _VP_SOURCE)
        
#pragma endregion

#pragma region Thread-Safe Invokers

        static inline std::uint64_t ghostmut_invoke_memprim(

#pragma region Arguments

            void* dst,

            void* src,

            const std::size_t len,

            const ghostmut_insn_e prim,

            const bool vp = false,

            const DWORD vp_flag = NULL,

            bool vp_dst = false,

            bool vp_src = false,

            const std::uint8_t set = NULL

#pragma endregion

        ) {

#pragma region Prologue / Mutex Guard

            std::lock_guard<std::mutex> ghostapi_lock(ghostapi::interrupt_interlock_mtx);

            std::lock_guard<std::recursive_mutex> interr_lock(g_ghostmut_interrupt_mtx);

#pragma endregion

#pragma region ghostmut Argument Frame Setup

            g_ghostmut_arg1.a13 = vp;

            g_ghostmut_arg1.vequ_abs = src;

            g_ghostmut_arg1.vequ_res = dst;

            g_ghostmut_arg1.a_res = NULL;

            g_ghostmut_arg1.a_res2 = len;

            g_ghostmut_arg1.at = (prim == GINSN_MEMCPY ? ghostmut_t_e::__MEMCOPY : prim == GINSN_MEMMOVE ? ghostmut_t_e::__MEMMOVE : prim == GINSN_MEMCMP ? ghostmut_t_e::__MEMCMP : prim == GINSN_MEMSET ? ghostmut_t_e::__MEMSET : ghostmut_t_e::_ERR);

            if (g_ghostmut_arg1.at == ghostmut_t_e::_ERR)
                return NULL;

            g_ghostmut_arg1.a0 = set;

            g_ghostmut_instruction = prim;

            g_ghostmut_arg1.a12 = vp_flag;

            g_ghostmut_arg1.b1 = vp_dst;

            g_ghostmut_arg1.b2 = vp_src;

#pragma endregion

#pragma region Address Resolution Macro

#define GHOST_EXPAND_GETADDR(ADDR) \
if (!g_ghostmut_mode.get()) {\
        ADDR = (volatile void*)cmut<std::uintptr_t>(\
            (std::uintptr_t)(new std::uint8_t(\
                cmut<std::uint8_t>(INT3).get()))\
        ).get();\
}\
else {\
    while (true) {\
        bool is_used_region = false;\
        std::uintptr_t region_start = NULL;\
        const auto& region = qengine::qmorph::qdisasm::interrupt_mappings()[r() % qengine::qmorph::qdisasm::interrupt_mappings().size()];\
        for (std::size_t i = 0; i < ghostapi::g_ghostapi_pad_abs.size(); ++i)\
            if (ghostapi::g_ghostapi_pad_abs[i] == (std::uintptr_t)region.region_address)\
                is_used_region = true;\
        if (!is_used_region) {\
            ghostapi::g_ghostapi_pad_abs.push_back(region_start = (std::uintptr_t)region.region_address);\
            ADDR = static_cast<volatile void*>(\
                reinterpret_cast<volatile std::uint8_t*>(region.region_address) + (r() % region.region_length));\
            break;\
        }\
    }\
}

#pragma endregion

#pragma region Interrupt CallSpoof Setup

            volatile void* insn_addr = nullptr;

#ifdef _M_X64
            MAKERD64();
#else
            MAKERD32();
#endif

			GHOST_EXPAND_GETADDR(insn_addr);

            DWORD x_perms = 0;

            if (!virtualprotect_rtImp_inst((void*)insn_addr, sizeof(std::uint8_t), PAGE_EXECUTE_READWRITE, &x_perms))
                return NULL;

            // Backup first Byte of Prologue for the Function
            g_ghostmut_backup_u8 = reinterpret_cast<volatile std::uint8_t*>(insn_addr)[0];

            // Overwrite first Byte with Interrupt Instruction (Restore it in the Case of qsection_assembler having Morphed it, Redundant Elseways but Must be Certain it's an Interrupt)
            reinterpret_cast<volatile std::uint8_t*>(insn_addr)[0] = INT3;

            reinterpret_cast<void(__stdcall*)()>(const_cast<void*>(insn_addr))();

            reinterpret_cast<volatile std::uint8_t*>(insn_addr)[0] = g_ghostmut_backup_u8;

            if (!virtualprotect_rtImp_inst((void*)insn_addr, sizeof(std::uint8_t), x_perms, &x_perms))
                return NULL;

#pragma endregion

#pragma region Epilogue / Cleanup

            x_perms = NULL;

            if (g_ghostmut_mode.get())
                ghostapi::g_ghostapi_pad_abs.pop_back();
            else
                delete insn_addr;
            
            ghostmut::gstruct::g_ghostmut_instruction = GINSN_ERR;

            return g_ghostmut_arg1.a_res;

#pragma endregion

        };

        template<typename T1, typename T2>
        static inline auto ghostmut_invoke(

#pragma region Arguments

            volatile T1& arg1,

            volatile T2 arg2,

            const ghostmut_insn_e insn

#pragma endregion
        
        ) -> typename std::common_type<T1, T2>::type {

#pragma region Prologue / Mutex Guard

            std::lock_guard<std::mutex> ghostapi_lock(ghostapi::interrupt_interlock_mtx);

            std::lock_guard<std::recursive_mutex> interr_lock(g_ghostmut_interrupt_mtx);

#pragma endregion

#pragma region ghostmut Argument Frame Setup

            using T3 = typename std::common_type<T1, T2>::type;

            constexpr const ghostmut_t_e ghost_t = ghostmut_t_to_e<T3>::value;

            T3 arg1_c = static_cast<T3>(arg1);

            T3 arg2_c = static_cast<T3>(arg2);

            g_ghostmut_instruction = insn;

            g_ghostmut_arg1.at = ghost_t;
            g_ghostmut_arg2.at = ghost_t;

            ghost_write(g_ghostmut_arg1, ghost_t, arg1_c);
            ghost_write(g_ghostmut_arg2, ghost_t, arg2_c);

            if ((ghostmut::gstruct::g_ghostmut_instruction % 2 && ghostmut::gstruct::g_ghostmut_instruction < 20u)
                || ghostmut::gstruct::g_ghostmut_instruction == ghostmut::gstruct::ADDASSIGN
                || ghostmut::gstruct::g_ghostmut_instruction == ghostmut::gstruct::INC
                || ghostmut::gstruct::g_ghostmut_instruction == ghostmut::gstruct::DEC
                || ghostmut::gstruct::g_ghostmut_instruction == ghostmut::gstruct::NOT
                )
                g_ghostmut_arg1.vequ_abs = reinterpret_cast<volatile void*>(&arg1);

#pragma endregion

#pragma region Interrupt CallSpoof Setup

            volatile void* insn_addr = nullptr;

#ifdef _M_X64
            MAKERD64();
#else
            MAKERD32();
#endif

			GHOST_EXPAND_GETADDR(insn_addr);

#undef GHOST_EXPAND_GETADDR

            DWORD x_perms = 0;

            if (!VirtualProtect((void*)insn_addr, sizeof(std::uint8_t), PAGE_EXECUTE_READWRITE, &x_perms))
                return T3(NULL);

            // Backup first Byte of Prologue for the Function
            g_ghostmut_backup_u8 = reinterpret_cast<volatile std::uint8_t*>(insn_addr)[0];

            // Overwrite first Byte with Interrupt Instruction (Restore it in the Case of qsection_assembler having Morphed it, Redundant Elseways but Must be Certain it's an Interrupt)
            reinterpret_cast<volatile std::uint8_t*>(insn_addr)[0] = INT3;

            FlushInstructionCache(GetCurrentProcess(), (void*)insn_addr, sizeof(std::uint8_t));

            reinterpret_cast<void(__stdcall*)()>(const_cast<void*>(insn_addr))();

            if (!VirtualProtect((void*)insn_addr, sizeof(std::uint8_t), x_perms, &x_perms))
                return T3(NULL);
#pragma endregion

#pragma region Epilogue / Cleanup

            x_perms = NULL;

            if (g_ghostmut_mode.get())
                ghostapi::g_ghostapi_pad_abs.pop_back();
            else
                delete insn_addr;

            ghostmut::gstruct::g_ghostmut_instruction = ERR;

            return ghost_read<T3>(g_ghostmut_sum, ghost_t);

#pragma endregion

        };

#pragma endregion

#pragma region Custom UserAPI Invokers (POTENTIALLY NOT Thread-safe)

        static inline std::uint64_t ghostmut_invoke_memprim_userapi(

#pragma region Arguments

            void* dst,

            void* src,

            const std::size_t       len,

            const ghostmut_insn_e   prim,

            volatile void*          userapi_fn,

            const bool 	            suspend_else_threads,

            const bool              vp = false,

            const DWORD             vp_flag = NULL,

            bool                    vp_dst = false,

            bool                    vp_src = false,

            const std::uint8_t      set = NULL

#pragma endregion

        ) noexcept {

#pragma region Prologue / Mutex Guard

#ifdef USE_THREADSAFE_USERAPI_MTX
            std::lock_guard<std::mutex> lock(ghostapi::ghostmut_thrsafe_userapi_mtx);
#endif

            std::lock_guard<std::recursive_mutex> interr_lock(g_ghostmut_interrupt_mtx);

            if (suspend_else_threads) {

                std::lock_guard<std::mutex> thr_lock(ghostapi::proc32_mtx);

                ghostapi::suspend_all_else();
            }

#pragma endregion

#pragma region ghostmut Argument Frame Setup

            g_ghostmut_arg1.a13 = vp;

            g_ghostmut_arg1.vequ_abs = src;

            g_ghostmut_arg1.vequ_res = dst;

            g_ghostmut_arg1.a_res = NULL;

            g_ghostmut_arg1.a_res2 = len;

            g_ghostmut_arg1.at = (prim == GINSN_MEMCPY ? ghostmut_t_e::__MEMCOPY : prim == GINSN_MEMMOVE ? ghostmut_t_e::__MEMMOVE : prim == GINSN_MEMCMP ? ghostmut_t_e::__MEMCMP : prim == GINSN_MEMSET ? ghostmut_t_e::__MEMSET : ghostmut_t_e::_ERR);

            if (g_ghostmut_arg1.at == ghostmut_t_e::_ERR)
                return NULL;

            g_ghostmut_arg1.a0 = set;

            g_ghostmut_instruction = prim;

            g_ghostmut_arg1.a12 = vp_flag;

            g_ghostmut_arg1.b1 = vp_dst;

            g_ghostmut_arg1.b2 = vp_src;

#pragma endregion

#pragma region User API CallSpoof

            DWORD x_perms = 0;

            if (!virtualprotect_rtImp_inst((void*)userapi_fn, sizeof(std::uint8_t), PAGE_EXECUTE_READWRITE, &x_perms))
                return NULL;

            // Backup first Byte of Prologue for the Function
            g_ghostmut_backup_u8 = reinterpret_cast<volatile std::uint8_t*>(userapi_fn)[0];

            // Overwrite first Byte with Interrupt Instruction (Restore it in the Case of qsection_assembler having Morphed it, Redundant Elseways but Must be Certain it's an Interrupt)
            reinterpret_cast<volatile std::uint8_t*>(userapi_fn)[0] = INT3;

            reinterpret_cast<void(__stdcall*)()>(const_cast<void*>(userapi_fn))();

            reinterpret_cast<volatile std::uint8_t*>(userapi_fn)[0] = g_ghostmut_backup_u8;

            if (!virtualprotect_rtImp_inst((void*)userapi_fn, sizeof(std::uint8_t), x_perms, &x_perms))
                return NULL;

#pragma endregion

#pragma region Epilogue / Cleanup

            x_perms = NULL;

            if (suspend_else_threads)
                ::ghostapi::resume_all_else();

            ghostmut::gstruct::g_ghostmut_instruction = GINSN_ERR;

            return g_ghostmut_arg1.a_res;

#pragma endregion

        };

        template<typename T1, typename T2>
        static inline auto ghostmut_invoke_userapi(

#pragma region Arguments

            volatile T1&            arg1,

            volatile T2             arg2,

            const ghostmut_insn_e   insn,

            volatile void*          userapi_fn,

            const bool 	            suspend_else_threads

#pragma endregion

        ) -> typename std::common_type<T1, T2>::type {

#pragma region Prologue / Mutex Guard

#ifdef USE_THREADSAFE_USERAPI_MTX
            std::lock_guard<std::mutex> lock(ghostapi::ghostmut_thrsafe_userapi_mtx);
#endif

            std::lock_guard<std::recursive_mutex> interr_lock(g_ghostmut_interrupt_mtx);

            if (suspend_else_threads) {

                std::lock_guard<std::mutex> thr_lock(ghostapi::proc32_mtx);

                ghostapi::suspend_all_else();
            }

#pragma endregion

#pragma region ghostmut Argument Frame Setup

            using T3 = typename std::common_type<T1, T2>::type;

            constexpr const ghostmut_t_e ghost_t = ghostmut_t_to_e<T3>::value;

            T3 arg1_c = static_cast<T3>(arg1);

            T3 arg2_c = static_cast<T3>(arg2);

            g_ghostmut_instruction = insn;

            g_ghostmut_arg1.at = ghost_t;
            g_ghostmut_arg2.at = ghost_t;

            ghost_write(g_ghostmut_arg1, ghost_t, arg1_c);
            ghost_write(g_ghostmut_arg2, ghost_t, arg2_c);

            if ((ghostmut::gstruct::g_ghostmut_instruction % 2 && ghostmut::gstruct::g_ghostmut_instruction < 20u)
                || ghostmut::gstruct::g_ghostmut_instruction == ghostmut::gstruct::ADDASSIGN
                || ghostmut::gstruct::g_ghostmut_instruction == ghostmut::gstruct::INC
                || ghostmut::gstruct::g_ghostmut_instruction == ghostmut::gstruct::DEC
                || ghostmut::gstruct::g_ghostmut_instruction == ghostmut::gstruct::NOT
                )
                g_ghostmut_arg1.vequ_abs = reinterpret_cast<volatile void*>(&arg1);

#pragma endregion

#pragma region User API CallSpoof

            DWORD x_perms = 0;

            if (!virtualprotect_rtImp_inst((void*)userapi_fn, sizeof(std::uint8_t), PAGE_EXECUTE_READWRITE, &x_perms))
                return T3(NULL);

            // Backup first Byte of Prologue for the Function
            g_ghostmut_backup_u8 = reinterpret_cast<volatile std::uint8_t*>(userapi_fn)[0];

            // Overwrite first Byte with Interrupt Instruction (Restore it in the Case of qsection_assembler having Morphed it, Redundant Elseways but Must be Certain it's an Interrupt)
            reinterpret_cast<volatile std::uint8_t*>(userapi_fn)[0] = INT3;

            FlushInstructionCache(GetCurrentProcess(), (void*)userapi_fn, sizeof(std::uint8_t));

            reinterpret_cast<void(__stdcall*)()>(const_cast<void*>(userapi_fn))();

            if (!virtualprotect_rtImp_inst((void*)userapi_fn, sizeof(std::uint8_t), x_perms, &x_perms))
                return T3(NULL);

#pragma endregion

#pragma region Epilogue / Cleanup

            x_perms = NULL;

            if (suspend_else_threads)
                ghostapi::resume_all_else();

            ghostmut::gstruct::g_ghostmut_instruction = ERR;

            return ghost_read<T3>(g_ghostmut_sum, ghost_t);

#pragma endregion

        };

#pragma endregion

#pragma endregion

    } // namespace gstruct

} // namespace ghostmut

#pragma pack(pop)

#endif