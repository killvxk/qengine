/*
	ghostcall Provides a Level of Indirection for Function Calls, Allowing for Discrete && Hard-to-Trace Function Calls, with all the Obfuscation Necessary Provided by C++20 Codebase and your Choice of Compiler -
    No VMProtect or Third-Party bin2bin Obfuscator Required. 
	ghostcall Essentially Calls a Dummy Function Pointer, which Triggers a Windows SEH VEH Handler, which then Redirects the Execution to the True Callee Function, making the True Callee Unknown to any Reverse Engineer
	or Malware Analyst, as the Dummy Function Pointer is Randomly Generated and Obfuscated, and the True Callee is Encrypted in Memory, making it Hard to Trace.
*/

#ifndef GSTRUCT_HXX
#define GSTRUCT_HXX

#include "../pdfn/pdfn.hxx"

#include <TlHelp32.h>

#pragma pack(push, 1)

#define GHOST_FUNC(__RET_RMOD__, __NAME__, __ARGS__)					\
    PDFN __RET_RMOD__ STDCALL __NAME__ __ARGS__;						\
    PDFN __RET_RMOD__ STDCALL __NAME__ __ARGS__ { FORCE_NLEAF();

namespace ghostapi {

#pragma region ghostapi Shared Singleton

    inline std::mutex proc32_mtx;

    inline std::mutex interrupt_interlock_mtx;

#pragma endregion

#pragma region Interrupt Padding Thread-Safe Globals

    inline std::vector<std::uintptr_t>                              g_ghostapi_pad_abs;

#pragma endregion

#pragma region Thread-Freezing (Workaround for MT Race-Conditions with WINAPI)

    /*
        Most Standard Library Functions are OOP Interface Wrappers around the Windows API (on Windows), Likewise Hooking any Common API Function Produces the Possibility of Numerous Race Conditions
        and Misdirections in Control-flow Across Multiple Threads.

        It would be far too Complex and Cumbersome to Mutex Lock up to a Potentially Infinite Amount of Threads in a Breakpoint-Style Hook while still Achieving the Objective Purpose of the Hook,
        so i have Decided to Play it Safe, and Freeze all Threads Other than the Calling Thread for Ease of Coding.

        (If you REALLY need this level of Security, it Shouldn't be used in any situation often enough for the performance to matter. Use it in a Licensing Window or Something once or twice)
    */

    inline std::vector<HANDLE> g_thr_snapshot;

    static inline void __cdecl suspend_all_else() noexcept {

        const auto pid = GetCurrentProcessId();

        const auto this_thr = GetCurrentThreadId();

        const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);

        if (snapshot == INVALID_HANDLE_VALUE) return;

        THREADENTRY32 entry_thr = { sizeof(THREADENTRY32) };

        for (BOOL rcode = Thread32First(snapshot, &entry_thr); rcode; rcode = Thread32Next(snapshot, &entry_thr)) {

            if (entry_thr.th32OwnerProcessID != pid || entry_thr.th32ThreadID == this_thr) continue;

            if (HANDLE thr_h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry_thr.th32ThreadID)) {

                printf("[+] ghostapi: Suspending Thread: %p\n", thr_h);

                if (SuspendThread(thr_h) != DWORD(-1))
                    g_thr_snapshot.push_back(thr_h);
                else
                    CloseHandle(thr_h);
            }
        }

        CloseHandle(snapshot);
    }

    static inline void _cdecl resume_all_else() noexcept {

        if (!g_thr_snapshot.size())
            return;

        for (auto& thr_h : g_thr_snapshot) {

            printf("[+] ghostapi: Resuming Thread: %p\n", thr_h);

            ResumeThread(thr_h);

            CloseHandle(thr_h);
        }

        g_thr_snapshot.clear();
    }

#pragma endregion

#pragma region Thread-safe UserAPI Function Wrapper

    std::mutex ghostmut_thrsafe_userapi_mtx;

    /*
        This Creates a Thread-Safe UserAPI Call, which can be used to call any Function specified for Usage by the ghostmut API (Use this Function to Invoke the Target Function for EACH CALL in your Application)

        ** You must Define USE_THREADSAFE_USERAPI_MTX in order for this Function to Protect Against Race Conditions, otherwise it will be UNSAFE to use this Function in a Multi-Threaded Environment.

        ** You must use the stdcall Convention for the Target Function or this will likely crash your Application
    */
    template<typename T, typename... args>
    static inline T ghostmut_threadsafe_userapi_call(

        volatile void* abs,

        args... arguments

    ) noexcept {

        // No Argument Safetycheck as it is Unknown if Return Type may be Casted to NULL - Ensure Call Safety Yourself

        using fn_t = T(__stdcall*)(args...);

        std::lock_guard<std::mutex> lock(ghostmut_thrsafe_userapi_mtx);

        return std::invoke(std::bit_cast<fn_t>((void*)abs), std::forward<args>(arguments)...);
    }

#pragma endregion
};

namespace ghostcall {

    namespace gstruct {

#pragma region Ghostcall Globals

        /*
            0 = HeapAlloc,
            1 = Interrupt Padding,
            2 = WINAPI
        */
        inline thread_local volatile std::uint8_t                       g_ghostcall_backup_u8 = NULL;

        inline std::recursive_mutex                                     g_ghostcall_interrupt_mtx;

#ifndef GHOSTCALL_USE_DYNALLOC
        inline cmut<volatile bool>                                      g_ghostcall_mode = true;
#else
        inline cmut<volatile bool>                                      g_ghostcall_mode = false;
#endif

        // Holds the Ghostcall Breakpoint Flag, Used to Distinguish Between Legitimate Breakpoints and Ghostcall Breakpoints
        // This is Set to True When a Ghostcall is Invoked, and Reset to False After the Call Completes
		// This is Used in the VEH to Determine if the Breakpoint was Hit by a Ghostcall or a Legitimate Call
		inline thread_local cmut<volatile bool>                         is_ghostcall_breakpoint = false;

        // Holds the Encrypted (For now, Simply Inversed) Address of the Ghostcall True Callee / Target Function
        inline thread_local cmut<volatile std::uintptr_t>               ghostcall_true_callee = NULL;

#pragma endregion

#pragma region Ghostcall Function Metadata / Invocation Routine

        typedef enum callconvention_t {

            _STDCALL = 0,

#define GSTDCALL ghostcall::gstruct::_STDCALL

            _CDECL = 1,

#define GCDECL ghostcall::gstruct::_CDECL

            _FASTCALL = 2,

#define GFASTCALL ghostcall::gstruct::_FASTCALL
        };

#define GCALL_INVOKE(Ret, Addr, Conv, ...)                                           \
    (ghostcall::gstruct::ghostcall_invoke<Ret>(                                      \
        reinterpret_cast<volatile void*>(&(Addr)),                                   \
        (Conv),                                                                      \
        __VA_ARGS__))

        template<typename T, typename... args>
        static inline volatile T __stdcall ghostcall_invoke(

            volatile void*          abs,

            const callconvention_t  convention,

            args...                 arguments

        ) noexcept {

            std::lock_guard<std::mutex> ghostapi_lock(ghostapi::interrupt_interlock_mtx);

            std::lock_guard<std::recursive_mutex> interr_lock(g_ghostcall_interrupt_mtx);

#pragma region Call Spoof Setup

#pragma region Address Resolution Macro
            
#define GHOST_EXPAND_GETADDR(ADDR) \
if (!g_ghostcall_mode.get()) {\
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

            volatile void* insn_addr = nullptr;

#ifdef _M_X64
            MAKERD64();
#else
            MAKERD32();
#endif

			GHOST_EXPAND_GETADDR(insn_addr);

#undef GHOST_EXPAND_GETADDR

            DWORD x_perms = NULL;

            if (!virtualprotect_rtImp_inst((void*)insn_addr, sizeof(std::uint8_t), PAGE_EXECUTE_READWRITE, &x_perms))
                return T(NULL);

            g_ghostcall_backup_u8 = reinterpret_cast<volatile std::uint8_t*>(insn_addr)[0];

            reinterpret_cast<volatile std::uint8_t*>(insn_addr)[0] = INT3;

            ghostcall::gstruct::ghostcall_true_callee = ~(reinterpret_cast<std::uintptr_t>(abs));

            ghostcall::gstruct::is_ghostcall_breakpoint = true;

#pragma endregion

            cmut<volatile T> rcode = T(NULL);

            switch (convention) {

                case _STDCALL:
                    rcode = reinterpret_cast<volatile T(__stdcall*)(args...)>(const_cast<void*>(insn_addr))(arguments...);
                    break;
                case _CDECL:
                    rcode = reinterpret_cast<volatile T(__cdecl*)(args...)>(const_cast<void*>(insn_addr))(arguments...);
                    break;
                case _FASTCALL:
                    rcode = reinterpret_cast<volatile T(__fastcall*)(args...)>(const_cast<void*>(insn_addr))(arguments...);
                    break;
                default:
                    return T(NULL);
            }

            reinterpret_cast<volatile std::uint8_t*>(insn_addr)[0] = g_ghostcall_backup_u8;

            FlushInstructionCache(GetCurrentProcess(), (void*)insn_addr, sizeof(std::uint8_t));

            if (!VirtualProtect((void*)insn_addr, sizeof(std::uint8_t), x_perms, &x_perms))
                return T(NULL);

            x_perms = NULL;

            is_ghostcall_breakpoint = cmut<bool>(false).get();

            if (g_ghostcall_mode.get())
                ghostapi::g_ghostapi_pad_abs.pop_back();
            else
                delete insn_addr;

            return rcode.get();
        }

        /*
			Use this Function if you wish to Specify a Windows API / User API Function to Call, instead of a Ghostcall Function Pointer; 

            userapi_fn = Addressof(WINAPI / USERAPI Function)

			suspend_else_threads = true if you wish to Suspend all Threads other than the Calling Thread, false otherwise (If you Specify WINAPI Function and Encounter Crashes / Hangs, this MAY resolve the Issue).
			If suspend_else_threads Fails to Solve the Problem - Create a Singleton Mutex and Wrap all Calls to the Target WINAPI Function in a Mutex Lock Guard (Which you Obviously lock before Calling this as well)
        */
        template<typename T, typename... args>
        static inline volatile T __stdcall ghostcall_invoke_userapi(

            volatile void*          abs,

            const callconvention_t  convention,

			volatile void*          userapi_fn,

			const bool 			    suspend_else_threads,

            args...                 arguments

        ) noexcept {

#pragma region Prologue / Mutex Guard

#ifdef USE_THREADSAFE_USERAPI_MTX

			std::lock_guard<std::mutex> lock(ghostapi::ghostmut_thrsafe_userapi_mtx);

#endif

            std::lock_guard<std::recursive_mutex> interr_lock(g_ghostcall_interrupt_mtx);

            if (suspend_else_threads) {

                std::lock_guard<std::mutex> thr_lock(ghostapi::proc32_mtx);

                ghostapi::suspend_all_else();
            }

#pragma endregion

#pragma region UserAPI Call Spoof Setup

            DWORD x_perms = NULL;

            if (!virtualprotect_rtImp_inst((void*)userapi_fn, sizeof(std::uint8_t), PAGE_EXECUTE_READWRITE, &x_perms))
                return T(NULL);

            g_ghostcall_backup_u8 = reinterpret_cast<volatile std::uint8_t*>(userapi_fn)[0];

            reinterpret_cast<volatile std::uint8_t*>(userapi_fn)[0] = INT3;

            ghostcall::gstruct::ghostcall_true_callee = ~(reinterpret_cast<std::uintptr_t>(abs));

            ghostcall::gstruct::is_ghostcall_breakpoint = true;

#pragma endregion

            cmut<volatile T> rcode = T(NULL);

            switch (convention) {

                case _STDCALL:
                    rcode = reinterpret_cast<volatile T(__stdcall*)(args...)>(const_cast<void*>(userapi_fn))(arguments...);
                    break;
                case _CDECL:
                    rcode = reinterpret_cast<volatile T(__cdecl*)(args...)>(const_cast<void*>(userapi_fn))(arguments...);
                    break;
                case _FASTCALL:
                    rcode = reinterpret_cast<volatile T(__fastcall*)(args...)>(const_cast<void*>(userapi_fn))(arguments...);
                    break;
                default:
                    return T(NULL);
            }

            reinterpret_cast<volatile std::uint8_t*>(userapi_fn)[0] = g_ghostcall_backup_u8;

            FlushInstructionCache(GetCurrentProcess(), (void*)userapi_fn, sizeof(std::uint8_t));

            if (!virtualprotect_rtImp_inst((void*)userapi_fn, sizeof(std::uint8_t), x_perms, &x_perms))
                return T(NULL);

            if (suspend_else_threads)
                ghostapi::resume_all_else();

            x_perms = NULL;

            is_ghostcall_breakpoint = cmut<bool>(false).get();

            return rcode.get();
        }

#pragma endregion

    } // namespace gstruct

} // namespace ghostcall

#pragma pack(pop)

#endif