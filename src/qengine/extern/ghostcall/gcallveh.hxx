#ifndef GVEH_HXX
#define GVEH_HXX

#include "gcallstruct.hxx"

/*
	Work on making this and pdfn Thread-Safe. As of now, if one thread is executing a Ghostcall , and another thread attempts to execute a Ghostcall, it will cause Problems
	As there is Only one Global Set of Ghostcall Descriptors (Real Callee, dummy API FN etc.)
	Turn this into an UnorderedMap, and include the Thread ID in each entry including more indentifying info that we are handling the proper call, same with pdfn

	ALSO, be careful and edit the RNG algorithm to exclude posssiblity of using same WINAPI dummy fn for multiple ghostcalls
*/
namespace ghostcall {

	namespace gveh {

		static NO_INLINE LONG CALLBACK ghostcall_veh(PEXCEPTION_POINTERS exception_p) noexcept {
		
			if (exception_p->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
				return cmut<LONG>(EXCEPTION_CONTINUE_SEARCH);

			if(!ghostcall::gstruct::ghostcall_true_callee.get() || !ghostcall::gstruct::is_ghostcall_breakpoint.get())
				return cmut<LONG>(EXCEPTION_CONTINUE_SEARCH);

			printf(QSTR("[+] ghostcall: Awaiting Mutex...\n"));

			std::lock_guard<std::recursive_mutex> lock(ghostcall::gstruct::g_ghostcall_interrupt_mtx);

#ifdef ENABLE_VEH_LOGS
#ifdef _M_X64
			printf(QSTR("[+] ghostcall: VEH Function Indirection Initiated @ Address: 0x%p\n"), exception_p->ContextRecord->Rip);
#else
			printf(QSTR("[+] ghostcall: VEH Function Indirection Initiated @ Address: 0x%p\n"), exception_p->ContextRecord->Eip);
#endif
#endif

#ifdef _M_X64
			exception_p->ContextRecord->Rip = ~ghostcall::gstruct::ghostcall_true_callee.get();
#else
			exception_p->ContextRecord->Eip = ~ghostcall::gstruct::ghostcall_true_callee.get();
#endif

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] ghostcall: Instruction Pointer Set to Address: 0x%p\n[+] Cleaning Globals...\n"), ~ghostcall::gstruct::ghostcall_true_callee.get());
#endif

			ghostcall::gstruct::ghostcall_true_callee ^= cmut<std::uintptr_t>(ghostcall::gstruct::ghostcall_true_callee).get();
			
#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] ghostcall: Instruction Pointer Override Succesfull, Directing Execution to Callee...\n"));
#endif

			return cmut<LONG>(EXCEPTION_CONTINUE_EXECUTION);
		}

#pragma region Ghostcall VEH Installation

		static __compelled_inline imut bool __stackcall install_ghostcall_veh() noexcept {

			std::lock_guard<std::recursive_mutex> lock(ghostcall::gstruct::g_ghostcall_interrupt_mtx);

			static cmut<volatile bool> is_veh_installed = false;

			if (is_veh_installed.get())
				return true;

			if (!AddVectoredExceptionHandler(1, ghostcall_veh)) {

#ifdef ENABLE_VEH_LOGS
				printf(QSTR("[!] ghostcall: Failed to Install VEH Handler\n"));
#endif

				return cmut<bool>(false).get();
			}

			is_veh_installed = true;

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] ghostcall: VEH Handler Installed Successfully\n"));
#endif

			return is_veh_installed.get();
		}

#pragma region VEH Auto-Install 

		struct _auto_install_ghostcall_veh {


			__compelled_inline __stackcall _auto_install_ghostcall_veh() noexcept {

				// Redundant, but Looks more Uniform
				static std::once_flag flag;

				std::call_once(

					flag,

					[]() -> void {

						if (!install_ghostcall_veh()) {
#ifdef ENABLE_VEH_LOGS
							printf(QSTR("[!] ghostcall: Auto Install of VEH Handler Failed\n"));
#endif
						}
					}

				);
			}
		};

		inline _auto_install_ghostcall_veh _auto_install_ghostcall_veh_Inst;

#pragma endregion

#pragma endregion

	} // namespace gveh

} // namespace ghostcall

#endif