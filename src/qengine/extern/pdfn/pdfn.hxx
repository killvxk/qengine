/*
	This Class Essentially Does Nothing in Debug Mode, as the pdata Section is Ommited in Debug Builds, 
	And does Nothing in x86_32 Build Targets
*/
#ifndef PDATA_HXX
#define PDATA_HXX

#pragma region Includes

#pragma region std

#include <vector>
#include <cstdint>
#include <cstring>
#include <utility>
#include <algorithm>
#include <mutex>

#pragma endregion

#pragma region Windows

#define NOMINMAX

#include <Windows.h>
#include <Psapi.h>

#pragma endregion

#pragma region qengine

#include "../../qmorph/qdisasm.hpp"
#include "../../../qengine/engine/qcipher_provider.hpp"

#pragma endregion

#pragma region Capstone

#include "../capstone/include/capstone/capstone.h"

#pragma endregion

#pragma endregion

#pragma region Preprocessor

#ifdef _WIN64

#pragma comment(lib, "capstone64.lib")

#elif defined(_WIN32)

#pragma comment(lib, "capstone32.lib")

#endif

#pragma endregion

#pragma region Preprocessor / imutants

#ifdef _WIN64

#define qcs_mode CS_MODE_64

#else

#define qcs_mode CS_MODE_32

#endif

#pragma endregion

#pragma region Macros

/*
	In order for a Function to Qualify as Non-Leaf, it MUST Alter Non-Voltile Registers E.G RSP, and by Forcing Stackspace Allocation we Force
	a .pdata (Exception Table) Entry to be Created for the Function

	This Creates a [[Potential]] Detection Vector if Always Placed at the Beginning of a Function, Techinically at all, However is Less Likely to be Recognized if Placed at Random Points within Function Body
	Removes the Need for using #pragma optimize("", off)
*/

#define FORCE_NLEAF() do{ volatile char __pad__[2]{__TIME__[6]}; volatile std::uint8_t* __vpad__ = (volatile std::uint8_t*)__pad__; __vpad__[0] = __TIME__[7];if(__vpad__[1] == __TIME__[6]) Sleep(__vpad__[0]); }while(0)

#define FORCE_PDFN FORCE_NLEAF();

/*
	NO_INLINE Macro:
	Prevents the compiler from inlining a function.
	Supported by MSVC, GCC, and Clang.
*/

#define PDFN NO_INLINE

#define INT3 (0xCCu)

namespace pdfn {

#pragma region Data Structures

	/*
		pdata_fn Structure:
		Represents metadata for a function, including its address, length, state, and exception table entry.
	*/
	struct pdata_fn {

		volatile const void*				abs;

		const std::size_t					len;

		bool								state;

		std::uintptr_t						ret_address;

		const std::uint8_t					first_insn_backup;

		std::uint8_t						ret_address_backup;

#ifdef _WIN64

		volatile const PRUNTIME_FUNCTION	ppdata_entry;

#endif

	};

#pragma endregion

#pragma region Singleton Globals

#pragma region PE Information

	inline volatile std::uintptr_t			module_base_address = NULL;

	inline volatile std::uintptr_t			module_end_address = NULL;

	inline volatile PIMAGE_DOS_HEADER		pdos_header = nullptr;

	inline volatile PIMAGE_NT_HEADERS		pnt_headers = nullptr;

	inline volatile PIMAGE_DATA_DIRECTORY	pdata_directory_entry;

	inline volatile PIMAGE_SECTION_HEADER	ppdata_scn_header = nullptr;

	inline			std::size_t				pdata_exception_entry_ct = 0;

#ifdef _WIN64

	inline volatile PRUNTIME_FUNCTION		pfirst_exception_entry = nullptr;

#endif

#pragma endregion

#pragma region Threading

	inline std::recursive_mutex				g_pdfn_mtx;

#pragma endregion

#pragma region Windows SEH Information Store

	/*
		This is used to Store all Original Instructions Located at Breakpoint Emplacements
	*/
	inline std::vector<pdata_fn> bp_insn_backups;

#pragma endregion

#pragma endregion

#pragma region PE Parsing

#pragma region Exception Table Arithmetic

#ifdef _WIN64

	/*
		abs_to_pdata_entry Function:
		Converts an absolute address to its corresponding exception table entry.
	*/
	static inline volatile const PRUNTIME_FUNCTION abs_to_pdata_entry(volatile const void* abs) noexcept {

		if (!abs || !pfirst_exception_entry || !pdata_exception_entry_ct)
			return nullptr;

		volatile auto pdata_entry = pfirst_exception_entry;

		for (std::size_t i = 0; i < pdata_exception_entry_ct; ++pdata_entry, ++i) {

			if ((module_base_address + pdata_entry->BeginAddress) == reinterpret_cast<std::uintptr_t>(abs))
				return pdata_entry;
		}

		return nullptr;
	}

#endif

	static inline const std::size_t legacy_get_function_length(volatile const void* abs) noexcept {

		std::size_t function_size = static_cast<size_t>(0x0);

		const std::uint8_t* address_iterator = reinterpret_cast<const std::uint8_t*>(const_cast<void*>(abs));

		csh handle;

		if ((cs_open(CS_ARCH_X86, qcs_mode, &handle) != CS_ERR_OK) || !handle)
			return NULL;

		cs_insn* instructions = nullptr;

		do {

			auto disasm_count = cs_disasm(handle, reinterpret_cast<LPCBYTE>(address_iterator), 0x10, reinterpret_cast<uint64_t>(address_iterator), static_cast<size_t>(0x0), &instructions);

			if (!disasm_count)
				break;

			/*
				This Function Obviously Breaks if an Artificial Breakpoint is Placed within the Function Body
			*/
			if (instructions[0].id == X86_INS_INT3)
				break;

			function_size += instructions[0].size;
			address_iterator += instructions[0].size;

			cs_free(instructions, disasm_count);

		} while (true);

		return function_size;
	}

	static inline const std::size_t get_function_length(volatile const void* abs) noexcept {

		if (!abs)
			return NULL;

		std::lock_guard<std::recursive_mutex> lock(g_pdfn_mtx);

#ifdef _WIN64

		volatile PRUNTIME_FUNCTION pdata_entry = nullptr;

		if (!(pdata_entry = abs_to_pdata_entry(abs)))
			return legacy_get_function_length(abs);

		return (pdata_entry->EndAddress - pdata_entry->BeginAddress);
#else

		return legacy_get_function_length(abs);

#endif
	}



#pragma endregion

#pragma region Windows SEH Handling

	static inline pdata_fn* get_bp_insn_entry(volatile const void* abs ) noexcept {

		if (!abs)
			return nullptr;

		for (auto& bp_entry : bp_insn_backups)
			if (reinterpret_cast<volatile const std::uintptr_t>(bp_entry.abs) == reinterpret_cast<std::uintptr_t>(abs))
				return &bp_entry;

#ifdef _WIN64

		volatile PRUNTIME_FUNCTION pdata_entry = nullptr;

		if (!(pdata_entry = abs_to_pdata_entry(abs)))
			return nullptr;

		const auto fn_len = static_cast<std::size_t>(pdata_entry->EndAddress - pdata_entry->BeginAddress);

#else

		const std::size_t fn_len = get_function_length(abs);

#endif

		/*
			If we Reach this Point, no Entry has been Created
		*/
		bp_insn_backups.push_back(

			{
				abs,

				fn_len,

				false,

				NULL,

				reinterpret_cast<volatile const std::uint8_t*>(abs)[0],

				NULL,

#ifdef _WIN64

				pdata_entry

#endif
			}
		);

		return &bp_insn_backups[bp_insn_backups.size() - 1];
	}

	static inline pdata_fn* get_bp_entry_from_retaddr(const std::uintptr_t retaddr) noexcept {

		if (!retaddr)
			return nullptr;

		for (auto& bp_entry : bp_insn_backups) {

			if (bp_entry.ret_address == retaddr)
				return &bp_entry;
		}

		return nullptr;
	}

	static inline const bool insert_bp_abs(volatile void* abs) noexcept {

		if (!abs)
			return false;

		std::lock_guard<std::recursive_mutex> lock(g_pdfn_mtx);

		pdata_fn* bp_entry = nullptr;

		if (!(bp_entry = get_bp_insn_entry(abs)))
			return false;

		DWORD x_perm = NULL;

		if (!virtualprotect_rtImp_inst(const_cast<void*>(abs), bp_entry->len, PAGE_EXECUTE_READWRITE, &x_perm))
			return false;

		qengine::qcipher_provider::cipher_encrypt(const_cast<void*>(abs), const_cast<void*>(abs), bp_entry->len);

		reinterpret_cast<volatile std::uint8_t*>(abs)[0] = INT3;

		bp_entry->state = true;

		FlushInstructionCache(GetCurrentProcess(), const_cast<void*>(abs), bp_entry->len);

		if (!virtualprotect_rtImp_inst(const_cast<void*>(abs), bp_entry->len, x_perm, &x_perm))
			return false;

		return true;
	}

	static __declspec(noinline) LONG CALLBACK pdfn_veh(PEXCEPTION_POINTERS exception_p) noexcept {

		if (
			(exception_p->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
			||
#ifdef _M_X64
			(exception_p->ContextRecord->Rip < module_base_address || exception_p->ContextRecord->Rip > module_end_address))
#else
			(exception_p->ContextRecord->Eip < module_base_address || exception_p->ContextRecord->Eip > module_end_address))
#endif
				return cmut<LONG>(EXCEPTION_CONTINUE_SEARCH);

		std::lock_guard<std::recursive_mutex> lock(g_pdfn_mtx);

#ifdef ENABLE_VEH_LOGS
		printf(QSTR("[+] Breakpoint VEH Routine Initiated @ Address 0x%p\n"), (std::uintptr_t)exception_p->ExceptionRecord->ExceptionAddress);
#endif

		cmut<std::uintptr_t> cexception_address(reinterpret_cast<std::uintptr_t>(exception_p->ExceptionRecord->ExceptionAddress));

		pdata_fn* bp_entry = nullptr;

		/*
			We MUST check for Return Address FIRST, as if we Check for ABS First, on the Return Address Breakpoint, it Obviously won't Match the Exception Address,
			and get_bp_insn_entry() will Create a New && Stripped (Zero) Entry with the Return Address as the ABS which Corrupts the 2nd VEH Subroutine
		*/
		if (!(bp_entry = get_bp_entry_from_retaddr(cexception_address.get())))
			if (!(bp_entry = get_bp_insn_entry((void*)cexception_address.get())))
				return EXCEPTION_CONTINUE_SEARCH;

#ifdef ENABLE_VEH_LOGS
		printf(QSTR("[+] Breakpoint Address Verified Within Module Address-Space\n"));
#endif

		DWORD x_perm = NULL, r_perm = NULL;

		/* Function Breakpoint (Decrypt Function), Restore First Byte of First INSN of Function */
		if (cmut<bool>(bp_entry->state).get()) {

			if (!virtualprotect_rtImp_inst((void*)cexception_address.get(), bp_entry->len, PAGE_EXECUTE_READWRITE, &x_perm))
				return cmut<LONG>(EXCEPTION_CONTINUE_SEARCH);

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] Callee VirtualProtect RWX Call_1 Success\n"));
#endif
			// Spare the Second get() Accessor for Performance; This is Already Scrambled beyond Necessity
			qengine::qcipher_provider::cipher_decrypt((void*)cexception_address.get(), exception_p->ExceptionRecord->ExceptionAddress, bp_entry->len);

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] Callee FN Decryption Success @ Address: 0x%p, FN Size: 0x%p\n"), reinterpret_cast<std::uintptr_t>(exception_p->ExceptionRecord->ExceptionAddress), bp_entry->len);
#endif

			reinterpret_cast<volatile std::uint8_t*>(cexception_address.get())[0] = bp_entry->first_insn_backup;

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] First Callee Function Byte 0x%02X Restored @ Address 0x%p\n"), bp_entry->first_insn_backup, reinterpret_cast<std::uintptr_t>(exception_p->ExceptionRecord->ExceptionAddress));
#endif

#ifdef _M_X64
			bp_entry->ret_address = *reinterpret_cast<std::uintptr_t*>(cmut<std::uintptr_t>(exception_p->ContextRecord->Rsp).get());
#else
			bp_entry->ret_address = *reinterpret_cast<std::uintptr_t*>(cmut<std::uintptr_t>(exception_p->ContextRecord->Esp).get());
#endif
			
#ifdef ENABLE_VEH_LOGS
			printf(

				QSTR("[+] Caller Return Address Recovered from Caller Stackframe @ 0x%p, Address: 0x%p\n"),

#ifdef _M_X64
				exception_p->ContextRecord->Rsp,
#else
				exception_p->ContextRecord->Esp,
#endif

				bp_entry->ret_address
			);
#endif

			if (!VirtualProtect(reinterpret_cast<void*>(bp_entry->ret_address), sizeof(std::uint8_t), cmut<DWORD>(PAGE_EXECUTE_READWRITE).get(), &r_perm))
				return cmut<LONG>(EXCEPTION_CONTINUE_SEARCH);

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] Caller VirtualProtect RWX Call_2 Success\n"));
#endif

			bp_entry->ret_address_backup = reinterpret_cast<volatile std::uint8_t*>(bp_entry->ret_address)[0];

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] First Caller Return Address Byte 0x%02X Stashed\n"), bp_entry->ret_address_backup);
#endif

			reinterpret_cast<volatile std::uint8_t*>(bp_entry->ret_address)[0] = INT3;

			bp_entry->state = cmut<bool>(false);

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] Interrupt Instruction Succesfully Written to Return Address @%p\n"), bp_entry->ret_address);
#endif

			if (!virtualprotect_rtImp_inst(reinterpret_cast<void*>(bp_entry->ret_address), sizeof(std::uint8_t), r_perm, &r_perm))
				return EXCEPTION_CONTINUE_SEARCH;

			if (!virtualprotect_rtImp_inst((void*)cexception_address.get(), bp_entry->len, x_perm, &x_perm))
				return EXCEPTION_CONTINUE_SEARCH;

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] Callee + Caller VirtualProtect Call_3 Success\n"));
#endif

			FlushInstructionCache(GetCurrentProcess(), (void*)cexception_address.get(), bp_entry->len);

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] Instruction Cache Flushed\n [+] Decryption Routine Success, Continuing Execution...\n"));
#endif
		}
		/* Return Address Breakpoint (Re-Encrypt Actual Function), Restore first Byte of first INSN @ Return Address */
		else {

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] Breakpoint Encryption Routine Initiated at Address 0x%p\n"), (std::uintptr_t)exception_p->ExceptionRecord->ExceptionAddress);
#endif

			if (!virtualprotect_rtImp_inst(const_cast<void*>(bp_entry->abs), bp_entry->len, PAGE_EXECUTE_READWRITE, &x_perm)
				||
				!virtualprotect_rtImp_inst((void*)cexception_address.get(), sizeof(std::uint8_t), PAGE_EXECUTE_READWRITE, &r_perm))
					return cmut<LONG>(EXCEPTION_CONTINUE_SEARCH);

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] Caller + Callee VirtualProtect Call_4 Success\n"));
#endif

			qengine::qcipher_provider::cipher_encrypt(const_cast<void*>(bp_entry->abs), const_cast<void*>(bp_entry->abs), bp_entry->len);

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] Callee Encryption Success @ Address: 0x%p, FN Size: 0x%p\n"), reinterpret_cast<std::uintptr_t>(bp_entry->abs), bp_entry->len);
#endif

			reinterpret_cast<volatile std::uint8_t*>(const_cast<void*>(bp_entry->abs))[0] = cmut<std::uint8_t>(INT3).get();

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] Interrupt Instruction Succesfully Written to Callee @0x%p\n"), reinterpret_cast<std::uintptr_t>(bp_entry->abs));
#endif

			reinterpret_cast<volatile std::uint8_t*>(cexception_address.get())[0] = bp_entry->ret_address_backup;

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] Caller Return Address 0x%p Interrupt Breakpoint Restored to Byte 0x%02X\n"), reinterpret_cast<std::uintptr_t>(exception_p->ExceptionRecord->ExceptionAddress), bp_entry->ret_address_backup);
#endif

			bp_entry->state = cmut<bool>(true);

			if (!virtualprotect_rtImp_inst((void*)cexception_address.get(), bp_entry->len, x_perm, &x_perm)
				||
				!virtualprotect_rtImp_inst(reinterpret_cast<void*>(bp_entry->ret_address), sizeof(std::uint8_t), r_perm, &r_perm))
					return cmut<LONG>(EXCEPTION_CONTINUE_SEARCH);

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] Caller + Callee VirtualProtect Call_5 Success\n"));
#endif

			FlushInstructionCache(GetCurrentProcess(), (void*)cexception_address.get(), sizeof(std::uint8_t));

#ifdef ENABLE_VEH_LOGS
			printf(QSTR("[+] Instruction Cache Flushed\n [+] Encryption Routine Success, Continuing Execution...\n"));
#endif
		}

#ifdef _M_X64
		exception_p->ContextRecord->Rip = static_cast<DWORD64>(cexception_address.get());
#else
		exception_p->ContextRecord->Eip = static_cast<DWORD32>(cexception_address.get());
#endif

		return cmut<LONG>(EXCEPTION_CONTINUE_EXECUTION);
	}

#pragma endregion

#pragma region qdisasm Callback Fixup

	NO_INLINE const bool __regcall _interrupt_pdfn_callback(void* abs, const std::size_t len) noexcept {

		if (!abs || !len)
			return false;

		std::lock_guard<std::recursive_mutex> lock(g_pdfn_mtx);

		const std::uint8_t* end = reinterpret_cast<const std::uint8_t*>(abs) + len;

		DWORD x_perms = NULL;

		for (const auto& pdfn_ : bp_insn_backups) {

			if (pdfn_.abs >= abs && pdfn_.abs <= end) {

				if (!virtualprotect_rtImp_inst(const_cast<void*>(pdfn_.abs), sizeof(std::uint8_t), PAGE_EXECUTE_READWRITE, &x_perms))
					return false;

				reinterpret_cast<volatile std::uint8_t*>(const_cast<void*>(pdfn_.abs))[0] = INT3;

				if (!virtualprotect_rtImp_inst(const_cast<void*>(pdfn_.abs), sizeof(std::uint8_t), x_perms, &x_perms))
					return false;

				return true;
			}
		}

		return false;
	};

#pragma endregion

#pragma region Exception Table Data Initialization

	static inline const bool init_pe_pointers() noexcept {

		static std::once_flag flag;

		std::call_once(

			flag,

			[]() -> void {

				std::lock_guard<std::recursive_mutex> lock(g_pdfn_mtx);

				module_base_address = reinterpret_cast<std::uintptr_t>(GetModuleHandle(nullptr));

				pdos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base_address);

				pnt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(module_base_address + pdos_header->e_lfanew);

#ifdef _WIN64

				pdata_directory_entry = &pnt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

				static volatile PIMAGE_SECTION_HEADER scn = IMAGE_FIRST_SECTION(pnt_headers);

				for (std::size_t i = 0; i < pnt_headers->FileHeader.NumberOfSections; ++i, ++scn) {

					const auto sec_begin = scn->VirtualAddress;

					const auto sec_end = scn->VirtualAddress + std::max(scn->Misc.VirtualSize, scn->SizeOfRawData);

					if (pdata_directory_entry->VirtualAddress >= sec_begin && pdata_directory_entry->VirtualAddress < sec_end) {

						ppdata_scn_header = scn;

						pdata_exception_entry_ct = pdata_directory_entry->Size / sizeof(RUNTIME_FUNCTION);

						pfirst_exception_entry = reinterpret_cast<PRUNTIME_FUNCTION>(module_base_address + scn->VirtualAddress);

						break;
					}
				}

#endif

				MODULEINFO mmod_descriptor;

				if (!GetModuleInformation(

					GetCurrentProcess(),

					GetModuleHandle(nullptr),

					&mmod_descriptor,

					sizeof(MODULEINFO)
				))
					return;

				module_end_address = module_base_address + mmod_descriptor.SizeOfImage;

				if (!AddVectoredExceptionHandler(1, pdfn_veh))
					TerminateProcess(GetCurrentProcess(), 0xFFFFFFFF);

				qengine::qmorph::qdisasm::interrupt_pdfn_callback = _interrupt_pdfn_callback;
			}
		);

		return true;
	}

#pragma endregion

#pragma region Auto-Instantiation

#pragma region Windows SEH Function Encryption Auto-Instantiation

	struct auto_init_cipher_fn {

		inline auto_init_cipher_fn(void* fn) noexcept {

			if (!pdfn::module_base_address)
				pdfn::init_pe_pointers();

			insert_bp_abs(fn);
		}
	};

#define PD_FUNC_INST(__FN_NAME__) \
    inline pdfn::auto_init_cipher_fn PD_##__FN_NAME__ { &__FN_NAME__ }

#ifdef NDEBUG

#define PD_FUNC(__RET_RMOD__, __NAME__, __ARGS__)						\
    PDFN __RET_RMOD__ __NAME__ __ARGS__;								\
    PD_FUNC_INST(__NAME__);												\
    PDFN __RET_RMOD__ __NAME__ __ARGS__ { FORCE_PDFN

#else

	#define PD_FUNC(__RET_RMOD__, __NAME__, __ARGS__)					\
    PDFN __RET_RMOD__ __NAME__ __ARGS__ {

#endif

#pragma endregion

#pragma region PDFN Direct-Call Auto-Instantion / Automation Macros

#ifdef _M_X64

#ifdef NDEBUG

#define PDFN_DCALL_SECURE(__FN__)do{																						\
const auto __SIZE_FN__ = pdfn::get_function_length(__FN__);																	\
DWORD __PAGE_PERMISSIONS__ = NULL;																							\
if (virtualprotect_rtImp_inst(__FN__, __SIZE_FN__, PAGE_EXECUTE_READWRITE, &__PAGE_PERMISSIONS__)) {						\
	qengine::qcipher_provider::cipher_encrypt(__FN__, __FN__, __SIZE_FN__);													\
	virtualprotect_rtImp_inst(__FN__, __SIZE_FN__, __PAGE_PERMISSIONS__, &__PAGE_PERMISSIONS__);							\
}}while(0)

#else

#define PDFN_DCALL_SECURE(__FN__)

#endif

	struct auto_init_cipher_dcall_fn {

		inline auto_init_cipher_dcall_fn(void* fn) noexcept {

			if (!pdfn::module_base_address)
				pdfn::init_pe_pointers();

			PDFN_DCALL_SECURE(fn);
		}
	};

#define PD_DCALL_FUNC_INST(__FN_NAME__) \
    inline pdfn::auto_init_cipher_dcall_fn PD_##__FN_NAME__ { &__FN_NAME__ }

#ifdef NDEBUG

#define PDFN_DIRECT_CALL(Ret, Addr, ...)											\
    (pdfn::pdfn_direct_call<Ret>(													\
        reinterpret_cast<void*>(&(Addr)),											\
        __VA_ARGS__))

template<typename T, typename... Args>
static inline T pdfn_direct_call(void* abs, Args... args) noexcept{	

	const auto _SIZE_FN_ = pdfn::get_function_length(abs);

	DWORD _PAGE_PERMISSIONS_ = NULL;		

	if (virtualprotect_rtImp_inst(abs, _SIZE_FN_, PAGE_EXECUTE_READWRITE, &_PAGE_PERMISSIONS_)) {

		qengine::qcipher_provider::cipher_decrypt(abs, abs, _SIZE_FN_);

		virtualprotect_rtImp_inst(abs, _SIZE_FN_, _PAGE_PERMISSIONS_, &_PAGE_PERMISSIONS_);

		T rcode = reinterpret_cast<T(*)(Args...)>(abs)(args...);

		PDFN_DCALL_SECURE(abs);

		return rcode;
	}

	return T(NULL);
}

#else

#define PDFN_DIRECT_CALL(__FN__, __ARGUMENTS__) do{ __FN__ __ARGUMENTS__; } while(0)

#endif

#pragma endregion

#endif

#pragma region PE Parsing

	/*
		Compiler Auto-Compiles to Entrypoint
	*/
	struct auto_init_pe_information {

		inline auto_init_pe_information() noexcept {

			init_pe_pointers();
		}
	};

	inline const auto_init_pe_information auto_init_pointer_info;

#pragma endregion

#pragma endregion

#pragma endregion

	}

#pragma endregion

#endif