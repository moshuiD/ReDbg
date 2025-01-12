#include <Windows.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <thread>
#include <string>
#include <exception>
#include <memory>
#include <functional>
#include <map>
#include <mutex>
#include <vector>
#include <algorithm>
#include <semaphore>
#include <variant>
#include "Zydis.h"

#ifdef _MSVC_LANG
static_assert(_MSVC_LANG >= 202002L, "C++20 Compiler Required");
#endif

namespace ReDbg
{
#ifdef _WIN64
#define IP Rip
#define DISASM_FLAG ZYDIS_MACHINE_MODE_LONG_64
#else
#define IP Eip
#define DISASM_FLAG ZYDIS_MACHINE_MODE_LONG_COMPAT_32
#endif 

	using std::string;
	using std::thread;
	using std::exception;
	using std::unique_ptr;
	using std::function;
	using std::map;
	using std::mutex;
	using std::vector;
	using std::binary_semaphore;
	using std::variant;

	class Process
	{
		string m_cmd;
		STARTUPINFOA m_si;
		PROCESS_INFORMATION m_pi;
		SECURITY_ATTRIBUTES m_sa;
		HANDLE m_hProc_StdIn_R = NULL;
		HANDLE m_hProc_StdIn_W = NULL;
		HANDLE m_hProc_StdOut_R = NULL;
		HANDLE m_hProc_StdOut_W = NULL;

	public:
		Process(string&& cmd) :
			m_cmd(cmd)
		{
			m_sa.nLength = sizeof(SECURITY_ATTRIBUTES);
			m_sa.bInheritHandle = TRUE;
			m_sa.lpSecurityDescriptor = NULL;

			if (!CreatePipe(&m_hProc_StdIn_R, &m_hProc_StdIn_W, &m_sa, 0))
				throw exception("Can't create stdin pipe");

			if (!SetHandleInformation(m_hProc_StdIn_W, HANDLE_FLAG_INHERIT, 0))
				throw exception("Can't create stdin pipe");

			if (!CreatePipe(&m_hProc_StdOut_R, &m_hProc_StdOut_W, &m_sa, 0))
				throw exception("Can't create stdout pipe");

			if (!SetHandleInformation(m_hProc_StdOut_R, HANDLE_FLAG_INHERIT, 0))
				throw exception("Can't create stdout pipe");


			ZeroMemory(&m_si, sizeof(STARTUPINFOA));
			m_si.cb = sizeof(STARTUPINFOA);
			m_si.hStdError = m_hProc_StdOut_W;
			m_si.hStdOutput = m_hProc_StdOut_W;
			m_si.hStdInput = m_hProc_StdIn_R;
			m_si.dwFlags |= STARTF_USESTDHANDLES;

			if (!CreateProcessA(NULL,
				const_cast<char*>(m_cmd.c_str()),
				NULL,
				NULL,
				TRUE,
				0,
				NULL,
				NULL,
				&m_si,
				&m_pi))
			{
				throw exception("Can't create process");
			}

			CloseHandle(m_hProc_StdOut_W);
		}

		inline string ReadLine(size_t length = 4096) {
			DWORD readCount = 0;
			unique_ptr<char[]> buf = std::make_unique<char[]>(length);
			if (ReadFile(m_hProc_StdOut_R, buf.get(), length, &readCount, NULL))
				return string(buf.get());
			else
				throw exception("Read file error");
		}

		inline bool WriteLine(string&& input) {
			DWORD writeCount = 0;
			size_t len = input.length() + 1;
			unique_ptr <char[]> buf = std::make_unique<char[]>(len);
			memcpy(buf.get(), input.c_str(), input.length());
			buf.get()[len - 1] = '\n';
			return WriteFile(m_hProc_StdIn_W, const_cast<char*>(buf.get()), len, &writeCount, NULL);
		}

		~Process() {
			CloseHandle(m_hProc_StdIn_R);
			CloseHandle(m_hProc_StdIn_W);
			CloseHandle(m_hProc_StdOut_R);
			CloseHandle(m_pi.hProcess);
			CloseHandle(m_pi.hThread);
		}
		inline DWORD GetPid() const {
			return m_pi.dwProcessId;
		}
	};

	class Dbg
	{
		using BreakPointCallBack = function<void(CONTEXT)>;

		//if return false means exit trace mode.
		using TraceCallBack = function<bool(ZydisDisassembledInstruction)>;

		struct BreakPoint
		{
			uintptr_t addr;
			unsigned char orgByte;
			enum { NormalBreakPoint, TracePoint } type;
			variant<BreakPointCallBack, TraceCallBack> callback;
		};

		enum class DbgStatus
		{
			Normal,
			Trace
		};

		DWORD m_pid;
		HANDLE m_hProc;
		map<uintptr_t, BreakPoint> m_bpMap;
		mutable mutex m_bpMapMutex;
		thread m_debugLoopThread;
		bool m_stopDebugLoop = false;
		binary_semaphore m_dbgInitFlag{ 0 };

	public:
		Dbg(string&& name) {
			m_pid = GetPidByName(name);
			if (!InitDbg()) {
				throw exception("Can't init dbg");
			}
		}

		Dbg(DWORD pid) :
			m_pid(pid)
		{
			if (!InitDbg()) {
				throw exception("Can't init dbg");
			}
		}

		~Dbg() {
			m_stopDebugLoop = true;
			m_debugLoopThread.join();
			DebugActiveProcessStop(m_pid);
			CloseHandle(m_hProc);
		};

		inline bool AddBpCallback(uintptr_t addr, BreakPointCallBack&& callback) {
			std::lock_guard lock(m_bpMapMutex);
			return AddCallback(addr, { addr, 00, BreakPoint::NormalBreakPoint, callback });
		}

		inline bool AddTrace(uintptr_t addr, TraceCallBack&& callback) {
			std::lock_guard lock(m_bpMapMutex);
			return AddCallback(addr, { addr, 00, BreakPoint::TracePoint, callback });
		}

		template<class T>
		inline T Read(uintptr_t addr, size_t length = sizeof(T)) {
			unique_ptr<T> buf = std::make_unique<T>(length);
			SIZE_T readCount = 0;
			ReadProcessMemory(m_hProc, reinterpret_cast<LPCVOID>(addr), buf.get(), length, &readCount);
			return *(buf);
		}

		template<class T>
		inline vector<T> ReadArray(uintptr_t addr, size_t length) {
			unique_ptr<T[]> buf = std::make_unique<T[]>(length + 1);
			SIZE_T readCount = 0;
			if (ReadProcessMemory(m_hProc, reinterpret_cast<LPCVOID>(addr), buf.get(), length, &readCount)) {
				vector<T> vec{};
				vec.reserve(readCount / sizeof(T));
				for (size_t i = 0; i < readCount / sizeof(T); i++) {
					vec.push_back(buf[i]);
				}
				return vec;
			}
		}

		template<class T>
		inline bool Write(uintptr_t addr, T buf, size_t length = sizeof(T)) {
			SIZE_T writeCount = 0;
			return WriteProcessMemory(m_hProc, reinterpret_cast<LPVOID>(addr), &buf, length, &writeCount);
		}

		template<class T>
		inline bool WriteArray(uintptr_t addr, T buf, size_t length) {
			SIZE_T writeCount = 0;
			return WriteProcessMemory(m_hProc, reinterpret_cast<LPVOID>(addr), buf, length, &writeCount);
		}

		inline uintptr_t GetModuleAddr(string&& name) {

			uintptr_t moduleBaseAddr = 0;

			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
			if (INVALID_HANDLE_VALUE == snapshot) {
				return 0;
			}
			MODULEENTRY32 me32;
			me32.dwSize = sizeof(MODULEENTRY32);
			if (!Module32First(snapshot, &me32)) {
				CloseHandle(snapshot);
				return 0;
			}

			while (true) {
				if (strcmp(me32.szModule, name.c_str()) == 0) {
					moduleBaseAddr = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
					break;
				}

				if (!Module32Next(snapshot, &me32)) {
					break;
				}
			}

			CloseHandle(snapshot);
			return moduleBaseAddr;
		}

	private:
		bool InitDbg() {
			HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, m_pid);
			if (0 == hProc)
				return false;
			m_hProc = hProc;
			m_debugLoopThread = thread(&Dbg::DebugLoop, this);
			m_dbgInitFlag.acquire();
			return true;
		}

		inline DWORD GetPidByName(string name) {
			HANDLE snapshot;
			PROCESSENTRY32 pe32{};
			BOOL status;
			DWORD pid = 0;

			snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (INVALID_HANDLE_VALUE == snapshot) {
				return 0;
			}

			pe32.dwSize = sizeof(PROCESSENTRY32);
			status = Process32First(snapshot, &pe32);
			while (status) {
				if (strcmp(pe32.szExeFile, name.c_str()) == 0) {
					pid = pe32.th32ProcessID;
					break;
				}
				status = Process32Next(snapshot, &pe32);
			}

			CloseHandle(snapshot);
			return pid;
		}

		inline bool AddCallback(uintptr_t addr, BreakPoint&& dbgPt) {
			if (!m_bpMap.contains(addr)) {
				unsigned char orgByte = Read<unsigned char>(addr, 1);
				dbgPt.orgByte = orgByte;
				if (Write(addr, '\xCC', 1)) {
					m_bpMap[addr] = dbgPt;
					return true;
				}
				return false;
			}
			return false;
		}

		inline void HandleNormalBp(CONTEXT& context, const BreakPoint& bp) {
			std::get<BreakPointCallBack>(bp.callback)(context);
			Write(bp.addr, bp.orgByte, 1);
			context.IP -= 1;
			context.EFlags |= 0x100;
		}

		//if return false means exit trace mode.
		inline bool NotifyTrace(const uintptr_t addr,const vector<ZyanU8>& opcode, const BreakPoint& bp) {
			ZydisDisassembledInstruction instruct{};
			ZydisDisassembleIntel(
				DISASM_FLAG,
				addr,
				opcode.data(),
				0x10,
				&instruct
			);
			return std::get<TraceCallBack>(bp.callback)(instruct);
		}

		inline void HandleFirstTrace(CONTEXT& context, const BreakPoint& bp) {
			Write(bp.addr, bp.orgByte, 1);
			auto buff = ReadArray<ZyanU8>(context.IP - 1, 0x10);
			NotifyTrace(context.IP - 1, buff, bp);
			context.IP -= 1;
			context.EFlags |= 0x100;
		}

		inline void HandleTrace(uintptr_t addr, DWORD tid, DbgStatus& dbgStatus, const BreakPoint& bp) {
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, tid);
			if (0 != hThread) {
				CONTEXT context{};
				context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
				if (GetThreadContext(hThread, &context)) {
					auto buff = ReadArray<ZyanU8>(addr, 0x10);
					if (!NotifyTrace(addr, buff, bp)) {
						dbgStatus = DbgStatus::Normal;
					}
					else {
						context.EFlags |= 0x100;
					}
				}
				SetThreadContext(hThread, &context);
			}
			CloseHandle(hThread);
		}

		inline void RecoverBp(uintptr_t addr) {
			Write(addr, '\xCC', 1);
		}

		inline void HandleBreakPointException(uintptr_t addr, DWORD tid,uintptr_t& lastBpAddr, DbgStatus& dbgStatus) {
			if (!m_bpMap.contains(addr)) {
				return;
			}
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, tid);
			if (INVALID_HANDLE_VALUE != hThread) {
				CONTEXT context{};
				context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
				if (GetThreadContext(hThread, &context)) {
					BreakPoint bp = m_bpMap[addr];
					switch (bp.type)
					{
					case BreakPoint::NormalBreakPoint:
						dbgStatus = DbgStatus::Normal;
						HandleNormalBp(context, bp);
						lastBpAddr = addr;
						break;

					case BreakPoint::TracePoint:
						dbgStatus = DbgStatus::Trace;
						HandleFirstTrace(context, bp);
						break;

					}
					SetThreadContext(hThread, &context);
				}
				CloseHandle(hThread);
			}
		}

		void DebugLoop() {
			DebugActiveProcess(m_pid);

			DEBUG_EVENT debugEvent{};
			uintptr_t lastBpAddr = 0;
			DbgStatus dbgStatus = DbgStatus::Normal;
			BreakPoint* pTraceBp = nullptr;
			while (!m_stopDebugLoop) {
				ZeroMemory(&debugEvent, sizeof(debugEvent));
				if (WaitForDebugEvent(&debugEvent, INFINITE)) {
					if (EXIT_PROCESS_DEBUG_EVENT == debugEvent.dwDebugEventCode) {
						break;
					}

					if (EXCEPTION_DEBUG_EVENT == debugEvent.dwDebugEventCode) {
						uintptr_t exceptionAddr = reinterpret_cast<uintptr_t>(debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
						if (reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgBreakPoint"))
							== exceptionAddr) {
							m_dbgInitFlag.release();
						}


						std::lock_guard lock(m_bpMapMutex);

						if (EXCEPTION_SINGLE_STEP == debugEvent.u.Exception.ExceptionRecord.ExceptionCode) {
							if (dbgStatus == DbgStatus::Normal &&
								lastBpAddr &&
								m_bpMap.contains(lastBpAddr) &&
								m_bpMap[lastBpAddr].type == BreakPoint::NormalBreakPoint)
							{
								RecoverBp(lastBpAddr);
								lastBpAddr = 0;
							}

							if (dbgStatus == DbgStatus::Trace) {
								HandleTrace(exceptionAddr, debugEvent.dwThreadId, dbgStatus,*pTraceBp);
							}
						}

						if (EXCEPTION_BREAKPOINT == debugEvent.u.Exception.ExceptionRecord.ExceptionCode) {
							HandleBreakPointException(exceptionAddr, debugEvent.dwThreadId, lastBpAddr,dbgStatus);
							if (dbgStatus == DbgStatus::Trace) {
								pTraceBp = &m_bpMap[exceptionAddr];
							}
						}

					}
					ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
					continue;
				}
				DebugActiveProcessStop(m_pid);
				return;
			}
		}
	};
}
