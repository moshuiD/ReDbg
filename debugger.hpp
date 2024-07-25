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
namespace ReDbg
{
#ifdef _WIN64
#define IP Rip
#else
#define IP Eip
#endif 

	using std::string;
	using std::thread;
	using std::exception;
	using std::unique_ptr;
	using std::function;
	using std::map;
	using std::mutex;
	using std::vector;

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
		struct BreakPoint
		{
			uintptr_t addr;
			unsigned char orgByte;
			function<void(CONTEXT)> callBack;
		};
		DWORD m_pid;
		HANDLE m_hProc;
		map<uintptr_t, BreakPoint> m_bpMap;
		mutable mutex m_bpMapMutex;
		thread m_debugLoopThread;
		bool m_stopDebugLoop = false;
		bool m_dbgInitFlag = false;
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

		inline bool AddCallback(uintptr_t addr, function<void(CONTEXT)>&& callback) {
			std::lock_guard lock(m_bpMapMutex);
			if (!m_bpMap.contains(addr)) {
				unsigned char orgByte = Read<unsigned char>(addr, 1);
				if (Write(addr, '\xCC', 1)) {
					m_bpMap.insert({ addr, { addr, orgByte, callback } });
					return true;
				}
				return false;
			}
			return false;
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
			while (!m_dbgInitFlag) {
				Sleep(1);
			}
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

		void DebugLoop() {
			DebugActiveProcess(m_pid);
			DEBUG_EVENT debugEvent{};
			while (!m_stopDebugLoop) {
				ZeroMemory(&debugEvent, sizeof(debugEvent));
				if (WaitForDebugEvent(&debugEvent, INFINITE)) {
					if (EXIT_PROCESS_DEBUG_EVENT == debugEvent.dwDebugEventCode) {
						break;
					}
					if (EXCEPTION_DEBUG_EVENT == debugEvent.dwDebugEventCode) {
						PVOID exception_addr = debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
						if (GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgBreakPoint") == exception_addr) {
							m_dbgInitFlag = true;
						}
						std::lock_guard lock(m_bpMapMutex);
						if (m_bpMap.contains(reinterpret_cast<uintptr_t>(exception_addr))) {
							HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, debugEvent.dwThreadId);
							if (0 != hThread) {
								CONTEXT context{};
								context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
								if (GetThreadContext(hThread, &context)) {
									BreakPoint bp = m_bpMap[reinterpret_cast<uintptr_t>(exception_addr)];
									bp.callBack(context);
									Write(bp.addr, bp.orgByte, 1);
									context.IP -= 1;
									SetThreadContext(hThread, &context);
								}
								CloseHandle(hThread);
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
