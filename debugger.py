from cython import *
from ctypes import *
from ctypes.wintypes import *

LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
PVOID = c_void_p
UINT_PTR = c_ulong
DWORD64 = c_ulonglong
DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010
PROCESS_ALL_ACCESS = 0x001F0FFF
INFINITE = 0xFFFFFFFF
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

EXCEPTION_DEBUG_EVENT = 0x01
CREATE_THREAD_DEBUG_EVENT = 0x02
CREATE_PROCESS_DEBUG_EVENT = 0x03
EXIT_THREAD_DEBUG_EVENT = 0x04
EXIT_PROCESS_DEBUG_EVENT = 0x05
LOAD_DLL_DEBUG_EVENT = 0x06
UNLOAD_DLL_DEBUG_EVENT = 0x07
OUTPUT_DEBUG_STRING_EVENT = 0x08
RIP_EVENT = 0x09

EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_GUARD_PAGE = 0x80000001
EXCEPTION_SINGLE_STEP = 0x80000004

TH32CS_SNAPTHREAD = 0x00000004

THREAD_ALL_ACCESS = 0x001F03FF

CONTEXT_FULL = 0x00010007
CONTEXT_DEBUG_REGISTERS = 0x00010010

HW_ACCESS = 0x00000003
HW_EXECUTE = 0x00000000
HW_WRITE = 0x00000001


class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize",        DWORD),
        ("th32ModuleID",  DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage",  DWORD),
        ("ProccntUsage",  DWORD),
        ("modBaseAddr",   PVOID),
        ("modBaseSize",   DWORD),
        ("hModule",       PVOID),
        ("szModule",      CHAR * 256),
        ("szExePath",     CHAR * 260),
    ]


class STARTUPINFO(Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPTSTR),
        ("lpDesktop", LPTSTR),
        ("lpTitle", LPTSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPTSTR),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]


class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]


class EXCEPTION_RECORD32(Structure):
    pass


EXCEPTION_RECORD32._fields_ = [
    ("ExceptionCode", DWORD),
    ("ExceptionFlags", DWORD),
    ("ExceptionRecord", POINTER(EXCEPTION_RECORD32)),
    ("ExceptionAddress", PVOID),
    ("NumberParameters", DWORD),
    ("ExceptionInformation", UINT_PTR*15),
]


class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD32),
        ("dwFirstChance", DWORD),
    ]


class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        # ("CreateThread", CREATE_THREAD_DEBUG_INFO),
    ]


class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", DEBUG_EVENT_UNION),
    ]


class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ThreadID", DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri", DWORD),
        ("tpDeltaPri", DWORD),
        ("dwFlags", DWORD)
    ]


class FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
    ]


class CONTEXT(Structure):
    _fields_ = [
        ('P1Home', DWORD64),
        ('P2Home', DWORD64),
        ('P3Home', DWORD64),
        ('P4Home', DWORD64),
        ('P5Home', DWORD64),
        ('P6Home', DWORD64),

        ('ContextFlags', DWORD),
        ('MxCsr', DWORD),

        ('SegCs',WORD),   
        ('SegDs',WORD), 
        ('SegEs',WORD), 
        ('SegFs',WORD), 
        ('SegGs',WORD), 
        ('SegSs',WORD), 
        ('EFlags',DWORD), 

        ('Dr0', DWORD64),
        ('Dr1', DWORD64),
        ('Dr2', DWORD64),
        ('Dr3', DWORD64),
        ('Dr6', DWORD64),
        ('Dr7', DWORD64),

        ('Eax', DWORD64),
        ('Ecx', DWORD64),
        ('Edx', DWORD64),
        ('Ebx', DWORD64),
        ('Esp', DWORD64),
        ('Ebp', DWORD64),
        ('Esi', DWORD64),
        ('Edi', DWORD64),
        ('R8', DWORD64),
        ('R9', DWORD64),
        ('R10', DWORD64),
        ('R11', DWORD64),
        ('R12', DWORD64),
        ('R13', DWORD64),
        ('R14', DWORD64),
        ('R15', DWORD64),
        ('Eip', DWORD64),
    ]


class PROC_STRUCT(Structure):
    _fields_ = [
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
    ]


class SYSTEM_INFO_UNION(Union):
    _fields_ = [
        ("dsOemId", DWORD),
        ("sProcStruc", PROC_STRUCT),
    ]


class SYSTEM_INFO(Structure):
    _fields_ = [
        ("uSysInfo", SYSTEM_INFO_UNION),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessMask", DWORD),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
    ]


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [('BaseAddress', c_void_p),
                ('AllocationBase', c_void_p),
                ('AllocationProtect', DWORD),
                ('RegionSize', c_size_t),
                ('State', DWORD),
                ('Protect', DWORD),
                ('Type', DWORD)]


class MEMORY_BASIC_INFORMATION64(Structure):
    _fields_ = [('BaseAddress', c_ulonglong),
                ('AllocationBase', c_ulonglong),
                ('AllocationProtect', DWORD),
                ('alignement1', DWORD),
                ('RegionSize', c_ulonglong),
                ('State', DWORD),
                ('Protect', DWORD),
                ('Type', DWORD),
                ('alignement2', DWORD)]


class SYSTEM_INFO(Structure):
    _fields_ = [('wProcessorArchitecture', WORD),
                ('wReserved', WORD),
                ('dwPageSize', DWORD),
                ('lpMinimumApplicationAddress', LPVOID),
                ('lpMaximumApplicationAddress', LPVOID),
                ('dwActiveProcessorMask', c_ulonglong),
                ('dwNumberOfProcessors', DWORD),
                ('dwProcessorType', DWORD),
                ('dwAllocationGranularity', DWORD),
                ('wProcessorLevel', WORD),
                ('wProcessorRevision', WORD)]


PAGE_EXECUTE_READWRITE = 64
PAGE_EXECUTE_READ = 32
PAGE_READONLY = 2
PAGE_READWRITE = 4
PAGE_NOCACHE = 512
PAGE_WRITECOMBINE = 1024
PAGE_GUARD = 256

MEM_COMMIT = 4096
MEM_FREE = 65536
MEM_RESERVE = 8192
PROCESS_ALL_ACCESS = 0x001F0FFF


class WinApi:

    def __init__(self) -> None:
        self.CreateToolhelp32Snapshot = CDLL(
            "kernel32.dll").CreateToolhelp32Snapshot
        self.Process32First = CDLL("kernel32.dll").Process32First
        self.Process32Next = CDLL("kernel32.dll").Process32Next
        self.GetLastError = CDLL("kernel32.dll").GetLastError
        self.CloseHandle = CDLL("kernel32.dll").CloseHandle
        self.OpenProcess = CDLL("kernel32.dll").OpenProcess
        self.ReadProcessMemory = CDLL("kernel32.dll").ReadProcessMemory
        self.WriteProcessMemory = CDLL("kernel32.dll").WriteProcessMemory
        self.VirtualProtectEx = CDLL("kernel32.dll").VirtualProtectEx
        self.DebugActiveProcess = CDLL("kernel32.dll").DebugActiveProcess
        self.WaitForDebugEvent = CDLL("kernel32.dll").WaitForDebugEvent
        self.OpenThread = CDLL("kernel32.dll").OpenThread
        self.GetThreadContext = CDLL("kernel32.dll").GetThreadContext
        self.ContinueDebugEvent = CDLL("kernel32.dll").ContinueDebugEvent
        self.GetLastError = CDLL("kernel32.dll").GetLastError
        self.SetThreadContext = CDLL("kernel32.dll").SetThreadContext
        self.Module32First = CDLL("kernel32.dll").Module32First
        self.Module32Next = CDLL("kernel32.dll").Module32Next

api = WinApi()


class Log:
    def warning(self, msg):
        print(f"\033[33m[w] : {msg}\033[0m")

    def error(self, msg):
        print(f"\033[31m[x] : {msg}\033[0m")

    def success(self, msg):
        print(f"\033[32m[+] : {msg}\033[0m")

    def info(self, msg):
        print(f"\033[37m[i] : {msg}\033[0m")


class BreakPoint:
    address = None
    original_byte = None
    handler = None

    def __init__(self, addr, org_byte, handler):
        self.address = addr
        self.original_byte = org_byte
        self.handler = handler


log = Log()


class ReDbg:
    _pid: DWORD = None
    _hproc = None
    _debug = None
    _handlers = dict()

    def _get_pid_by_name(self, name):
        class PROCESSENTRY32(Structure):
            _fields_ = [('dwSize', DWORD),
                        ('cntUsage', DWORD),
                        ('th32ProcessID', DWORD),
                        ('th32DefaultHeapID', POINTER(ULONG)),
                        ('th32ModuleID', DWORD),
                        ('cntThreads', DWORD),
                        ('th32ParentProcessID', DWORD),
                        ('pcPriClassBase', LONG),
                        ('dwFlags', DWORD),
                        ('szExeFile', c_char * 260)]

        snapshot = HANDLE(api.CreateToolhelp32Snapshot(
            DWORD(0x00000002), DWORD(0)))
        process = PROCESSENTRY32()
        process.cntUsage = 0
        process.th32ProcessID = 0
        process.th32ModuleID = 0
        process.cntThreads = 0
        process.th32ParentProcessID = 0
        process.pcPriClassBase = 0
        process.dwFlags = 0
        process.szExeFile = b""
        process.dwSize = sizeof(PROCESSENTRY32)

        i = 0
        pid = -1
        while 1:
            if (i == 0):
                last = not api.Process32First(snapshot, byref(process))
            else:
                last = not api.Process32Next(snapshot, byref(process))
            procname = process.szExeFile
            if procname.decode("utf-8").lower() == name.lower():
                pid = process.th32ProcessID
                break

            if (last):
                break
            i += 1
        api.CloseHandle(snapshot)
        if (pid > -1):
            return pid
        return None

    def __init__(self, pid=None, name=None, debug=False) -> None:
        self._debug = debug
        if (pid != None):
            self._pid = pid
        elif (name != None):
            self._pid = self._get_pid_by_name(name)

        if (self._pid != None):
            if (self._debug):
                log.success(f"Get pid is {self._pid}")
        else:
            raise Exception("Can't get pid")

        self._hproc = self._open_process(self._pid)
        self._attach()

    def add_handler(self, addr, handler):
        org_byte = self._read_process_memory(addr, 1)
        res = self._write_process_memory(addr, b"\xCC")
        if res:
            bp = BreakPoint(addr, org_byte, handler)
            self._handlers[addr] = bp
            if (self._debug):
                log.success(f"Set break point success at {hex(addr)}")

        else:
            raise Exception(
                f"Can't set break point at {hex(addr)}. Error code {hex(api.GetLastError())}")

    def debug(self):
        while self._get_debug_event():
            pass
        if (self._debug):
                log.success("Debugger terminated")

    def _open_process(self, pid):
        hproc = api.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if (hproc != 0):
            if (self._debug):
                log.success(f"Get hproc {hproc}")
            return hproc
        else:
            raise Exception("Can't get hproc")

    def _attach(self):
        if (api.DebugActiveProcess(self._pid)):
            if (self._debug):
                log.success("Attach success")
        else:
            Exception("Can't attach to the process")

    def _open_thread(self, thread_id):
        h_thread = api.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        if (h_thread is not None):
            return h_thread
        else:
            log.error("Can't OpenThread")
            return False

    def _get_thread_context(self, h_thread) -> CONTEXT:
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        if (h_thread is not False):
            if (not api.GetThreadContext(h_thread, byref(context))):
                log.error("Get thread context fail.")

        return context

    def _get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE
        if (api.WaitForDebugEvent(byref(debug_event), INFINITE)):
            if (self._debug):
                log.success("Event code: %d Thread ID: %d" % (
                    debug_event.dwDebugEventCode, debug_event.dwThreadId))
            if (debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT):
                return False
            if (debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT):
                #exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                bp: BreakPoint = self._handlers.get(
                    exception_address, None)
                if (bp is not None):
                    h_thread = self._open_thread(debug_event.dwThreadId)
                    context = self._get_thread_context(h_thread)

                    if (bp.handler is not None):
                        bp.handler(context)
                        self._write_process_memory(
                            bp.address, bp.original_byte)
                        context.Eip = context.Eip - 1
                        if (not api.SetThreadContext(h_thread, byref(context))):
                            raise Exception("SetThreadContext Error!")
                    else:
                        log.warning(
                            f"This breakpoint does not have a handler.Address : {hex(exception_address)}")
                    api.CloseHandle(h_thread)
            api.ContinueDebugEvent(
                debug_event.dwProcessId, debug_event.dwThreadId, continue_status)
            return True

    def get_module_addr(self, name: bytes):
        current_entry = MODULEENTRY32()
        snapshot = api.CreateToolhelp32Snapshot(
            DWORD(0x00000008), DWORD(self._pid))

        if snapshot == 0xFFFFFFFF:
            log.error("Can't create snap shot in function 'get_module_addr'")

        current_entry.dwSize = sizeof(current_entry)

        if not api.Module32First(snapshot, byref(current_entry)):
            return -1

        while True:
            if (current_entry.szModule == name):
                api.CloseHandle(snapshot)
                return current_entry.modBaseAddr

            if not api.Module32Next(snapshot, byref(current_entry)):
                break
        api.CloseHandle(snapshot)

    def _read_process_memory(self, address, length):
        data = b""
        read_buf = create_string_buffer(length)
        count = c_ulong(0)
        if not api.ReadProcessMemory(self._hproc, address, read_buf, length, byref(count)):
            log.error("ReadProcessMemory fail")
            return False
        else:
            data += read_buf.raw
            return data

    def _write_process_memory(self, address, data):
        count = c_ulong(0)
        length = len(data)
        c_data = c_char_p((data[count.value:]))
        if not api.WriteProcessMemory(self._hproc, address, c_data, length, byref(count)):
            return False
        else:
            return True


if __name__ == "__main__":
    r = ReDbg(name="quite_easy.exe", debug=True)

    def handler(context: CONTEXT):
        print(r._read_process_memory(context.Eax, 5))
        print(f"Eax:{context.Eax}")

    baseaddr = r.get_module_addr(b"quite_easy.exe")
    r.add_handler(baseaddr + 0xAD39, handler)
    r.debug()
