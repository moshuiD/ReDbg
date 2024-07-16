from cython import *
from ctypes import *
from ctypes.wintypes import *

LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
PVOID = c_void_p
UINT_PTR = c_ulong

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
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
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
