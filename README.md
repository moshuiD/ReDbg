# ReDbg
an easy debugger for CTF  
[Blog](https://www.moshui.eu.org/2024/07/25/ReDbg/)
# Function
**Can easily achieve automated debugging of Windows programs**  

**We provide two interfaces: C++ and Python**
## C++ *(Stable and efficient)*
We provide two classes, one for controlling processes and the other for debugging  

Developed using Visual Studio.Using **C++17** standard and **multi byte character** set and using define to switch registers between x64 and x32 (Eip/Rip)  

They can easily debug x64 and x32 programs   

Here is a simple example:  
```cpp
#include "debugger.hpp"
int main() {
	auto p = ReDbg::Process("xxxxxx.exe");
	printf("%s\n", p.ReadLine().c_str());
	auto dbg = ReDbg::Dbg("xxxxxx.exe");
	dbg.AddCallback(dbg.GetModuleAddr("xxxxxx.exe") + 0xAD39, [&](CONTEXT c)->void {
		auto a = dbg.Read<std::string>(c.Rax, 5);
		printf("%s\n", a.c_str());
	});
	auto a = p.WriteLine("12345");
	printf("%s\n", p.ReadLine().c_str());
    //We used multithreading to prevent the debugging loop from being terminated.
    //so the following code only blocks the main thread to prevent the program from ending
	while (true) {
		Sleep(1);
	}
}
```
## Python *(Generally stable)*
We provide a **ReDbg** class to accomplish debugging functionality.    

We can use **Python3 (x64)** to debug **Win (x86) exe**  

You can use Python's **subprocess** module to create processes and communicate with them.  

Here is a simple example:  
```Python
import subprocess
import threading
import time
from debugger import ReDbg
if __name__ == "__main__":
    pr = subprocess.Popen("xxxxxx.exe", stdin=subprocess.PIPE, stdout=subprocess.PIPE,shell=True)
    # The stupid way to wait for the process to be created...
    time.sleep(0.1)

    r = ReDbg(name="xxxxxx.exe", debug=True)

    def handler(context: CONTEXT):
        print(r._read_process_memory(context.Eax, 5))
        print(f"Eax:{context.Eax}")

    baseaddr = r.get_module_addr(b"xxxxxx.exe")
    r.add_handler(baseaddr + 0xAD39, handler)
    # The Debug function here is a debug loop. We need multithreading to prevent it from blocking the main thread
    threading.Thread(target=r.debug).start()

    outs, errs = pr.communicate(input=b"12345")
```
