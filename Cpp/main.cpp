#include "debugger.hpp"
#include "Zydis.h"
#include <stdio.h>
int main() {
	auto dbg = ReDbg::Dbg(31676);
	char last_cmd[90] = "";
	char last_cmd_2[90] = "";
	dbg.AddTrace(0x41F07F, [&](ZydisDisassembledInstruction asminfo)->bool {
		if (asminfo.runtime_address == 0x041F082) {
			return false;
		}

		if ((strcmp(last_cmd, "popad") == 0 && strcmp(asminfo.text, "pushad") != 0)
			|| (strcmp(last_cmd_2, "pushfd") == 0 && strcmp(asminfo.text, "pop eax") != 0)) {
			printf("%p   ", asminfo.runtime_address);
			for (size_t i = 0; i < strlen(asminfo.text); i++)
			{
				printf("%c", asminfo.text[i]);
			}
			printf("\n");
		}
		strcpy_s(last_cmd_2, last_cmd);
		strcpy_s(last_cmd, asminfo.text);
		return true;
		});
	while (1)
	{
		Sleep(1);
	}
}