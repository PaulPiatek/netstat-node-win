#include "include.h"

void getProcessName(TCHAR* taskName, int taskNameSize, DWORD pid);
void getConnections(v8::Local<v8::Array>* result_list, v8::Isolate *isolate);