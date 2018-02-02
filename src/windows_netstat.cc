// had to put windows header files before nodes,
// otherwise electron-rebuild would fail.... :/
#include <winsock2.h>
#include <iphlpapi.h>
#include <Ws2tcpip.h>
#include <node.h>
#include <v8.h>

using namespace v8;

MIB_TCPTABLE_OWNER_PID *TestApi()
{
  MIB_TCPTABLE_OWNER_PID *pTCPInfo;
  DWORD size;
  DWORD dwResult;

  dwResult = GetExtendedTcpTable(NULL, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
  pTCPInfo = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
  dwResult = GetExtendedTcpTable(pTCPInfo, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

  if (dwResult != NO_ERROR)
  {
    printf("Couldn't get our IP table");
    return NULL;
  }

  return pTCPInfo;
}

void GetConnections(const FunctionCallbackInfo<Value> &args)
{
  Isolate *isolate = args.GetIsolate();
  Local<Array> result_list = Array::New(isolate);
  MIB_TCPTABLE_OWNER_PID *ptr = TestApi();
  MIB_TCPROW_OWNER_PID *owner;
  for (DWORD dwLoop = 0; dwLoop < ptr->dwNumEntries; dwLoop++)
  {
    char ipstr[INET6_ADDRSTRLEN];
    owner = &ptr->table[dwLoop];

    struct in_addr a;
    a.S_un.S_addr = htonl(((long)owner->dwRemoteAddr));
    inet_ntop(AF_INET, &a, (PSTR)ipstr, 20);
    Local<Object> result = Object::New(isolate);

    result->Set(String::NewFromUtf8(isolate, "pid"), Number::New(isolate, owner->dwOwningPid));
    result->Set(String::NewFromUtf8(isolate, "localPort"), Number::New(isolate, ntohs((u_short)owner->dwLocalPort)));
    result->Set(String::NewFromUtf8(isolate, "state"), Number::New(isolate, owner->dwState));
    result->Set(String::NewFromUtf8(isolate, "remoteIP"), String::NewFromUtf8(isolate, ipstr));
    result->Set(String::NewFromUtf8(isolate, "remotePort"), Number::New(isolate, ntohs((u_short)owner->dwRemotePort)));

    result_list->Set(dwLoop, result);
    //printf("  PID: %5u - Port: %5u, State: %15u, Address: %15s, Port: %5u\n", owner->dwOwningPid, ntohs(owner->dwLocalPort), owner->dwState,  ipstr, ntohs(owner->dwRemotePort));
  }
  args.GetReturnValue().Set(result_list);
}

void init(Local<Object> exports)
{
  NODE_SET_METHOD(exports, "connections", GetConnections);
}

NODE_MODULE(NODE_GYP_MODULE_NAME, init)