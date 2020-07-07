#include "include.h"

using namespace v8;

char *HumanReadableState(int state)
{
    switch (state)
    {
    case MIB_TCP_STATE_CLOSED:
        return "CLOSED";
    case MIB_TCP_STATE_LISTEN:
        return "LISTEN";
    case MIB_TCP_STATE_ESTAB:
        return "ESTABLISHED";
    case MIB_TCP_STATE_SYN_SENT:
        return "SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD:
        return "SYN_RCVD";
    case MIB_TCP_STATE_FIN_WAIT1:
        return "FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2:
        return "FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT:
        return "CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING:
        return "CLOSING";
    case MIB_TCP_STATE_LAST_ACK:
        return "LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT:
        return "TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB:
        return "DELETE_TCB";
    default:
        return "UNKNOWN";
    }
}

void fillProcessMap(std::map<DWORD, TCHAR *> *processMap)
{
    // tried CreateToolhelp32Snapshot( TH32CS_SNAPALL, pid ) and OpenProcess(READ_CONTROL | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid);
    // but both methods did not return all modules (e.g. svchost.exe), therefore the use of CreateToolhelp32Snapshot

    HANDLE snapshot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 me32;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    me32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &me32))
    {
        CloseHandle(snapshot);
    }
    do
    {
        (*processMap).emplace(me32.th32ProcessID, new char[MAX_PATH]);
        strncpy((*processMap)[me32.th32ProcessID], me32.szExeFile, MAX_PATH);

    } while (Process32Next(snapshot, &me32));
}

MIB_TCPTABLE_OWNER_PID *GetTCP()
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

MIB_UDPTABLE_OWNER_PID *GetUDP()
{
    MIB_UDPTABLE_OWNER_PID *pUDPInfo;
    DWORD size;
    DWORD dwResult;

    dwResult = GetExtendedUdpTable(NULL, &size, false, AF_INET, UDP_TABLE_OWNER_PID, 0);
    pUDPInfo = (MIB_UDPTABLE_OWNER_PID *)malloc(size);
    dwResult = GetExtendedUdpTable(pUDPInfo, &size, false, AF_INET, UDP_TABLE_OWNER_PID, 0);

    if (dwResult != NO_ERROR)
    {
        printf("Couldn't get our IP table");
        return NULL;
    }

    return pUDPInfo;
}

void DWORDToString(char *ipString, DWORD address)
{
    struct in_addr a;
    a.S_un.S_addr = address;
    inet_ntop(AF_INET, &a, ipString, 20);
}

void getConnections(Local<Array> *result_list, Isolate *isolate)
{
    auto context = isolate->GetCurrentContext();
    std::map<DWORD, TCHAR *> processMap;
    fillProcessMap(&processMap);

    MIB_TCPTABLE_OWNER_PID *ptr = GetTCP();
    MIB_TCPROW_OWNER_PID *owner;
    int counter = 0;
    for (DWORD dwLoop = 0; dwLoop < ptr->dwNumEntries; dwLoop++)
    {
        owner = &ptr->table[dwLoop];
        char localIpstr[INET6_ADDRSTRLEN];
        char remoteIpstr[INET6_ADDRSTRLEN];

        DWORDToString(localIpstr, owner->dwLocalAddr);
        DWORDToString(remoteIpstr, owner->dwRemoteAddr);

        Local<Object> result = Object::New(isolate);
        result->Set(context, String::NewFromUtf8(isolate, "pid").ToLocalChecked(), Number::New(isolate, owner->dwOwningPid));
        result->Set(context, String::NewFromUtf8(isolate, "taskName").ToLocalChecked(), String::NewFromUtf8(isolate, processMap[owner->dwOwningPid]).ToLocalChecked());
        result->Set(context, String::NewFromUtf8(isolate, "localIP").ToLocalChecked(), String::NewFromUtf8(isolate, localIpstr).ToLocalChecked());
        result->Set(context, String::NewFromUtf8(isolate, "localPort").ToLocalChecked(), Number::New(isolate, ntohs((u_short)owner->dwLocalPort)));
        result->Set(context, String::NewFromUtf8(isolate, "state").ToLocalChecked(), String::NewFromUtf8(isolate, HumanReadableState(owner->dwState)).ToLocalChecked());
        result->Set(context, String::NewFromUtf8(isolate, "remoteIP").ToLocalChecked(), String::NewFromUtf8(isolate, remoteIpstr).ToLocalChecked());
        result->Set(context, String::NewFromUtf8(isolate, "remotePort").ToLocalChecked(), Number::New(isolate, ntohs((u_short)owner->dwRemotePort)));
        result->Set(context, String::NewFromUtf8(isolate, "protocol").ToLocalChecked(), String::NewFromUtf8(isolate, "TCP").ToLocalChecked());

        (*result_list)->Set(context, counter, result);
        counter++;
    }

    MIB_UDPTABLE_OWNER_PID *ptrUdp = GetUDP();
    MIB_UDPROW_OWNER_PID *ownerUdp;
    for (DWORD dwLoop = 0; dwLoop < ptrUdp->dwNumEntries; dwLoop++)
    {
        ownerUdp = &ptrUdp->table[dwLoop];
        char localIpstr[INET6_ADDRSTRLEN];

        DWORDToString(localIpstr, ownerUdp->dwLocalAddr);

        Local<Object> result = Object::New(isolate);
        result->Set(context, String::NewFromUtf8(isolate, "pid").ToLocalChecked(), Number::New(isolate, ownerUdp->dwOwningPid));
        result->Set(context, String::NewFromUtf8(isolate, "taskName").ToLocalChecked(), String::NewFromUtf8(isolate, processMap[owner->dwOwningPid]).ToLocalChecked());
        result->Set(context, String::NewFromUtf8(isolate, "localIP").ToLocalChecked(), String::NewFromUtf8(isolate, localIpstr).ToLocalChecked());
        result->Set(context, String::NewFromUtf8(isolate, "localPort").ToLocalChecked(), Number::New(isolate, ntohs((u_short)ownerUdp->dwLocalPort)));
        result->Set(context, String::NewFromUtf8(isolate, "state").ToLocalChecked(), String::NewFromUtf8(isolate, "*").ToLocalChecked());
        result->Set(context, String::NewFromUtf8(isolate, "remoteIP").ToLocalChecked(), String::NewFromUtf8(isolate, "*").ToLocalChecked());
        result->Set(context, String::NewFromUtf8(isolate, "remotePort").ToLocalChecked(), String::NewFromUtf8(isolate, "*").ToLocalChecked());
        result->Set(context, String::NewFromUtf8(isolate, "protocol").ToLocalChecked(), String::NewFromUtf8(isolate, "UDP").ToLocalChecked());

        (*result_list)->Set(context, counter, result);
        counter++;
    }
    processMap.clear();
}