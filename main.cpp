#include <windows.h>
#include <setupapi.h>
#include <stdio.h>
#include <tchar.h>

#define VENDOR_FTDI 0x403
#define VENDOR_ARDUINO 0x2341
#define MAX_NAME_PORTS 7
#define RegDisposition_OpenExisting (0x00000001)
#define CM_REGISTRY_HARDWARE        (0x00000000)

typedef DWORD WINAPI (* CM_Open_DevNode_Key)(DWORD, DWORD, DWORD, DWORD, ::PHKEY, DWORD);

HANDLE BeginEnumeratePorts(VOID) {
    BOOL guidTest = FALSE;
    DWORD RequiredSize = 0;
    HDEVINFO DeviceInfoSet;
    char* buf;

    guidTest = SetupDiClassGuidsFromNameA("Ports", (LPGUID)0, 0, &RequiredSize);
    if(RequiredSize < 1) {
        return (HANDLE) -1;
    }

    buf = (char *) malloc(RequiredSize*sizeof(GUID));

    guidTest = SetupDiClassGuidsFromNameA("Ports", (_GUID *)buf, RequiredSize*sizeof(GUID), &RequiredSize);

    if(!guidTest) {
        return (HANDLE) -1;
    }

    DeviceInfoSet = SetupDiGetClassDevs((_GUID *)buf, NULL, NULL, DIGCF_PRESENT);
    free(buf);

    if(DeviceInfoSet == INVALID_HANDLE_VALUE) {
        return (HANDLE) -1;
    }

    return DeviceInfoSet;
}

BOOL EnumeratePortsNext(HANDLE DeviceInfoSet, LPTSTR lpBuffer, int *index) {
    static CM_Open_DevNode_Key OpenDevNodeKey = NULL;
    static HINSTANCE CfgMan;

    int res1;
    char DevName[MAX_NAME_PORTS] = {0};
    static int numDev = 0;
    int numport;

    SP_DEVINFO_DATA DeviceInfoData = {0};
    DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    if(!DeviceInfoSet || !lpBuffer) {
        return -1;
    }

    if(!OpenDevNodeKey) {
        CfgMan = LoadLibrary("cfgmgr32");
        if(!CfgMan) {
            return FALSE;
        }
        OpenDevNodeKey = (CM_Open_DevNode_Key)GetProcAddress(CfgMan, "CM_Open_DevNode_Key");
        if(!OpenDevNodeKey) {
            FreeLibrary(CfgMan);
            return FALSE;
        }
    }

    while(TRUE) {
        HKEY KeyDevice;
        DWORD len;
        res1 = SetupDiEnumDeviceInfo(DeviceInfoSet, numDev, &DeviceInfoData);

        if(!res1) {
            SetupDiDestroyDeviceInfoList(DeviceInfoSet);
            FreeLibrary(CfgMan);
            OpenDevNodeKey = NULL;
            return FALSE;
        }

        res1=OpenDevNodeKey(DeviceInfoData.DevInst,KEY_QUERY_VALUE,0,
                            RegDisposition_OpenExisting,&KeyDevice,CM_REGISTRY_HARDWARE);
        if(res1 != ERROR_SUCCESS) {
            return FALSE;
        }
        len = MAX_NAME_PORTS;

        res1 = RegQueryValueEx(KeyDevice, "portname", NULL, NULL, (BYTE*)DevName, &len);
        RegCloseKey(KeyDevice);

        if(res1 != ERROR_SUCCESS) {
            return FALSE;
        }

        *index = numDev;
        numDev++;
        if(memcmp(DevName, "COM", 3)) {
            continue;
        }
        numport = atoi(DevName + 3);
        if(numport > 0 && numport <= 256) {
            strcpy(lpBuffer, DevName);
            return TRUE;
        }

        FreeLibrary(CfgMan);
        OpenDevNodeKey = NULL;
        return FALSE;
    }
}

BOOL EndEnumeratePorts(HANDLE DeviceInfoSet) {
    if(SetupDiDestroyDeviceInfoList(DeviceInfoSet)) {
        return TRUE;
    } else {
        return FALSE;
    }
}

int htoi(char *p) {
    int n = 0;
    while(*p) {
        char c = *p;
        if(c >= '0' && c <= '9') {
            n = n * 16 + (c - '0');
        } else if(c >= 'a' && c <= 'z') {
            n = n * 16 + ((c+10) - 'a');
        } else if(c >= 'A' && c <= 'Z') {
            n = n * 16 + ((c+10) - 'A');
        } else {
            break;
        }
        p++;
    }
    return n;
}

int main(int argc, _TCHAR* argv[]) {
    HANDLE h;
    SP_DEVINFO_DATA devInfo;
    int vendor, product;
    int deviceIndex;

    char portname[50] = {0};
    char idstring[100] = {0};
    char infostring[100];
    char *sernostr;
    char *infop = infostring;

    h = BeginEnumeratePorts();
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);

    while(EnumeratePortsNext(h, portname, &deviceIndex)) {
        char *p;
        SetupDiEnumDeviceInfo(h, deviceIndex, &devInfo);
        SetupDiGetDeviceInstanceId(h, &devInfo, idstring, sizeof(idstring)-1, NULL);
        infop = infostring;

        p = strstr(idstring, "VID_");
        if(p) {
            product = htoi(p+4);
        } else {
            vendor = 0;
        }

        p = strstr(idstring, "PID_");
        if(p) {
            product = htoi(p+4);
            sernostr = p + 9;
        } else {
            product = 0;
            sernostr = NULL;
        }

        if(vendor == VENDOR_FTDI || vendor == VENDOR_ARDUINO) {
            printf("\nPossible Arduino on %s, VID 0x%04x PID 0x%04x\n    Serno %s", portname, vendor, product, sernostr);
        }
    }
}
