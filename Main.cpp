#include <windows.h>
#include <commctrl.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory>

// Link with required libraries
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")

// System Information Classes
#define SystemCodeIntegrityInformation 103
#define SystemSecureBootInformation 123
#define SystemHypervisorInformation 132
#define SystemCodeIntegrityPolicyInformation 157
#define SystemVirtualizationBasedSecurityInformation 196

// Structures
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

// Function pointer for NtQuerySystemInformation
typedef struct _SYSTEM_SECUREBOOT_INFORMATION {
    BOOLEAN SecureBootEnabled;
    BOOLEAN SecureBootCapable;
} SYSTEM_SECUREBOOT_INFORMATION, * PSYSTEM_SECUREBOOT_INFORMATION;

// Function pointer types for NtQuerySystemInformation
typedef struct _SYSTEM_HYPERVISOR_INFORMATION {
    ULONG HypervisorPresent;
    ULONG HypervisorDebuggerPresent;
    ULONG HypervisorDebuggerEnabled;
    ULONG Reserved[5];
} SYSTEM_HYPERVISOR_INFORMATION, * PSYSTEM_HYPERVISOR_INFORMATION;

// Function pointer type for NtQuerySystemInformation
typedef struct _SYSTEM_CODEINTEGRITY_POLICY_INFORMATION {
    ULONG Options;
    ULONG Version;
    ULONG PolicyCount;
    ULONG PolicySize;
    BYTE Policies[1];
} SYSTEM_CODEINTEGRITY_POLICY_INFORMATION, * PSYSTEM_CODEINTEGRITY_POLICY_INFORMATION;

// Function pointer type for NtQuerySystemInformation
typedef struct _SYSTEM_VBS_INFORMATION {
    ULONG VbsEnabled;
    ULONG VbsRequired;
    ULONG VbsRunning;
    ULONG VbsCapabilities;
    ULONG VbsFlags;
    ULONG Reserved[3];
} SYSTEM_VBS_INFORMATION, * PSYSTEM_VBS_INFORMATION;

// NtQuerySystemInformation prototype
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

// RtlGetVersion prototype (unaffected by the Windows 8.1+ appcompat shim that causes GetVersionExW to return 6.2.9200 for unmanifested apps).
typedef LONG(NTAPI* pRtlGetVersion)(OSVERSIONINFOEXW* VersionInfo);

// CI Option Flags
struct CiOptionFlag {
    ULONG flag;
    const wchar_t* name;
    const wchar_t* description;
    const wchar_t* activation;
};

// Constants for Code Integrity Options shown in the UI table.
const CiOptionFlag g_CiOptionFlags[] = {
    { 0x00000001, L"CODEINTEGRITY_OPTION_ENABLED", L"Code Integrity is enabled",
      L"Enabled by default on all modern Windows systems. It cannot be turned off without breaking code integrity, which will cause boot failure or automatic repair." },
    { 0x00000002, L"CODEINTEGRITY_OPTION_TESTSIGN", L"Test signing mode enabled",
      L"Run \"bcdedit /set testsigning on\" from an elevated prompt and reboot. Secure Boot must be disabled in UEFI firmware first." },
    { 0x00000004, L"CODEINTEGRITY_OPTION_UMCI_ENABLED", L"User Mode Code Integrity (UMCI) enabled",
      L"Enabled automatically when a Windows Defender Application Control (WDAC) or AppLocker policy targeting user-mode code is deployed and enforced." },
    { 0x00000008, L"CODEINTEGRITY_OPTION_KMCI_ENABLED", L"Kernel Mode Code Integrity (KMCI) enabled",
      L"Enabled by default. Disabled only via \"bcdedit /set nointegritychecks on\" or by disabling Driver Signature Enforcement from the F8 boot menu." },
    { 0x00000010, L"CODEINTEGRITY_OPTION_WHQL_ENFORCEMENT_ENABLED", L"WHQL enforcement enabled",
      L"Default on 64-bit Windows. Temporarily disable with \"bcdedit /set nointegritychecks on\" or the F8 \"Disable Driver Signature Enforcement\" option." },
    { 0x00000020, L"CODEINTEGRITY_OPTION_WHQL_TESTSIGN_ENABLED", L"WHQL test signing enabled",
      L"Enabled together with test signing mode: \"bcdedit /set testsigning on\", then reboot." },
    { 0x00000040, L"CODEINTEGRITY_OPTION_ELAM_ENABLED", L"Early Launch Anti-Malware (ELAM) enabled",
      L"Controlled by the Group Policy \"Boot-Start Driver Initialization Policy\" (Administrative Templates > System > Early Launch Antimalware), or the registry under HKLM\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch." },
    { 0x00000080, L"CODEINTEGRITY_OPTION_VBS_ENABLED", L"Virtualization-Based Security (VBS) enabled",
      L"Toggle \"Memory integrity\" under Windows Security > Device Security > Core Isolation, or the Group Policy \"Turn On Virtualization Based Security\", then reboot." },
    { 0x00000100, L"CODEINTEGRITY_OPTION_HVCI_ENABLED", L"Hypervisor-Protected Code Integrity (HVCI) enabled",
      L"Enable \"Memory integrity\" in Windows Security > Core Isolation, or via Group Policy with HVCI set to Enabled, then reboot. Requires VBS and compatible hardware/drivers." },
    { 0x00000200, L"CODEINTEGRITY_OPTION_WHQL_ENFORCEMENT_DISABLED", L"WHQL enforcement disabled",
      L"Set by \"bcdedit /set nointegritychecks on\" or \"bcdedit /set testsigning on\", which relaxes strict WHQL signature enforcement." },
    { 0x00000400, L"CODEINTEGRITY_OPTION_FLIGHT_BUILD", L"Flight build (insider build)",
      L"Set automatically when running a Windows Insider Preview (flighted) build. Enroll via Settings > Windows Update > Windows Insider Program." },
    { 0x00000800, L"CODEINTEGRITY_OPTION_FLIGHTING_ENABLED", L"Flighting enabled",
      L"Enabled by joining the Windows Insider Program and selecting an active flighting channel (Dev/Beta/Release Preview)." },
    { 0x00001000, L"CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED", L"HVCI with KMCI enabled",
      L"Set when HVCI is enabled together with kernel-mode code integrity. Enable via the same Core Isolation > Memory Integrity setting as HVCI_ENABLED." },
    { 0x00002000, L"CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED", L"HVCI with Isolated User Mode enabled",
      L"Reflects HVCI operating together with Isolated User Mode. Enable Memory Integrity and Credential Guard under Windows Security > Device Security." },
    { 0x00004000, L"CODEINTEGRITY_OPTION_WHQL_ENFORCEMENT_ENABLED_V2", L"WHQL enforcement v2 enabled",
      L"A newer-generation WHQL enforcement variant. Follows the default driver signing enforcement state; managed the same way as WHQL_ENFORCEMENT_ENABLED." },
    { 0x00008000, L"CODEINTEGRITY_OPTION_HVCI_MICROSOFT_ROOT_CERT", L"HVCI Microsoft root certificate",
      L"Indicates the HVCI policy trusts the Microsoft root certificate. Set automatically by the HVCI policy; not independently toggled by the user." },
    { 0x00010000, L"CODEINTEGRITY_OPTION_HVCI_STRICT_MODE", L"HVCI strict mode enabled",
      L"Enable Memory Integrity via Group Policy (System > Device Guard > Turn On Virtualization Based Security) with HVCI set to Enabled without UEFI lock, in strict compatibility mode." },
    { 0x00020000, L"CODEINTEGRITY_OPTION_HVCI_IUM_POLICY", L"HVCI IUM policy deployed",
      L"Set when a WDAC/HVCI policy governing Isolated User Mode is deployed, e.g. via an HVCI policy XML applied with the ConfigCI PowerShell module and Group Policy/MDM." },
    { 0x00040000, L"CODEINTEGRITY_OPTION_HVCI_KMCI_POLICY", L"HVCI KMCI policy deployed",
      L"Set when a WDAC kernel-mode code integrity policy is deployed alongside HVCI. Build with Set-CIPolicy/ConvertFrom-CIPolicy and deploy via Group Policy or MDM." },
    { 0x00080000, L"CODEINTEGRITY_OPTION_HVCI_IUM_POLICY_ENABLED", L"HVCI IUM policy enforced",
      L"Companion flag to HVCI_IUM_POLICY; becomes active once the deployed IUM policy is enforced rather than staged in audit mode." },
    { 0x00100000, L"CODEINTEGRITY_OPTION_HVCI_KMCI_POLICY_ENABLED", L"HVCI KMCI policy enforced",
      L"Companion flag to HVCI_KMCI_POLICY; becomes active once the deployed kernel-mode CI policy is enforced rather than staged in audit mode." },
    { 0x00200000, L"CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED_V2", L"HVCI IUM v2 enabled",
      L"Newer-generation IUM/HVCI combination flag. Enabled the same way as HVCI_IUM_ENABLED, via Memory Integrity plus Credential Guard." },
    { 0x00400000, L"CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED_V2", L"HVCI KMCI v2 enabled",
      L"Newer-generation HVCI+KMCI combination flag. Enabled the same way as HVCI_KMCI_ENABLED, via Memory Integrity." },
    { 0x00800000, L"CODEINTEGRITY_OPTION_HVCI_IUM_POLICY_V2", L"HVCI IUM policy v2",
      L"Newer-generation IUM policy flag. Deployed and enforced the same way as HVCI_IUM_POLICY." },
    { 0x01000000, L"CODEINTEGRITY_OPTION_HVCI_KMCI_POLICY_V2", L"HVCI KMCI policy v2",
      L"Newer-generation KMCI policy flag. Deployed and enforced the same way as HVCI_KMCI_POLICY." },
    { 0x02000000, L"CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED_V3", L"HVCI IUM v3 enabled",
      L"Further IUM/HVCI generation flag. Same activation path as the other HVCI_IUM_ENABLED variants." },
    { 0x04000000, L"CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED_V3", L"HVCI KMCI v3 enabled",
      L"Further HVCI+KMCI generation flag. Same activation path as the other HVCI_KMCI_ENABLED variants." },
    { 0x08000000, L"CODEINTEGRITY_OPTION_HVCI_IUM_POLICY_V3", L"HVCI IUM policy v3",
      L"Further IUM policy generation flag. Same deployment path as the other HVCI_IUM_POLICY variants." },
    { 0x10000000, L"CODEINTEGRITY_OPTION_HVCI_KMCI_POLICY_V3", L"HVCI KMCI policy v3",
      L"Further KMCI policy generation flag. Same deployment path as the other HVCI_KMCI_POLICY variants." },
    { 0x20000000, L"CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED_V4", L"HVCI IUM v4 enabled",
      L"Latest observed IUM/HVCI generation flag. Same activation path as the other HVCI_IUM_ENABLED variants." },
    { 0x40000000, L"CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED_V4", L"HVCI KMCI v4 enabled",
      L"Latest observed HVCI+KMCI generation flag. Same activation path as the other HVCI_KMCI_ENABLED variants." },
    { 0x80000000, L"CODEINTEGRITY_OPTION_RESERVED", L"Reserved flag",
      L"Reserved by the operating system. Not user-controllable." }
};

const int g_CiOptionFlagsCount = sizeof(g_CiOptionFlags) / sizeof(g_CiOptionFlags[0]);

// Diagnostics Properties (Diagnostics tab rows)
struct DiagItem {
    const wchar_t* name;
    const wchar_t* description;
    const wchar_t* activation;
};

const DiagItem g_DiagItems[] = {
    { L"OS Version", L"Windows version and build",
      L"Informational only. Reflects the installed Windows build; change it via Windows Update (Settings > Windows Update)." },
    { L"Secure Boot Capable", L"Whether hardware supports Secure Boot",
      L"Hardware/firmware capability. If supported, enable it in UEFI firmware setup (varies by OEM); not possible on legacy BIOS/CSM systems." },
    { L"Secure Boot Enabled", L"Whether Secure Boot is currently enabled",
      L"Enable in UEFI/BIOS setup: Boot or Security tab > Secure Boot > Enabled. Requires UEFI boot mode (not Legacy/CSM)." },
    { L"Hypervisor Present", L"Whether a hypervisor is running (Hyper-V, etc.)",
      L"Enable \"Hyper-V\" or \"Windows Hypervisor Platform\" via \"Turn Windows features on or off\", or run \"bcdedit /set hypervisorlaunchtype auto\" and reboot." },
    { L"Hypervisor Debugger Present", L"Whether hypervisor debugger is attached",
      L"Enabled for kernel/hypervisor debugging via \"bcdedit /hypervisorsettings\" plus \"bcdedit /debug on\"; used in development/debugging setups." },
    { L"Hypervisor Debugger Enabled", L"Whether hypervisor debugging is enabled",
      L"Enable with \"bcdedit /set hypervisordebug on\" together with a configured debug transport (e.g. \"bcdedit /dbgsettings serial|net ...\")." },
    { L"VBS Enabled", L"Virtualization-Based Security enabled in policy",
      L"Toggle \"Memory integrity\" in Windows Security > Core Isolation, or Group Policy \"Turn On Virtualization Based Security\", or set EnableVirtualizationBasedSecurity=1 under HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard." },
    { L"VBS Required", L"VBS required by policy",
      L"Set by an administrator via Group Policy \"Turn On Virtualization Based Security\" = Enabled, typically combined with a required Platform Security Level (Secure Boot, or Secure Boot and DMA Protection)." },
    { L"VBS Running", L"VBS currently running",
      L"Reflects runtime state after VBS is enabled and the system rebooted; not directly toggled � follows from \"VBS Enabled\" plus a compatible boot configuration." },
    { L"VBS Capabilities", L"VBS hardware capabilities",
      L"Hardware-dependent. Determined by CPU virtualization extensions (Intel VT-x/EPT or AMD-V/NPT) and firmware virtualization settings; not directly user-togglable." },
    { L"VBS Flags", L"VBS runtime flags",
      L"Reflects the current runtime combination of HVCI/VBS settings. Change by adjusting Memory Integrity and VBS settings above, then reboot." },
};

const int g_DiagItemsCount = sizeof(g_DiagItems) / sizeof(g_DiagItems[0]);

// Global variables
HINSTANCE g_hInst = NULL;
HWND g_hMainWnd = NULL;
HWND g_hTabControl = NULL;
HWND g_hListView = NULL;
HWND g_hDiagListView = NULL;
HWND g_hTabPage1 = NULL;
HWND g_hTabPage2 = NULL;
HWND g_hStatusBar = NULL;
UINT_PTR g_TimerId = 1;
pNtQuerySystemInformation g_NtQuerySystemInformation = nullptr;
pRtlGetVersion g_RtlGetVersion = nullptr;
SYSTEM_CODEINTEGRITY_INFORMATION g_CiInfo = { 0 };
ULONG g_ReturnLength = 0;
NTSTATUS g_LastStatus = 0;
ULONG g_LastCiOptions = 0;
bool  g_NeedsColorClear = false; // true after a change tick so we force one more repaint to drop yellow
HFONT g_hBoldFont = NULL;
bool  g_BoldFontIsStock = false; // true if g_hBoldFont is a stock object (no DeleteObject needed)

// Diagnostics data
SYSTEM_SECUREBOOT_INFORMATION g_SecureBootInfo = { 0 };
SYSTEM_HYPERVISOR_INFORMATION g_HypervisorInfo = { 0 };
SYSTEM_VBS_INFORMATION g_VbsInfo = { 0 };
std::wstring g_CiPolicyInfo = L"";
OSVERSIONINFOEXW g_OsVersion = { 0 };
ULONG g_OsUbr = 0; // Update Build Revision (post-build number, e.g. 4831 in 22631.4831)
bool g_HaveOsVersion = false;

const wchar_t* CLASS_NAME = L"CiOptionsCheckWindowClass";

// Forward declarations
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
void InitializeListView(HWND hwnd);
void InitializeDiagListView(HWND hwnd);
void UpdateListView();
void UpdateDiagView();
void QueryAllSystemInfo();
std::wstring FormatHex(ULONG value);
std::wstring FormatHex64(ULONGLONG value);
void UpdateStatusBar();
void OnTimer(HWND hwnd);
void CreateControls(HWND hwnd);
void CreateTabControl(HWND hwnd);
HWND CreateTabPage(HWND hTab, int index, const wchar_t* title);
void OnTabChange(HWND hwnd);
std::wstring GetOsVersionString();
void QueryOsVersion();
std::wstring GetCiPolicyDetails();
std::wstring GetVbsCapabilitiesString(ULONG caps);
std::wstring GetVbsFlagsString(ULONG flags);
bool QuerySecureBoot();
bool QueryHypervisor();
bool QueryVbs();
bool QueryCiPolicy();
LRESULT CALLBACK TabPageSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);

// WinMain
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    g_hInst = hInstance;

    // Initialize common controls
    INITCOMMONCONTROLSEX icex = { 0 };
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_TAB_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);

    // Load ntdll.dll and get NtQuerySystemInformation + RtlGetVersion
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        g_NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
        g_RtlGetVersion = (pRtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion");
    }

    if (!g_NtQuerySystemInformation) {
        MessageBoxW(NULL, L"Failed to load NtQuerySystemInformation from ntdll.dll", L"Error", MB_ICONERROR | MB_OK);
        return 1;
    }
    if (!g_RtlGetVersion) {
        MessageBoxW(NULL, L"Failed to load RtlGetVersion from ntdll.dll", L"Error", MB_ICONERROR | MB_OK);
        return 1;
    }

    // Initialize structures
    g_CiInfo.Length = sizeof(SYSTEM_CODEINTEGRITY_INFORMATION);
    g_OsVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

    // Register window class
    WNDCLASSEXW wcex = { 0 };
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_3DFACE + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = CLASS_NAME;
    wcex.hIconSm = LoadIcon(wcex.hInstance, IDI_APPLICATION);

    if (!RegisterClassExW(&wcex)) {
        MessageBoxW(NULL, L"Failed to register window class", L"Error", MB_ICONERROR | MB_OK);
        return 1;
    }

    // Create window
    // Fixed-size window: remove maximize box, minimize box, and resize border.
    // Keep caption + system menu + close button only.
    HWND hwnd = CreateWindowExW(
        0,
        CLASS_NAME,
        L"CiOptions Check - Code Integrity Options Viewer",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_BORDER,
        CW_USEDEFAULT, CW_USEDEFAULT, 1000, 700,
        NULL, NULL, hInstance, NULL
    );

    if (!hwnd) {
        MessageBoxW(NULL, L"Failed to create window", L"Error", MB_ICONERROR | MB_OK);
        return 1;
    }
    g_hMainWnd = hwnd;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // Initial query.
    // Sync g_LastCiOptions to the real value immediately so the first
    // NM_CUSTOMDRAW pass sees wasSet == isSet and draws green/gray instead
    // of yellow (yellow means "changed since last tick", not "set on boot").
    QueryAllSystemInfo();
    g_LastCiOptions = g_CiInfo.CodeIntegrityOptions;
    UpdateListView();
    // Force a full repaint of the CI options ListView so that subitem 0
    // (Flag Name) is repainted with the correct per-subitem colors.
    // The first paint happened before QueryAllSystemInfo() (during
    // ShowWindow/UpdateWindow) when g_CiInfo was still zero, so all rows
    // were drawn as gray/unset. Subitem 0 is never invalidated by
    // UpdateListView() (which only touches subitems 1 and 2), so without
    // this it would stay gray/black forever.
    InvalidateRect(g_hListView, NULL, TRUE);
    UpdateDiagView();
    UpdateStatusBar();

    // Set timer for auto-refresh (1 second)
    SetTimer(hwnd, g_TimerId, 1000, NULL);

    // Message loop
    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Cleanup
    KillTimer(hwnd, g_TimerId);

    return (int)msg.wParam;
}

// Query all system information
void QueryAllSystemInfo() {
    g_LastCiOptions = g_CiInfo.CodeIntegrityOptions;

    // Reset Length before each call (NtQuerySystemInformation may modify it on output)
    g_CiInfo.Length = sizeof(SYSTEM_CODEINTEGRITY_INFORMATION);

    // Query CI Options
    g_LastStatus = g_NtQuerySystemInformation(
        SystemCodeIntegrityInformation,
        &g_CiInfo,
        sizeof(g_CiInfo),
        &g_ReturnLength
    );

    // Query Secure Boot
    QuerySecureBoot();

    // Query Hypervisor
    QueryHypervisor();

    // Query VBS
    QueryVbs();

    // Query CI Policy
    QueryCiPolicy();

    // Query OS version (fixed: was never populated before)
    if (!g_HaveOsVersion) {
        QueryOsVersion();
    }
}

// Query OS version via RtlGetVersion the adds Update Build Revision (UBR) from the registry 
// so we can show the full "Build 22xxx.xxxx" form that RtlGetVersion does not expose.
void QueryOsVersion() {
    memset(&g_OsVersion, 0, sizeof(g_OsVersion));
    g_OsVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
    g_OsUbr = 0;

    if (g_RtlGetVersion) {
        LONG status = g_RtlGetVersion(&g_OsVersion);
        if (status == 0) {
            g_HaveOsVersion = true;
        }
    }

    // Read UBR from the registry. Value is a REG_DWORD.
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    {
        DWORD ubr = 0;
        DWORD type = 0;
        DWORD cb = sizeof(ubr);
        if (RegQueryValueExW(hKey, L"UBR", NULL, &type,
            reinterpret_cast<LPBYTE>(&ubr), &cb) == ERROR_SUCCESS
            && type == REG_DWORD)
        {
            g_OsUbr = ubr;
        }
        RegCloseKey(hKey);
    }
}

// Query Secure Boot status
bool QuerySecureBoot() {
    NTSTATUS status = g_NtQuerySystemInformation(
        SystemSecureBootInformation,
        &g_SecureBootInfo,
        sizeof(g_SecureBootInfo),
        &g_ReturnLength
    );

    if (status != 0) {
        // NtQuerySystemInformation failed (common on some UEFI/configs).
        // Falls back to the registry method for Secure Boot detection.
        memset(&g_SecureBootInfo, 0, sizeof(g_SecureBootInfo));
        HKEY hKey = NULL;
        DWORD uefiSecureBoot = 0;
        DWORD type = 0;
        DWORD cb = sizeof(uefiSecureBoot);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
            0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
        {
            if (RegQueryValueExW(hKey, L"UEFISecureBootEnabled", NULL, &type,
                reinterpret_cast<LPBYTE>(&uefiSecureBoot), &cb) == ERROR_SUCCESS
                && type == REG_DWORD)
            {
                g_SecureBootInfo.SecureBootEnabled = (uefiSecureBoot != 0);
                g_SecureBootInfo.SecureBootCapable = TRUE;
            }
            RegCloseKey(hKey);
        }
    }

    return status == 0;
}

// Query Hypervisor info
bool QueryHypervisor() {
    NTSTATUS status = g_NtQuerySystemInformation(
        SystemHypervisorInformation,
        &g_HypervisorInfo,
        sizeof(g_HypervisorInfo),
        &g_ReturnLength
    );
    return status == 0;
}

// Query VBS info
bool QueryVbs() {
    NTSTATUS status = g_NtQuerySystemInformation(
        SystemVirtualizationBasedSecurityInformation,
        &g_VbsInfo,
        sizeof(g_VbsInfo),
        &g_ReturnLength
    );
    return status == 0;
}

// Query CI Policy
bool QueryCiPolicy() {
    ULONG size = 0;
    NTSTATUS status = g_NtQuerySystemInformation(
        SystemCodeIntegrityPolicyInformation,
        NULL,
        0,
        &size
    );

    if (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
        std::vector<BYTE> buffer(size);
        PSYSTEM_CODEINTEGRITY_POLICY_INFORMATION policyInfo = (PSYSTEM_CODEINTEGRITY_POLICY_INFORMATION)buffer.data();
        status = g_NtQuerySystemInformation(
            SystemCodeIntegrityPolicyInformation,
            policyInfo,
            size,
            &g_ReturnLength
        );
        if (status == 0) {
            std::wstringstream ss;
            ss << L"Options: 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0') << policyInfo->Options << L"\n";
            ss << L"Version: " << std::dec << policyInfo->Version << L"\n";
            ss << L"Policy Count: " << policyInfo->PolicyCount << L"\n";
            ss << L"Policy Size: " << policyInfo->PolicySize << L" bytes";
            g_CiPolicyInfo = ss.str();
            return true;
        }
    }
    g_CiPolicyInfo = L"Query failed or no policies";
    return false;
}

// Window procedure
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        CreateControls(hwnd);
        CreateTabControl(hwnd);
        InitializeListView(hwnd);
        InitializeDiagListView(hwnd);
        break;

    case WM_SIZE: {
        int width = LOWORD(lParam);
        int height = HIWORD(lParam);

        int statusHeight = 25;
        int padding = 10;

        int y = padding;

        // Tab control takes the full client area minus status bar
        int tabHeight = height - y - statusHeight - padding * 2;
        MoveWindow(g_hTabControl, padding, y, width - padding * 2, tabHeight, TRUE);

        // Resize tab pages and their child ListViews
        RECT rcTab;
        GetClientRect(g_hTabControl, &rcTab);
        TabCtrl_AdjustRect(g_hTabControl, FALSE, &rcTab);

        // Use global tab page handles
        if (g_hTabPage1) {
            MoveWindow(g_hTabPage1, rcTab.left, rcTab.top, rcTab.right - rcTab.left, rcTab.bottom - rcTab.top, TRUE);
            // Resize ListView in page 1
            if (g_hListView) {
                RECT rcPage;
                GetClientRect(g_hTabPage1, &rcPage);
                MoveWindow(g_hListView, 0, 0, rcPage.right, rcPage.bottom, TRUE);
            }
        }
        if (g_hTabPage2) {
            MoveWindow(g_hTabPage2, rcTab.left, rcTab.top, rcTab.right - rcTab.left, rcTab.bottom - rcTab.top, TRUE);
            // Resize ListView in page 2
            if (g_hDiagListView) {
                RECT rcPage;
                GetClientRect(g_hTabPage2, &rcPage);
                MoveWindow(g_hDiagListView, 0, 0, rcPage.right, rcPage.bottom, TRUE);
            }
        }

        // Status bar
        MoveWindow(g_hStatusBar, 0, height - statusHeight, width, statusHeight, TRUE);
        SendMessage(g_hStatusBar, WM_SIZE, 0, 0);
        break;
    }

    case WM_TIMER:
        if (wParam == g_TimerId) {
            OnTimer(hwnd);
        }
        break;

    case WM_NOTIFY: {
        LPNMHDR nmhdr = (LPNMHDR)lParam;
        if (nmhdr->hwndFrom == g_hListView && nmhdr->code == NM_CUSTOMDRAW) {
            LPNMLVCUSTOMDRAW lplvcd = (LPNMLVCUSTOMDRAW)lParam;
            switch (lplvcd->nmcd.dwDrawStage) {
            case CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW;
            case CDDS_ITEMPREPAINT: {
                int itemIndex = (int)lplvcd->nmcd.dwItemSpec;
                if (itemIndex >= 0 && itemIndex < g_CiOptionFlagsCount) {
                    // Lazy-init the bold font once
                    if (!g_hBoldFont) {
                        HFONT hCurr = (HFONT)SendMessage(g_hListView, WM_GETFONT, 0, 0);
                        LOGFONTW lf = { 0 };
                        if (hCurr && GetObjectW(hCurr, sizeof(lf), &lf)) {
                            lf.lfWeight = FW_BOLD;
                            g_hBoldFont = CreateFontIndirectW(&lf);
                            g_BoldFontIsStock = (g_hBoldFont == NULL);
                        }
                        if (!g_hBoldFont) {
                            // Fallback: system bold default GUI font.
                            g_hBoldFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
                            g_BoldFontIsStock = true;
                        }
                    }
                }
                return CDRF_NOTIFYSUBITEMDRAW;
            }
            case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
                int itemIndex = (int)lplvcd->nmcd.dwItemSpec;
                if (itemIndex >= 0 && itemIndex < g_CiOptionFlagsCount) {
                    ULONG flag = g_CiOptionFlags[itemIndex].flag;
                    bool isSet = (g_CiInfo.CodeIntegrityOptions & flag) != 0;
                    bool wasSet = (g_LastCiOptions & flag) != 0;

                    // Select the appropriate font for this subitem
                    HDC hdc = lplvcd->nmcd.hdc;
                    if (hdc) {
                        HFONT hDefault = (HFONT)SendMessage(g_hListView, WM_GETFONT, 0, 0);
                        HFONT hFont = isSet ? g_hBoldFont : hDefault;
                        SelectObject(hdc, hFont);

                        // Apply colors directly to the DC (most reliable across Windows versions)
                        if (isSet != wasSet) {
                            SetTextColor(hdc, RGB(0, 0, 0));
                            SetBkColor(hdc, RGB(255, 255, 150));
                        }
                        else if (isSet) {
                            SetTextColor(hdc, RGB(0, 128, 0));
                            SetBkColor(hdc, RGB(255, 255, 255));
                        }
                        else {
                            SetTextColor(hdc, RGB(128, 128, 128));
                            SetBkColor(hdc, RGB(255, 255, 255));
                        }
                    }

                    // Also set the NMLVCUSTOMDRAW fields so the ListView
                    // can use them directly as well.
                    if (isSet != wasSet) {
                        lplvcd->clrText = RGB(0, 0, 0);
                        lplvcd->clrTextBk = RGB(255, 255, 150);
                    }
                    else if (isSet) {
                        lplvcd->clrText = RGB(0, 128, 0);
                        lplvcd->clrTextBk = RGB(255, 255, 255);
                    }
                    else {
                        lplvcd->clrText = RGB(128, 128, 128);
                        lplvcd->clrTextBk = RGB(255, 255, 255);
                    }
                }
                return CDRF_NEWFONT;
            }
            }
        }
        else if (nmhdr->code == LVN_GETINFOTIPW) {
            // ListView-managed tooltip (requires LVS_EX_INFOTIP). The ListView
            // owns the tooltip and fires this notification to its parent; the
            // tab-page subclass forwards it to the main window here.
            LPNMLVGETINFOTIPW pgi = (LPNMLVGETINFOTIPW)lParam;
            HWND hwndList = nmhdr->hwndFrom;
            int item = pgi->iItem;
            if (item < 0) {
                // Fall back to the item currently under the cursor.
                POINT pt;
                GetCursorPos(&pt);
                ScreenToClient(hwndList, &pt);
                LVHITTESTINFO ht = { 0 };
                ht.pt = pt;
                item = ListView_HitTest(hwndList, &ht);
            }
            if (item >= 0) {
                const wchar_t* desc = NULL;
                const wchar_t* activation = NULL;
                if (hwndList == g_hListView && item < g_CiOptionFlagsCount) {
                    desc = g_CiOptionFlags[item].description;
                    activation = g_CiOptionFlags[item].activation;
                }
                else if (hwndList == g_hDiagListView && item < g_DiagItemsCount) {
                    desc = g_DiagItems[item].description;
                    activation = g_DiagItems[item].activation;
                }
                if (desc) {
                    // Build the full tip: one-liner summary, blank line, then the
                    // "how to enable/disable" instructions from the activation field.
                    // TTM_SETMAXTIPWIDTH (set in CreateTabControl) allows \n to wrap.
                    std::wstring tip = desc;
                    if (activation && activation[0]) {
                        tip += L"\n\n";
                        tip += activation;
                    }
                    wcsncpy_s(pgi->pszText, pgi->cchTextMax, tip.c_str(), _TRUNCATE);
                }
            }
        }
        else if (nmhdr->hwndFrom == g_hTabControl && nmhdr->code == TCN_SELCHANGE) {
            OnTabChange(hwnd);
        }
        break;
    }

    case WM_CTLCOLORSTATIC: {
        // Default classic Windows color scheme for static controls
        HDC hdcStatic = (HDC)wParam;
        SetBkColor(hdcStatic, GetSysColor(COLOR_3DFACE));
        SetTextColor(hdcStatic, GetSysColor(COLOR_BTNTEXT));
        return (LRESULT)GetSysColorBrush(COLOR_3DFACE);
    }

    case WM_DESTROY:
        KillTimer(hwnd, g_TimerId);
        if (g_hBoldFont && !g_BoldFontIsStock) {
            DeleteObject(g_hBoldFont);
        }
        g_hBoldFont = NULL;
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// Create child controls
void CreateControls(HWND hwnd) {
    // Status bar (no size grip: window is non-resizable)
    g_hStatusBar = CreateWindowExW(
        0, STATUSCLASSNAMEW, L"",
        WS_CHILD | WS_VISIBLE,
        0, 0, 0, 0, hwnd, NULL, g_hInst, NULL
    );
    int statusParts[] = { -1 };
    SendMessage(g_hStatusBar, SB_SETPARTS, 1, (LPARAM)statusParts);
}

// Create tab control with two tabs
void CreateTabControl(HWND hwnd) {
    g_hTabControl = CreateWindowExW(
        0, WC_TABCONTROLW, L"",
        WS_CHILD | WS_VISIBLE | TCS_TABS | TCS_SINGLELINE,
        0, 0, 0, 0, hwnd, NULL, g_hInst, NULL
    );
    SendMessage(g_hTabControl, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

    // CI Options tab
    TCITEMW tie = { 0 };
    tie.mask = TCIF_TEXT;
    tie.pszText = const_cast<LPWSTR>(L"CI Options");
    TabCtrl_InsertItem(g_hTabControl, 0, &tie);

    // Diagnostics tab
    tie.pszText = const_cast<LPWSTR>(L"Diagnostics");
    TabCtrl_InsertItem(g_hTabControl, 1, &tie);

    // Variable to hold tab page handles
    g_hTabPage1 = CreateTabPage(g_hTabControl, 0, L"CI Options");
    g_hTabPage2 = CreateTabPage(g_hTabControl, 1, L"Diagnostics");

    // Create ListView for CI Options tab
    g_hListView = CreateWindowExW(
        0, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_BORDER,
        0, 0, 0, 0, g_hTabPage1, NULL, g_hInst, NULL
    );
    SendMessage(g_hListView, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER | LVS_EX_INFOTIP);

    // Create ListView for Diagnostics tab
    g_hDiagListView = CreateWindowExW(
        0, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_BORDER,
        0, 0, 0, 0, g_hTabPage2, NULL, g_hInst, NULL
    );
    SendMessage(g_hDiagListView, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    ListView_SetExtendedListViewStyle(g_hDiagListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER | LVS_EX_INFOTIP);

    // Enable word-wrapping in both ListView tooltip controls.
    // Without TTM_SETMAXTIPWIDTH the tooltip renders as one unbounded horizontal
    // line; any \n in the text is ignored and long strings clip at the screen edge.
    HWND hTip1 = ListView_GetToolTips(g_hListView);
    if (hTip1) SendMessage(hTip1, TTM_SETMAXTIPWIDTH, 0, 600);
    HWND hTip2 = ListView_GetToolTips(g_hDiagListView);
    if (hTip2) SendMessage(hTip2, TTM_SETMAXTIPWIDTH, 0, 600);

    // Show first tab
    ShowWindow(g_hTabPage1, SW_SHOW);
    ShowWindow(g_hTabPage2, SW_HIDE);
}

// Create a tab page window
HWND CreateTabPage(HWND hTab, int index, const wchar_t* title) {
    RECT rc;
    GetClientRect(hTab, &rc);
    TabCtrl_AdjustRect(hTab, FALSE, &rc);

    HWND hPage = CreateWindowExW(
        0, L"STATIC", L"",
        WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
        rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
        hTab, NULL, g_hInst, NULL
    );

    // STATIC controls eat WM_NOTIFY from child controls (ListView, Tooltip).
    // Subclass so we can relay those notifications up to the main window's
    // WndProc, where the existing NM_CUSTOMDRAW / LVN_GETINFOTIPW handlers live.
    if (hPage) {
        SetWindowSubclass(hPage, TabPageSubclassProc, 0, 0);
    }
    return hPage;
}

// Handle tab change
void OnTabChange(HWND hwnd) {
    int sel = TabCtrl_GetCurSel(g_hTabControl);

    if (sel == 0) {
        ShowWindow(g_hTabPage1, SW_SHOW);
        ShowWindow(g_hTabPage2, SW_HIDE);

        // Force resize of the visible ListView
        if (g_hListView) {
            RECT rc;
            GetClientRect(g_hTabPage1, &rc);
            MoveWindow(g_hListView, 0, 0, rc.right, rc.bottom, TRUE);
        }
    }
    else {
        ShowWindow(g_hTabPage1, SW_HIDE);
        ShowWindow(g_hTabPage2, SW_SHOW);

        // Force resize of the visible ListView
        if (g_hDiagListView) {
            RECT rc;
            GetClientRect(g_hTabPage2, &rc);
            MoveWindow(g_hDiagListView, 0, 0, rc.right, rc.bottom, TRUE);
        }
    }
}

// Initialize CI Options ListView
void InitializeListView(HWND hwnd) {
    LVCOLUMNW lvc = { 0 };
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

    // Flag Name
    lvc.fmt = LVCFMT_LEFT;
    lvc.cx = 350;
    lvc.pszText = const_cast<LPWSTR>(L"Flag Name");
    lvc.iSubItem = 0;
    ListView_InsertColumn(g_hListView, 0, &lvc);

    // Value
    lvc.cx = 80;
    lvc.pszText = const_cast<LPWSTR>(L"Value");
    lvc.iSubItem = 1;
    ListView_InsertColumn(g_hListView, 1, &lvc);

    // Description
    lvc.cx = 450;
    lvc.pszText = const_cast<LPWSTR>(L"Description");
    lvc.iSubItem = 2;
    ListView_InsertColumn(g_hListView, 2, &lvc);

    // Insert items for each flag
    LVITEMW lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    for (int i = 0; i < g_CiOptionFlagsCount; i++) {
        lvi.iItem = i;
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(g_CiOptionFlags[i].name);
        ListView_InsertItem(g_hListView, &lvi);

        ListView_SetItemText(g_hListView, i, 1, const_cast<LPWSTR>(L""));
        ListView_SetItemText(g_hListView, i, 2, const_cast<LPWSTR>(g_CiOptionFlags[i].description));
    }
}

// Initialize Diagnostics ListView
void InitializeDiagListView(HWND hwnd) {
    LVCOLUMNW lvc = { 0 };
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

    // Property
    lvc.fmt = LVCFMT_LEFT;
    lvc.cx = 250;
    lvc.pszText = const_cast<LPWSTR>(L"Property");
    lvc.iSubItem = 0;
    ListView_InsertColumn(g_hDiagListView, 0, &lvc);

    // Value
    lvc.cx = 550;
    lvc.pszText = const_cast<LPWSTR>(L"Value");
    lvc.iSubItem = 1;
    ListView_InsertColumn(g_hDiagListView, 1, &lvc);

    // Insert items into the Diagnostics ListView
    LVITEMW lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    for (int i = 0; i < g_DiagItemsCount; i++) {
        lvi.iItem = i;
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(g_DiagItems[i].name);
        ListView_InsertItem(g_hDiagListView, &lvi);
        ListView_SetItemText(g_hDiagListView, i, 1, const_cast<LPWSTR>(L""));
    }
}

// Update CI Options ListView
void UpdateListView() {
    for (int i = 0; i < g_CiOptionFlagsCount; i++) {
        ULONG flag = g_CiOptionFlags[i].flag;
        bool isSet = (g_CiInfo.CodeIntegrityOptions & flag) != 0;
        ListView_SetItemText(g_hListView, i, 1, const_cast<LPWSTR>(isSet ? L"TRUE" : L"FALSE"));
        std::wstring desc = g_CiOptionFlags[i].description;
        desc += isSet ? L" [ENABLED]" : L" [disabled]";
        ListView_SetItemText(g_hListView, i, 2, const_cast<LPWSTR>(desc.c_str()));
    }
}

// Update Diagnostics ListView
void UpdateDiagView() {
    int row = 0;

    // NOTE: Row order here must match g_DiagItems[] definition exactly.
    //       If you add/remove/reorder g_DiagItems, update this function accordingly.

    // OS Version
    ListView_SetItemText(g_hDiagListView, row++, 1, const_cast<LPWSTR>(GetOsVersionString().c_str()));

    // Secure Boot
    ListView_SetItemText(g_hDiagListView, row++, 1, const_cast<LPWSTR>(g_SecureBootInfo.SecureBootCapable ? L"Yes" : L"No"));
    ListView_SetItemText(g_hDiagListView, row++, 1, const_cast<LPWSTR>(g_SecureBootInfo.SecureBootEnabled ? L"Yes" : L"No"));

    // Hypervisor
    ListView_SetItemText(g_hDiagListView, row++, 1, const_cast<LPWSTR>(g_HypervisorInfo.HypervisorPresent ? L"Yes" : L"No"));
    ListView_SetItemText(g_hDiagListView, row++, 1, const_cast<LPWSTR>(g_HypervisorInfo.HypervisorDebuggerPresent ? L"Yes" : L"No"));
    ListView_SetItemText(g_hDiagListView, row++, 1, const_cast<LPWSTR>(g_HypervisorInfo.HypervisorDebuggerEnabled ? L"Yes" : L"No"));

    // VBS
    ListView_SetItemText(g_hDiagListView, row++, 1, const_cast<LPWSTR>(g_VbsInfo.VbsEnabled ? L"Yes" : L"No"));
    ListView_SetItemText(g_hDiagListView, row++, 1, const_cast<LPWSTR>(g_VbsInfo.VbsRequired ? L"Yes" : L"No"));
    ListView_SetItemText(g_hDiagListView, row++, 1, const_cast<LPWSTR>(g_VbsInfo.VbsRunning ? L"Yes" : L"No"));
    ListView_SetItemText(g_hDiagListView, row++, 1, const_cast<LPWSTR>(GetVbsCapabilitiesString(g_VbsInfo.VbsCapabilities).c_str()));
    ListView_SetItemText(g_hDiagListView, row++, 1, const_cast<LPWSTR>(GetVbsFlagsString(g_VbsInfo.VbsFlags).c_str()));
}

// Update status bar
void UpdateStatusBar() {
    std::wstring text = L"g_CiOptions: " + FormatHex(g_CiInfo.CodeIntegrityOptions) + L" | " + GetOsVersionString();
    SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)text.c_str());
}

// Timer callback
void OnTimer(HWND hwnd) {
    QueryAllSystemInfo();

    // Refresh the ListViews when something actually changed, OR on the tick
    // immediately after a change (g_NeedsColorClear) so that the yellow
    // highlight is replaced with stable green/gray once the value settles.
    // Limiting updates this way avoids SetItemText thrashing the control and
    // killing any visible tooltip on every tick.
    bool changed = (g_LastCiOptions != g_CiInfo.CodeIntegrityOptions);
    if (changed || g_NeedsColorClear) {
        UpdateListView();
        // Full repaint so subitem 0 (Flag Name) gets correct colors too;
        // UpdateListView() only touches subitems 1 and 2.
        InvalidateRect(g_hListView, NULL, TRUE);
        UpdateDiagView();
        g_NeedsColorClear = changed; // arm for one more repaint if we just went yellow
    }

    UpdateStatusBar();
}

// Format hex string
std::wstring FormatHex(ULONG value) {
    std::wstringstream ss;
    ss << L"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0') << value;
    return ss.str();
}

std::wstring FormatHex64(ULONGLONG value) {
    std::wstringstream ss;
    ss << L"0x" << std::hex << std::uppercase << std::setw(16) << std::setfill(L'0') << value;
    return ss.str();
}

// Get OS version string (full build, e.g. "Windows 11 Build 2xxxx.xxxx")
std::wstring GetOsVersionString() {
    if (!g_HaveOsVersion) {
        return L"Unknown";
    }
    std::wstringstream ss;
    ss << L"Windows " << g_OsVersion.dwMajorVersion << L"." << g_OsVersion.dwMinorVersion
        << L" Build " << g_OsVersion.dwBuildNumber;
    if (g_OsUbr != 0) {
        ss << L"." << g_OsUbr;
    }
    if (g_OsVersion.wServicePackMajor || g_OsVersion.wServicePackMinor) {
        ss << L" SP" << g_OsVersion.wServicePackMajor << L"." << g_OsVersion.wServicePackMinor;
    }
    return ss.str();
}

// Get VBS capabilities string
std::wstring GetVbsCapabilitiesString(ULONG caps) {
    std::wstringstream ss;
    bool first = true;
    if (caps & 0x1) { if (!first) ss << L", "; ss << L"VBS_CAPABILITY_HVCI"; first = false; }
    if (caps & 0x2) { if (!first) ss << L", "; ss << L"VBS_CAPABILITY_VBS_BASIC"; first = false; }
    if (caps & 0x4) { if (!first) ss << L", "; ss << L"VBS_CAPABILITY_VBS_ENHANCED"; first = false; }
    if (first) ss << L"None";
    return ss.str();
}

// Get VBS flags string
std::wstring GetVbsFlagsString(ULONG flags) {
    std::wstringstream ss;
    bool first = true;
    if (flags & 0x1) { if (!first) ss << L", "; ss << L"VBS_FLAG_HVCI_ENABLED"; first = false; }
    if (flags & 0x2) { if (!first) ss << L", "; ss << L"VBS_FLAG_VBS_ENABLED"; first = false; }
    if (first) ss << L"None";
    return ss.str();
}

// Subclass procedure for the STATIC-based tab page windows.
// ListView children send WM_NOTIFY to their immediate parent (the static page),
// which a stock STATIC control does not forward. Relay those notifications to
// the main window so NM_CUSTOMDRAW (row coloring) and LVN_GETINFOTIPW (tooltips)
// are actually handled.
LRESULT CALLBACK TabPageSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    switch (msg) {
    case WM_NOTIFY:
        // Forward to the main window so its WndProc handles NM_CUSTOMDRAW,
        // LVN_GETINFOTIPW, and TCN_SELCHANGE uniformly.
        if (g_hMainWnd) {
            return SendMessageW(g_hMainWnd, msg, wParam, lParam);
        }
        break;
    case WM_NCDESTROY:
        RemoveWindowSubclass(hwnd, TabPageSubclassProc, uIdSubclass);
        break;
    }
    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

