#pragma once

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <map>
#include <string>
#include <tchar.h>
#include <vector>
#include <windows.h>
#include <winternl.h>
#include "json.hpp"

#include <dbghelp.h>
#include <Psapi.h>
#include <tlhelp32.h>

// https://github.com/nlohmann/json
using nlohmann::json;

#define Granulariy	0x10 // 0x10 for x64, 0x08 for x86. 
#define HasFiberDataMask 0x004 // 6.0 and up.
#define NtHeap		0xFFEEFFEE
#define SegmentHeap 0xDDEEDDEE
#define STATUS_SUCCESS 0x00000000

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/teb/index.htm
#define TebOffset_ActivationContextStackPointer 0x2c8 // 1703 and higher.
// #define PebOffset_FlsCallback 0x320 // Pre 1903, 
#define TebOffset_FlsData 0x17C8 // 5.2 onwards
#define TebOffset_GuaranteedStackBytes  0x1748 // Late 5.2 and higher
#define	TebOffset_ProcessEnvironmentBlock 0x60 // all versions
#define TebOffset_SameTebFlags 0x17EE // 6.0 and onwards.

BOOL g_windowsVerBelow10 = false;
std::string g_symPath = "C:\\symbols\\;";

// https://github.com/wine-mirror/wine/blob/master/include/winternl.h
typedef struct _FLS_CALLBACK
{
	void* unknown;
	PFLS_CALLBACK_FUNCTION callback; // ~0 if NULL callback is set, NULL if FLS index is free.
} FLS_CALLBACK, * PFLS_CALLBACK;

typedef struct _FLS_INFO_CHUNK
{
	ULONG count;         // number of allocated FLS indexes in the chunk.
	FLS_CALLBACK callbacks[1];  // the size is 0x10 for chunk 0 and is twice as the previous chunk size for the rest.
} FLS_INFO_CHUNK, * PFLS_INFO_CHUNK;

typedef struct _GLOBAL_FLS_DATA
{
	FLS_INFO_CHUNK* flsCallbackChunks[8];
	LIST_ENTRY      flsListHead;
	ULONG           flsHighIndex;
} GLOBAL_FLS_DATA, * PGLOBAL_FLS_DATA;

typedef struct _TEB_FLS_DATA
{
	LIST_ENTRY      flsListEntry;
	PVOID			flsDataChunks[8];
} TEB_FLS_DATA, * PTEB_FLS_DATA;

// https://processhacker.sourceforge.io/doc/heapstruct_8h_source.html#l00005
// Not the actual structure, but has the same size.
typedef struct _HEAP_ENTRY
{
	PVOID Data1;
	PVOID Data2;
} HEAP_ENTRY, * PHEAP_ENTRY;

// https://processhacker.sourceforge.io/doc/heapstruct_8h_source.html#l00014
// First few fields of HEAP_SEGMENT, VISTA and above
typedef struct _HEAP_SEGMENT
{
	HEAP_ENTRY HeapEntry;
	ULONG SegmentSignature;
	ULONG SegmentFlags;
	LIST_ENTRY SegmentListEntry;
	struct _HEAP* Heap;
	// ...
} HEAP_SEGMENT, * PHEAP_SEGMENT;

enum MY_THREADINFOCLASS
{
	ThreadBasicInformation,
};

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

// https://github.com/processhacker/phnt/blob/master/ntpebteb.h#L19
typedef struct _ACTIVATION_CONTEXT_STACK
{
	struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

//
// Pseudo Fiber struct rebuilt from IDA KernelBase!CreateFiberEx
//
struct Fiber
{
	PVOID FiberData;
	struct _EXCEPTION_REGISTRATION_RECORD* ExceptionList;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID DeallocationStack;
	CONTEXT FiberContext;
	PVOID Wx86Tib;
	struct  _ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
	TEB_FLS_DATA* FlsData;
	ULONG GuaranteedStackBytes;
	ULONG TebFlags;
	uint64_t XoredCookie; // Xored stack based cookie, used as a sanity check when switching fibers in KernelBase!SwitchToFiber
	PVOID ShadowStack;
};

struct TidPid
{
	DWORD tid;
	DWORD pid;
};

struct FlsSlot
{
	DWORD index;
	uint64_t addrOfFlsSlotData; // This will exist either on the stack/heap.
	std::string locationofFlsSlotData; // heap||stackUninitialized||stackZeroInitialized||other. 
	SIZE_T flsSlotDataSize;
	DWORD flsSlotDataMemType;
	DWORD flsSlotDataMemState;
	DWORD flsSlotDataMemProt;
	double flsSlotDataEntropyScore;
	bool flsDataIsPtr = false; // Are the first 8 bytes in Fls data a valid ptr.
	DWORD flsDataPtrMemType;
	DWORD flsDataPtrMemState;
	DWORD flsDataPtrMemProt;
	std::string flsDataPtrModBaseName; // We only calculate this if ptr is stored in slot. Since FLS slot will always be stored on stack/heap depending on size.
	bool associatedCallbackFound = false; // If an associated callback found then FLS slot data will be used.
	uint64_t associatedCallback; // For attempted symbol resolution look in CallbackResult vector inside FiberResult.
};

struct MyFlsLinkedEntries
{
	DWORD pid;
	DWORD tid;
	std::vector<LIST_ENTRY*> flsListEntries;
};

struct CallbackTable
{
	DWORD pid;
	DWORD tid;
	std::vector<FLS_CALLBACK> callbackEntries; // Entries appear in order of index.
};

struct MyFiber
{
	PVOID addressOnHeap; // Address of Fiber Object on heap. This is _HEAP_ENTRY + 0x10 (heap entry header)
	PVOID ntHeapAddr; // Base Address of heap
	BOOL currentFiber; // Is this the currently executing fiber
	DWORD pid; // Owning pid
	DWORD tid; // Associated TID if available.
	SIZE_T flsDataSz;
	SIZE_T fiberDataSz;
	PVOID tibFiberDataValue; // address pointed to by ntdll!_NT_TIB FiberData value if available.
	Fiber fiberObject; // Associated fiber object from NTHeap
	std::vector<LIST_ENTRY*> flsListEntries; // Fiber->FlsData->fls_list_entry Points to LIST_ENTRY linked list. This linked list is shared between fibers running on the same thread.
													// Use this to detemine the TID of Dormant threads running in the same process.
	std::vector<FlsSlot> flsSlotVector;
	std::vector<FLS_CALLBACK> callbackEntries; // Callback entires.
};

struct CallbackResult
{
	DWORD index;
	uint64_t callback;
	DWORD callbackMemType;
	DWORD callbackMemProt;
	DWORD callbackMemState;
	bool callbackUnbackedMem = false;
	std::string callbackModBaseName;
	std::string callbackSymbol;
};

struct FiberResult
{
	DWORD pid;
	DWORD tid;
	std::string processName;
	uint64_t fiberDataAddr;
	bool fiberDataUnbackedMem = false;
	std::string fiberDataAddrModBaseName;
	DWORD fiberDataMemType;
	DWORD fiberDataMemProt;
	DWORD fiberDataMemState;
	double fiberDataEntropyScore;
	std::vector<CallbackResult> callbackResultVector;
	std::vector<FlsSlot> flsSlotVector;
};

// Used to identify currently running fibers and enrich MyFiber Objects.
struct FiberFromTeb
{
	DWORD pid;
	DWORD tid;
	TEB_FLS_DATA* tebFlsData;
	ULONG tebGuaranteedStackBytes;
	PVOID tebActivationContextStackPointer;
	PVOID tibStackBase;
	PVOID tibStackLimit;
	PVOID tibFiberData; // ntdll!_NT_TIB FiberData.
	PVOID tibFiberDataValue; // Address pointed to by ntdll!_NT_TIB FiberData.
};

struct HeapEntryMeta
{
	DWORD pid; // Owning PID
	PVOID ntHeapAddr; // Allocation base of the heap block belongs to
	uint64_t heapBlockAddr;
	uint16_t heapBlockSize;
	uint8_t flags;
	uint8_t unusedBytes;
	SIZE_T requestedBytes; // Value given to RtlAllocateHeap. Calculated from heapBlockSize - unusedBytes.
};

// Imported functions
// NTDLL
typedef NTSTATUS(NTAPI* _NtQueryInformationThread)(
	IN		HANDLE				ThreadHandle,
	IN		MY_THREADINFOCLASS	ThreadInformationClass,
	IN OUT	PVOID				ThreadInformation,
	IN		ULONG				ThreadInformationLength,
	OUT		PULONG				ReturnLength OPTIONAL
	);

_NtQueryInformationThread NtQueryInfoThread;

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
	IN	HANDLE				ProcessHandle,
	IN	PROCESSINFOCLASS	ProcessInformationClass,
	OUT	PVOID				ProcessInformation,
	IN	ULONG				ProcessInformationLength,
	OUT PULONG				ReturnLength OPTIONAL
	);

_NtQueryInformationProcess NtQueryInfoProcess;

// Kernel32
// If we can't initialize then we are running < Win10.
typedef LONG(NTAPI* _GetPackageFamilyName)(
	IN  HANDLE	ProcessHandle,
	OUT UINT32* packageFamilyNameLength,
	OUT PWSTR	packageFamilyName OPTIONAL
	);

_GetPackageFamilyName MyGetPackageFamilyName;

// Main funcs
void PrintHelp(char* name);
BOOL SetTokenPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL InitializeFuncs();
BOOL ListProcessThreads(std::vector<TidPid>& tidPidVector);
BOOL EnumFibersFromThreads(std::vector<TidPid>& tidPidVector, std::vector<MyFiber>& fibersVector);
BOOL GetFiberResults(std::vector<MyFiber>& fibersVector, std::vector<FiberResult>& fiberResultsVector);

// Secondary
void EnumCurrentlyExecutingFibers(std::vector<TidPid> tidPidVector, std::vector<FiberFromTeb>& myFiberFromTebVector, std::vector<HeapEntryMeta>& heapEntryMetaVector);
BOOL IsThreadUsingFibers(HANDLE& hProcess, THREAD_BASIC_INFORMATION& tbi);
BOOL EnumCurrentFiberFromTEB(HANDLE& hProcess, THREAD_BASIC_INFORMATION tbi, FiberFromTeb& fiberFromTeb);
BOOL EnumNtHeap(HANDLE& hProcess, std::vector<HeapEntryMeta>& heapEntryMetaVector);
void DecodeHeader(uint64_t encodeFlagMask, unsigned char encoding[16], uint64_t heapBlock);
BOOL IsNtHeapBlockAddr(std::vector<HeapEntryMeta> heapEntryMetaVector, uint64_t addr);
BOOL IsNtHeapPtr(HANDLE hProcess, LPVOID heapPtr, MEMORY_BASIC_INFORMATION& mbi);
void EnumFibersFromHeapBlocks(std::vector<HeapEntryMeta> heapEntryMetaVector, std::vector<MyFiber>& myFiberVector);
void EnrichMyFiberVector(std::vector<MyFiber>& myHeapFiberVector, std::vector<FiberFromTeb> myFiberFromTebVector, std::vector<HeapEntryMeta> heapEntryMetaVector);
void GetFlsLinkedEntries(MyFiber& myFiber, std::vector<MyFlsLinkedEntries>& myFlsLinkedEntiresVector);
void GetFls(std::vector<MyFiber>& myHeapFiberVector, std::vector<HeapEntryMeta> heapEntryMetaVector);
BOOL RemoteFlsGetValue(HANDLE hProcess, ULONG index, TEB_FLS_DATA fls, std::vector<HeapEntryMeta> heapEntryMetaVector, MyFiber& myFiber, FlsSlot& flsSlot);
void GetFlsValueSize(HANDLE& hProcess, MyFiber myFiber, std::vector<HeapEntryMeta> heapEntryMetaVector, FlsSlot& flsSlot);
static unsigned int GetFlsChunkSz(unsigned int chunk_index);
static unsigned int GetFlsChunkIndexFromIndex(unsigned int index, unsigned int* index_in_chunk);

// Analysis funcs
BOOL GetFiberDataMeta(HANDLE& hProcess, MyFiber myFiber, FiberResult& fiberResult);
BOOL GetCallbackMeta(HANDLE& hProcess, MyFiber myFiber, FiberResult& fiberResult);
BOOL GetFlsSlotsMeta(HANDLE& hProcess, MyFiber myFiber, FiberResult& fiberResult);
BOOL GetSymbol(HANDLE hProcess, DWORD64 addr, std::string& symbol);

// Util funcs
DWORD GetMaxFlsIndexValue();
BOOL IsInvalidPtr(PVOID ptr);
BOOL IsMemReadable(HANDLE& hProcess, PVOID addrToRead, MEMORY_BASIC_INFORMATION& mbi);
BOOL IsMemReadable(HANDLE& hProcess, PVOID addrToRead);
BOOL IsMemUnbacked(HANDLE& hProcess, PVOID addrToRead, std::string& moduleName);
SIZE_T GetRemainingRegionSize(PVOID currentAddress, MEMORY_BASIC_INFORMATION& mbi);
BOOL IsUwpProcess(HANDLE& hProcess);
void ValidateFiberObjects(std::vector<MyFiber> myHeapFiberVector, std::vector<HeapEntryMeta> heapEntryMetaVector, std::vector<MyFiber>& validFibers);
std::string GetModuleName(HANDLE& hProcess);

// Shannon entropy funcs
double Log2(double number);
double MyCalculateShannonEntropy(uint8_t* inputString, size_t inputStringSize);

// ResultsWriter funcs
void ToJson(json& j, const FiberResult& r);
BOOL ResultsWriter(const char* name, std::vector<FiberResult>& fiberResultVector);

// Unused funcs
BOOL IsMemPrivExeCommit(HANDLE& hProcess, PVOID addrToRead);


/*
* https://www.nobugs.org/developer/win32/debug_crt_heap.html#table
* https://en.wikipedia.org/wiki/Magic_number_(programming)#Debug_values
* 0xABABABAB : Used by Microsoft's HeapAlloc() to mark "no man's land" guard bytes after allocated heap memory
* 0xABADCAFE : A startup to this value to initialize all free memory to catch errant pointers
* 0xBAADF00D : Used by Microsoft's LocalAlloc(LMEM_FIXED) to mark uninitialised allocated heap memory
* 0xBADCAB1E : Error Code returned to the Microsoft eVC debugger when connection is severed to the debugger
* 0xBEEFCACE : Used by Microsoft .NET as a magic number in resource files
* 0xCCCCCCCC : Used by Microsoft's C++ debugging runtime library to mark uninitialised stack memory
* 0xCDCDCDCD : Used by Microsoft's C++ debugging runtime library to mark uninitialised heap memory
* 0xDDDDDDDD : Used by Microsoft's C++ debugging heap to mark freed heap memory
* 0xDEADDEAD : A Microsoft Windows STOP Error code used when the user manually initiates the crash.
* 0xFDFDFDFD : Used by Microsoft's C++ debugging heap to mark "no man's land" guard bytes before and after allocated heap memory
* 0xFEEEFEEE : Used by Microsoft's HeapFree() to mark freed heap memory
*/