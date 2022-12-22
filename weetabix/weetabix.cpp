#include "weetabix.h"

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(CallbackResult,
	index,
	callback,
	callbackMemType,
	callbackMemProt,
	callbackMemState,
	callbackUnbackedMem,
	callbackModBaseName,
	callbackSymbol)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(FlsSlot,
		index,
		addrOfFlsSlotData,
		flsSlotDataSize,
		flsSlotDataMemType,
		flsSlotDataMemState,
		flsSlotDataMemProt,
		flsSlotDataEntropyScore,
		flsDataIsPtr,
		flsDataPtrMemType,
		flsDataPtrMemState,
		flsDataPtrMemProt,
		flsDataPtrModBaseName,
		associatedCallbackFound,
		associatedCallback)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(FiberResult,
		pid,
		tid,
		processName,
		fiberDataAddr,
		fiberDataUnbackedMem,
		fiberDataAddrModBaseName,
		fiberDataMemType,
		fiberDataMemProt,
		fiberDataMemState,
		fiberDataEntropyScore,
		callbackResultVector,
		flsSlotVector)

void ToJson(json& j, const FiberResult& r)
{
	j = json{
		{"pid", r.pid},
		{"tid", r.tid},
		{"process_name", r.processName},
		{"fiber_data_address", r.fiberDataAddr},
		{"fiber_data_unbacked", r.fiberDataUnbackedMem},
		{"fiber_data_addr_module", r.fiberDataAddrModBaseName},
		{"fiber_data_mem_type", r.fiberDataMemType},
		{"fiber_data_mem_prot", r.fiberDataMemProt},
		{"fiber_data_mem_state", r.fiberDataMemState},
		{"fiber_data_entropy", r.fiberDataEntropyScore},
		{"fiber_callbacks", r.callbackResultVector},
		{"fiber_local_storage", r.flsSlotVector} };
}

//
// Prints a NDJSON file.
//
BOOL ResultsWriter(const char* name, std::vector<FiberResult>& fiberResultVector)
{
	printf("[+] Printing results\n");

	std::ofstream outputFile(name, std::ios::out | std::ios::trunc);

	if (outputFile.is_open())
	{
		for (const auto& fiberResult : fiberResultVector)
		{
			json j;
			ToJson(j, fiberResult);

			outputFile << j;
			outputFile << std::endl;
		}

		outputFile.close();
		return true;
	}
	else
	{
		return false;
	}
}

template<typename T>
BOOL foundInVector(std::vector<T> myVector, T item)
{
	if (std::find(myVector.begin(), myVector.end(), item) != myVector.end())
	{
		return true;
	}
	else
	{
		return false;
	}
}

//
// Borrowed from Will's code / Unknown cheats.
// https://www.unknowncheats.me/forum/c-and-c-/304873-checking-valid-pointer.html
//
BOOL IsInvalidPtr(PVOID ptr)
{
	static SYSTEM_INFO si = {};
	if (nullptr == si.lpMinimumApplicationAddress)
	{
		GetSystemInfo(&si);
	}

	return (((uint64_t)ptr < (uint64_t)si.lpMinimumApplicationAddress || (uint64_t)ptr >(uint64_t)si.lpMaximumApplicationAddress));
}

//
// Builds FiberResults vector using pseudo fiber struct.
// Adds meta-data to fiber data, callback and fls slot information.
//
BOOL GetFiberResults(std::vector<MyFiber>& fibersVector, std::vector<FiberResult>& fiberResultsVector)
{
	// Skip if no fibers found.
	if (fibersVector.empty())
	{
		printf("[+] No Fibers found!\n");
		return true;
	}
	else
	{
		printf("[+] %zu Fibers found\n", fibersVector.size());
		printf("[+] Building Fiber results\n");
	}

	HANDLE hProcess = NULL;
	for (const auto& myFiber : fibersVector)
	{
		hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, myFiber.pid);
		if (!hProcess)
		{
			continue;
		}

		// Required to resolve private symbols.
		if (!SymInitialize(hProcess, g_symPath.c_str(), TRUE))
		{
			printf("[!] SymInitialize failed\n");
			return false;;
		}

		// Start building our fiberResult
		FiberResult fiberResult = {};
		fiberResult.pid = myFiber.pid;
		fiberResult.tid = myFiber.tid;
		fiberResult.processName = GetModuleName(hProcess);

		GetFiberDataMeta(hProcess, myFiber, fiberResult);
		GetCallbackMeta(hProcess, myFiber, fiberResult);
		GetFlsSlotsMeta(hProcess, myFiber, fiberResult);

		fiberResultsVector.push_back(fiberResult);
		SymCleanup(hProcess);
	}

	return true;
}

BOOL InitializeFuncs()
{
	NtQueryInfoThread = (_NtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationThread");

	if (NtQueryInfoThread == NULL)
	{
		printf("[!] Failed to resolve NtQueryInformationThread\n");
		return false;
	}

	NtQueryInfoProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");

	if (NtQueryInfoProcess == NULL)
	{
		printf("[!] Failed to resolve NtQueryInformationProcess\n");
		return false;
	}

	MyGetPackageFamilyName = (_GetPackageFamilyName)GetProcAddress(GetModuleHandleA("kernel32"), "GetPackageFamilyName");

	if (MyGetPackageFamilyName == NULL)
	{
		printf("[!] Failed to resolve GetPackageFamilyName, implies we are running on version of Windows < 10\n");
		g_windowsVerBelow10 = true;
	}

	return true;
}

//
// https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getpackagefamilyname
// If we supply a 0 packageFamilyNameLength (2nd parameter) then attempting to get the package name of a UWP app will return ERROR_INSUFFICIENT_BUFFER.
// A non UWP app will return APPMODEL_ERROR_NO_PACKAGE.
//
BOOL IsUwpProcess(HANDLE& hProcess)
{
	uint32_t size = 0;
	LONG result;
	result = MyGetPackageFamilyName(hProcess, &size, NULL);

	if (result == ERROR_INSUFFICIENT_BUFFER)
	{
		return true;
	}

	return false;
}

//
// https://learn.microsoft.com/en-us/windows/win32/debug/retrieving-symbol-information-by-address
// Requires private symbols to resolve functions such as free_fls, destroy_fls etc.
// Hence we point SymInitialize to c:\symbols. 
//
BOOL GetSymbol(HANDLE hProcess, DWORD64 addr, std::string& symbol)
{
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;

	if (!SymFromAddr(hProcess, addr, 0, pSymbol))
	{
		printf("[-] Unable to resolve symbol\n");
		return false;
	}

	symbol = pSymbol->Name;

	return true;
}

//
// Attempts to add memory meta-data, backed module name and symbol name to fiber callbacks.
//
BOOL GetCallbackMeta(HANDLE& hProcess, MyFiber myFiber, FiberResult& fiberResult)
{
	int index = 0;
	CallbackResult callbackResult = {};
	MEMORY_BASIC_INFORMATION mbi = {};
	std::string backedModuleName;

	for (const auto& callbackEntry : myFiber.callbackEntries)
	{
		mbi = {};
		callbackResult = {};
		callbackResult.index = index;
		callbackResult.callback = (uint64_t)callbackEntry.callback;

		if (IsInvalidPtr(callbackEntry.callback))
		{
			printf("[-] Invalid callback address\n");
			goto Cleanup;
		}

		if (!IsMemReadable(hProcess, callbackEntry.callback, mbi))
		{
			printf("[-] Unable to read callback address\n");
		}

		callbackResult.callbackMemProt = mbi.Protect;
		callbackResult.callbackMemState = mbi.State;
		callbackResult.callbackMemType = mbi.Type;

		backedModuleName.clear();
		if (IsMemUnbacked(hProcess, callbackEntry.callback, backedModuleName))
		{
			callbackResult.callbackUnbackedMem = true;
		}
		else
		{
			// If backed add module and symbol info.
			callbackResult.callbackModBaseName = backedModuleName;
			GetSymbol(hProcess, (DWORD64)callbackEntry.callback, callbackResult.callbackSymbol);
		}

	Cleanup:
		fiberResult.callbackResultVector.push_back(callbackResult);
		index++;
	}

	return true;
}

//
// Iterates through FLS slot data to calculate memory meta-data and entropy score.
// A fls slot will always appear on either the stack (if small enough) or the Heap so no need to see if it backed.
// If the first 8 bytes of FLS slot data is a ptr follow this to collect the memory meta-data and if backed by a module.
//
BOOL GetFlsSlotsMeta(HANDLE& hProcess, MyFiber myFiber, FiberResult& fiberResult)
{
	MEMORY_BASIC_INFORMATION mbi = {};
	FlsSlot flsSlotResult = {};
	PVOID flsSlotDataBuff = NULL;
	size_t nBytesRead;
	int index;

	// Iterate through FLS slots
	// The flsSlot data could be in raw format OR a pointer to somewhere else in memory.
	// We expect FLS index 1 to point the error codes. in urc module.
	for (const auto& flsSlot : myFiber.flsSlotVector)
	{
		flsSlotResult = {};
		flsSlotResult = flsSlot; // Populate with already collected fields.

		// Collect memory prot,type,perm
		if (!IsMemReadable(hProcess, (PVOID)flsSlot.addrOfFlsSlotData, mbi))
		{
			printf("[-] Unable to read flsSlot.addrOfFlsSlotData\n");
			goto Cleanup;
		}

		flsSlotResult.flsSlotDataMemProt = mbi.Protect;
		flsSlotResult.flsSlotDataMemState = mbi.State;
		flsSlotResult.flsSlotDataMemType = mbi.Type;

		// Read FlsSlotData & generate entropy score.
		flsSlotDataBuff = calloc(1, flsSlot.flsSlotDataSize);
		if (!ReadProcessMemory(hProcess, (PVOID)flsSlot.addrOfFlsSlotData, flsSlotDataBuff, flsSlot.flsSlotDataSize, &nBytesRead))
		{
			printf("[-] ReadProcessMemory failed to read FiberData: %i\n", GetLastError());
			free(flsSlotDataBuff);
			goto Cleanup;
		}

		flsSlotResult.flsSlotDataEntropyScore = MyCalculateShannonEntropy((uint8_t*)flsSlotDataBuff, nBytesRead);
		free(flsSlotDataBuff);

		// Find associated callback address using matching index.
		index = 0;
		for (const auto& callback : myFiber.callbackEntries)
		{
			if (flsSlot.index == index)
			{
				flsSlotResult.associatedCallbackFound = true;
				flsSlotResult.associatedCallback = (uint64_t)callback.callback;
			}

			index++;
		}

		// Check first 8 bytes of FlsSlot data to see if it is a ptr.
		if (flsSlot.flsSlotDataSize >= 8)
		{
			PVOID flsDataPtr = NULL;

			// Read ptr
			if (!ReadProcessMemory(hProcess, (PVOID)flsSlot.addrOfFlsSlotData, &flsDataPtr, sizeof(PVOID), NULL))
			{
				printf("[-] ReadProcessMemory failed to read FlsDataPtr: %i\n", GetLastError());
				goto Cleanup;
			}

			if (!IsInvalidPtr(flsDataPtr))
			{
				flsSlotResult.flsDataIsPtr = true;

				// Try Read data it is pointing to and get memory prot/type/perms.
				if (!IsMemReadable(hProcess, flsDataPtr, mbi))
				{
					printf("[-] Unable to flsSlot Data ptr\n");
					continue;
					goto Cleanup;
				}

				flsSlotResult.flsDataPtrMemType = mbi.Type;
				flsSlotResult.flsDataPtrMemState = mbi.State;
				flsSlotResult.flsDataPtrMemProt = mbi.Protect;

				// Does this ptr point to a valid module
				std::string backedModuleName;
				if (!IsMemUnbacked(hProcess, flsDataPtr, backedModuleName))
				{
					flsSlotResult.flsDataPtrModBaseName = backedModuleName;
				}

			}
		}

	Cleanup:
		fiberResult.flsSlotVector.push_back(flsSlotResult);
	}

	return true;
}

//
// Since no FLS indexes have been allocated in the scanner this should generate the maximum index available for the current host
//
DWORD GetMaxFlsIndexValue()
{
	printf("[+] Getting max FLS Index value\n");

	DWORD result = 0;
	DWORD maxIndex = 0;
	UINT count = 0;

	while (result != FLS_OUT_OF_INDEXES)
	{
		result = FlsAlloc(NULL);
		count += 1;

		if (result != FLS_OUT_OF_INDEXES) {

			maxIndex = result;
		}
	}

	printf("[-] Max FLS Index value: %i\n", maxIndex);
	printf("[-] Out of available slots at attempt: %i\n", count);

	return maxIndex;
}

//
// Calculates the size of the FLS data.
// If FLS stored on the heap it uses HEAP_ENTRY block size to determine size.
// If FLS stored on the stack it will read the fiber object stack data up until an uninitialized value.
//
SIZE_T GetFlsValueSize(HANDLE& hProcess, MyFiber myFiber, PVOID addrInFlsSlot, std::vector<HeapEntryMeta> heapEntryMetaVector)
{
	// If FLS is stored in stack
	if ((addrInFlsSlot >= myFiber.fiberObject.StackLimit) && (addrInFlsSlot < myFiber.fiberObject.StackBase))
	{
		std::vector<uint64_t> fiberStackData = {};
		SIZE_T remainingStackSz = 0;
		SIZE_T maxElements = 0;
		int elementNumber = 0;

		remainingStackSz = (uint64_t)addrInFlsSlot - (uint64_t)myFiber.fiberObject.StackLimit;
		maxElements = (remainingStackSz / sizeof(uint64_t)) + 1;
		fiberStackData.resize(maxElements);

		// Read Stack for FiberObject.
		// Read from high->low memory. So stack limit (lowest address) towards our addrInFlsSlot (higher up in the stack).
		if (!ReadProcessMemory(hProcess, myFiber.fiberObject.StackLimit, fiberStackData.data(), maxElements * sizeof(uint64_t), NULL))
		{
			printf("[-] ReadProcessMemory failed to read stack: %i\n", GetLastError());
			return 0;
		}

		// Now iterate through until we get to 0xCCCCCCCC value to denote uninitialized stack memory and thus our end of FLS Slot stack data value.
		// Reverse iterator loop.
		for (std::vector<uint64_t>::reverse_iterator it = fiberStackData.rbegin(); it != fiberStackData.rend(); ++it) 
		{
			if (*it == 0xCCCCCCCCCCCCCCCC)
			{
				return elementNumber * sizeof(uint64_t);
			}
			elementNumber++;
		}


		// If we get here then we have encountered a Zero initialized stack and cannot determine FLS value size.
		// Cobalt strike Artifact kit zero initializes the stack values, so looking for 0xCCCCCCCC uninitialized stack memory doesn't work. 
			// Can this be used as a detection strategy amongst irregular fibers?? As the way the thread stack spoofing is implemented?


	}
	else // Check to see if it appears on the heap instead.
	{
		// Get heap entry & requested size.
		// If it sits within a heap entry, find its offset into the entry and determine the size.
		for (const auto& heapEntry : heapEntryMetaVector)
		{

			if (heapEntry.pid != myFiber.pid)
			{
				continue;
			}

			if (((uint64_t)addrInFlsSlot >= heapEntry.heapBlockAddr) && ((uint64_t)addrInFlsSlot <= (heapEntry.heapBlockAddr + heapEntry.heapBlockSize)))
			{
				// We have found the heap entry our FLS Slot data is located in.
				// Return size of the data.
				return (heapEntry.heapBlockAddr + heapEntry.heapBlockSize) - (uint64_t)addrInFlsSlot;
			}
		}
	}

	// We shouldn't arrive here. Because it means a FLS slot points to an address outside the stack or heap. 
		// Testing has revealed this can point directly to a module instead of the stack/heap. e.g. 0x00007ff811540100 - C:\Windows\System32\ucrtbase.dll
		// Thus this could be a function ptr.
	printf("[-] Strange FLS slot ptr. Not pointing to stack/heap!: 0x%llx\n", addrInFlsSlot);
	return 0;
}

BOOL IsMemReadable(HANDLE& hProcess, PVOID addrToRead, MEMORY_BASIC_INFORMATION& mbi)
{
	if (!VirtualQueryEx(hProcess, addrToRead, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		printf("[-] VirtualQueryEx Failed\n");
		return false;
	}

	if (!(mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE))
		return false;

	return true;
}

BOOL IsMemReadable(HANDLE& hProcess, PVOID addrToRead)
{
	MEMORY_BASIC_INFORMATION mbi;

	if (!VirtualQueryEx(hProcess, addrToRead, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		printf("[-] VirtualQueryEx Failed\n");
		return false;
	}

	if (!(mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE))
		return false;

	return true;
}

BOOL IsMemUnbacked(HANDLE& hProcess, PVOID addrToRead, std::string& moduleName)
{
	char mappedModuleName[MAX_PATH];
	if (!GetMappedFileNameA(hProcess, addrToRead, mappedModuleName, sizeof(mappedModuleName)))
	{
		return true;
	}

	moduleName = mappedModuleName;
	return false;
}

std::string GetModuleName(HANDLE& hProcess)
{
	char moduleName[MAX_PATH];
	if (!GetModuleFileNameExA(hProcess, 0, moduleName, sizeof(moduleName)))
	{
		printf("[-] Unable to get module name\n");
	}

	return moduleName;
}

SIZE_T GetRemainingRegionSize(PVOID currentAddress, MEMORY_BASIC_INFORMATION& mbi)
{
	uint64_t upperBounds = (uint64_t)mbi.BaseAddress + (uint64_t)mbi.RegionSize;
	uint64_t bytesRemaining = upperBounds - (uint64_t)currentAddress;

	return (SIZE_T)bytesRemaining;
}

// 
// Gets memory info, backed module & entropy of fiber data
//
BOOL GetFiberDataMeta(HANDLE& hProcess, MyFiber myFiber, FiberResult& fiberResult)
{
	PVOID fiberDataBuff = NULL;
	SIZE_T nBytesRead = 0;
	double entropyScore = 0;

	fiberResult.fiberDataAddr = (uint64_t)myFiber.fiberObject.FiberData;

	std::string backedModuleName;
	if (IsMemUnbacked(hProcess, myFiber.fiberObject.FiberData, backedModuleName))
	{
		fiberResult.fiberDataUnbackedMem = true;
		fiberResult.fiberDataAddrModBaseName = backedModuleName;
	}

	MEMORY_BASIC_INFORMATION mbi;
	if (!IsMemReadable(hProcess, myFiber.fiberObject.FiberData, mbi))
	{
		printf("[-] tibFiberData isn't readable\n");
		return false;
	}

	fiberResult.fiberDataMemType = mbi.Type;
	fiberResult.fiberDataMemProt = mbi.Protect;
	fiberResult.fiberDataMemState = mbi.State;

	// Read FiberData & generate entropy score.
	fiberDataBuff = calloc(1, myFiber.fiberDataSz);
	if (!ReadProcessMemory(hProcess, myFiber.fiberObject.FiberData, fiberDataBuff, myFiber.fiberDataSz, &nBytesRead))
	{
		printf("[-] ReadProcessMemory failed to read FiberData: %i\n", GetLastError());
		free(fiberDataBuff);
		return false;
	}

	fiberResult.fiberDataEntropyScore = MyCalculateShannonEntropy((uint8_t*)fiberDataBuff, nBytesRead);

	free(fiberDataBuff);
	return true;
}

//
// Decodes _HEAP_ENTRY's header to reveal heap block size
//
void DecodeHeader(uint64_t encodeFlagMask, unsigned char encoding[16], uint64_t heapBlock)
{
	unsigned char decodedFields[8];
	unsigned char encodedFields[8];

	// Decode the first few fields of the heapBlock so we can get correct Size, Flags & SmallTagIndex.
	//0:002 > dt ntdll!_HEAP_ENTRY
	//    + 0x000 PreviousBlockPrivateData : Ptr64 Void
	//    + 0x008 Size : Uint2B
	//    + 0x00a Flags : UChar
	//    + 0x00b SmallTagIndex : UChar
	//
	if (encodeFlagMask != NULL)
	{
		memcpy(encodedFields, (const void*)(heapBlock + 0x008), 8);

		for (int i = 0; i < 8; ++i)
		{
			decodedFields[i] = encodedFields[i] ^ encoding[i + 8];
		}

		memcpy((void*)(heapBlock + 0x008), decodedFields, 8);
	}
}

//
//  Function collects NT type Heap block entry meta-data by:
//  1. Reading heaps of NT type from the PEB
//  2. Decoding heap block headers to reveal size of heap block and determine the requested size given to RtlAllocateHeap function.
//
BOOL EnumNtHeap(HANDLE& hProcess, std::vector<HeapEntryMeta>& heapEntryMetaVector)
{
	PROCESS_BASIC_INFORMATION pbi = {};
	PEB peb = {};
	std::vector<PVOID> heapPtrVector = {};
	std::vector<MEMORY_BASIC_INFORMATION> mbiNtHeapsVector = {};
	uint32_t nHeaps = NULL;
	uint32_t maxHeaps = NULL;
	PVOID heapsPtr = NULL;

	// Get PEB
	NTSTATUS status = NtQueryInfoProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	if (!NT_SUCCESS(status))
	{
		printf("[-] NtQueryInfoProcess failed to collect ProcessBasicInformation\n");
		return false;
	}

	if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL))
	{
		printf("[-] ReadProcessMemory failed to read address of the PEB: %i\n", GetLastError());
		return false;
	}

	// Get Heap info.
	//0:002 > dt ntdll!_PEB
	//    + 0x0e8 NumberOfHeaps : Uint4B
	//    + 0x0ec MaximumNumberOfHeaps : Uint4B
	//    + 0x0f0 ProcessHeaps : Ptr64 Ptr64 Void
	nHeaps = (uint64_t)peb.Reserved9[16] & 0x00000000FFFFFFFF;  // NumberOfHeaps;
	maxHeaps = (uint64_t)peb.Reserved9[16] >> 32;               // MaximumNumberOfHeaps;
	heapsPtr = (PVOID*)peb.Reserved9[17];                       // ProcessHeaps;

	// Adjust of size of heapPtrVector to nHeaps elements.
	heapPtrVector.resize(nHeaps);

	// Read heap pointers
	if (!ReadProcessMemory(hProcess, heapsPtr, heapPtrVector.data(), sizeof(PVOID) * nHeaps, NULL))
	{
		printf("[-] ReadProcessMemory failed to read address heap pointers into heapPtrVector: %i\n", GetLastError());
		return false;
	}

	// Only collect NT type heaps.
	for (const auto& heapPtr : heapPtrVector)
	{
		MEMORY_BASIC_INFORMATION mbi = {};

		if (!IsNtHeapPtr(hProcess, heapPtr, mbi))
		{
			continue;
		}
		mbiNtHeapsVector.push_back(mbi);
	}

	if (mbiNtHeapsVector.empty())
	{
		printf("[-] No NT type heaps found\n");
		return false;
	}

	// Enumerate _HEAP_ENTRYs
	for (const auto& mbiNtHeap : mbiNtHeapsVector)
	{
		HeapEntryMeta heapEntryMeta = { 0 };

		unsigned char encoding[16];
		uint32_t encodeFlagMask = NULL;

		uint64_t heapBlock = NULL;
		uint64_t firstHeapBlockEntry = NULL;
		uint64_t firstHeapBlockEntryOffset = NULL;
		uint64_t currentHeapBlockEntryOffset = NULL;
		uint64_t heapBlockAddress = NULL;

		uint64_t requestedBytes = NULL;
		uint16_t heapBlockSize = NULL;
		uint16_t prevHeapBlockSize = NULL;
		uint8_t unusedBytes = NULL;
		uint8_t flags = NULL;

		void* heapBuffer = calloc(1, mbiNtHeap.RegionSize);

		if (!ReadProcessMemory(hProcess, mbiNtHeap.AllocationBase, heapBuffer, mbiNtHeap.RegionSize, NULL))
		{
			printf("[-] ReadProcessMemory failed to read heap: %i\n", GetLastError());
			free(heapBuffer);
			continue;
		}

		// Get the Encoding value and FlagMask from the heap header.
		// The EncodeFlagMask determines if heap entries are encoded:
		//    Encoded == 0x00100000
		//    Non-encoding == 0x00000000
		// 
		// The Encoding field can be use to decode _HEAP_ENTRY values.
		//0:002 > dt ntdll!_HEAP
		//    + 0x07c EncodeFlagMask : Uint4B
		//    + 0x080 Encoding : _HEAP_ENTRY
		//0:002 > ?? sizeof(_HEAP_ENTRY)
		//    unsigned int64 0x10
		memcpy(encoding, (const void*)((uint64_t)heapBuffer + 0x80), 16);
		memcpy(&encodeFlagMask, (const void*)((uint64_t)heapBuffer + 0x07c), 4);

		// Identify the first _HEAP_ENTRY block using _HEAP header
		//0:002 > dt ntdll!_HEAP
		//    + 0x040 FirstEntry : Ptr64 _HEAP_ENTRY
		memcpy(&firstHeapBlockEntry, (const void*)((uint64_t)heapBuffer + 0x040), 8);

		// Calculate the offset of the first _HEAP_ENTRY within heapBuffer.
		firstHeapBlockEntryOffset = firstHeapBlockEntry - (uint64_t)mbiNtHeap.AllocationBase;
		heapBlock = (uint64_t)heapBuffer + firstHeapBlockEntryOffset;

		// Loop through _HEAP_ENTRY blocks of an NTheap.
		// The region size equals the number of committed heap bytes.
		while (((firstHeapBlockEntry + currentHeapBlockEntryOffset) - (uint64_t)mbiNtHeap.AllocationBase) < mbiNtHeap.RegionSize)
		{
			// Decode encoded _HEAP_ENTRY
			DecodeHeader(encodeFlagMask, encoding, heapBlock);

			// Get HEAP_ENTRY Size, Flags, PreviousSize (PreviousBlockSize) & UnusedBytes.
			//  0:003 > dt _HEAP_ENTRY
			//    ntdll!_HEAP_ENTRY
			//    + 0x008 Size              : Uint2B
			//    + 0x00a Flags             : UChar
			//    + 0x00b SmallTagIndex     : UChar
			//    + 0x00c PreviousSize      : Uint2B
			//    + 0x00f UnusedBytes       : UChar
			memcpy(&heapBlockSize, (const void*)(heapBlock + 0x008), 2);
			memcpy(&flags, (const void*)(heapBlock + 0x00a), 1);
			memcpy(&prevHeapBlockSize, (const void*)(heapBlock + 0x00c), 2);
			memcpy(&unusedBytes, (const void*)(heapBlock + 0x00f), 1);

			// Size & PreviousSize need to be multiplied by the granularity which is:
			// 0x10 for x64.
			// 0x08 for x86.
			heapBlockSize *= Granulariy;
			prevHeapBlockSize *= Granulariy;

			// Then calculate the requested size in bytes. 
			// This will be the 3rd parameter given to ntdll!RtlAllocateHeap when creating a Fiber Object via CreateFiberEx & ConvertThreadToFiber/Ex API calls.
			requestedBytes = heapBlockSize - unusedBytes;
			heapBlockAddress = firstHeapBlockEntry + currentHeapBlockEntryOffset;

			/*
			printf("Address:            0x0000%llx\n", heapBlockAddress);
			printf("Heap Block Size:    0x%x\n", heapBlockSize);
			printf("Previous   Size:    0x%x\n", prevHeapBlockSize);
			printf("Flags:              0x%x\n", flags);
			printf("Requested bytes:    0x%x\n\n", requestedBytes);
			*/

			// Save _HEAP_ENTRY info.
			heapEntryMeta.pid = (DWORD)pbi.UniqueProcessId;
			heapEntryMeta.ntHeapAddr = mbiNtHeap.AllocationBase;
			heapEntryMeta.heapBlockAddr = heapBlockAddress;
			heapEntryMeta.heapBlockSize = heapBlockSize;
			heapEntryMeta.flags = flags;
			heapEntryMeta.unusedBytes = unusedBytes;
			heapEntryMeta.requestedBytes = requestedBytes;
			heapEntryMetaVector.push_back(heapEntryMeta);

			currentHeapBlockEntryOffset += heapBlockSize;
			heapBlock += heapBlockSize;
		}
		free(heapBuffer);
	}

	return true;
}

//
// Always include current fiber as a valid fiber.
// 
// Then checks remaining dormant fibers to see if FLS pointer within pseudo fiber object points to an expected location i.e. a heap entry.
// Ignores dormant fiber objects that don't comply with this logic.
// 
// NOTE: The CS Artifact kit doesn't have a FLS data ptr for the current fiber.
//
void ValidateFiberObjects(std::vector<MyFiber> myHeapFiberVector, std::vector<HeapEntryMeta> heapEntryMetaVector, std::vector<MyFiber>& validFibers)
{

	for (auto& myFiber : myHeapFiberVector)
	{
		// Condition 1: Always add the current fiber (from the TEB).
		if (myFiber.currentFiber)
		{
			validFibers.push_back(myFiber);
			continue;
		}

		// Condition 2: A fiber objects FiberObject.FlsData should always point to a heapEntry address just after the header (sizeof header == 0x10):
			// myFiber.fiberObject.FlsData should always == (heapEntryMeta.heapBlockAddr + 0x10) 
		for (const auto& heapEntryMeta : heapEntryMetaVector)
		{
			// Match up the correct heaps
			if ((myFiber.pid == heapEntryMeta.pid) && (myFiber.ntHeapAddr == heapEntryMeta.ntHeapAddr))
			{
				if ((uint64_t)myFiber.fiberObject.FlsData == (heapEntryMeta.heapBlockAddr + 0x10))
				{
					// Add to valid vector fiber objects.
					validFibers.push_back(myFiber);
				}
			}
		}
	}
}

//
// Looks for heap entries with a requested block size allocation of 0x530 bytes as potential FiberObjects
//
void EnumFibersFromHeapBlocks(std::vector<HeapEntryMeta> heapEntryMetaVector, std::vector<MyFiber>& myFiberVector)
{
	HANDLE hProcess = NULL;
	for (const auto& heapEntryMeta : heapEntryMetaVector)
	{
		// KernelBase!CreateFiberEx - RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, KernelBaseGlobalData, 0x530ui64);
		if (heapEntryMeta.requestedBytes == 0x530)
		{
			hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, heapEntryMeta.pid);
			if (!hProcess)
			{
				continue;
			}

			// Skip first 0x10 bytes due to _HEAP_ENTRY header.
			MyFiber myHeapFiber = { 0 };
			if (!ReadProcessMemory(hProcess, (PVOID)(heapEntryMeta.heapBlockAddr + 0x10), &myHeapFiber.fiberObject, sizeof(Fiber), NULL))
			{
				printf("[-] ReadProcessMemory failed to Fiber from heap entry: %i\n", GetLastError());
				continue;
			}

			// Initialize rest of fields where possible.
			myHeapFiber.currentFiber = false;
			myHeapFiber.pid = heapEntryMeta.pid;
			myHeapFiber.addressOnHeap = (PVOID)(heapEntryMeta.heapBlockAddr + 0x10);
			myHeapFiber.ntHeapAddr = heapEntryMeta.ntHeapAddr;
			myFiberVector.push_back(myHeapFiber);
			CloseHandle(hProcess);
		}
	}
}

//
// Collects information of the current fiber from the TEB & TIB
//
BOOL EnumCurrentFiberFromTEB(HANDLE& hProcess, THREAD_BASIC_INFORMATION tbi, FiberFromTeb& fiberFromTeb)
{
	TEB teb = { 0 };
	if (!ReadProcessMemory(hProcess, tbi.TebBaseAddress, &teb, sizeof(TEB), NULL))
	{
		printf("[-] ReadProcessMemory failed to read TEB: %i\n", GetLastError());
		return false;
	}

	//0:002 > dt ntdll!_TEB
	//    + 0x000 NtTib            : _NT_TIB
	//0:002 > dt ntdll!_NT_TIB
	//    +0x008 StackBase  : Ptr64 Void == teb.Reserved1[1]
	//	  +0x010 StackLimit : Ptr64 Void == teb.Reserved1[2]
	//    +0x020 FiberData  : Ptr64 Void == teb.Reserved1[4]
	fiberFromTeb.tibStackBase = teb.Reserved1[1];
	fiberFromTeb.tibStackLimit = teb.Reserved1[2];
	fiberFromTeb.tibFiberData = teb.Reserved1[4];

	// Address pointed to by the ntdll!_NT_TIB FiberData value
	PVOID tibFiberDataValue = NULL;
	if (!ReadProcessMemory(hProcess, teb.Reserved1[4], &tibFiberDataValue, sizeof(PVOID), NULL))
	{
		printf("[-] ReadProcessMemory failed to read tibFiberDataValue: %i\n", GetLastError());
		return false;
	}
	fiberFromTeb.tibFiberDataValue = tibFiberDataValue;

	// Get Fiber related fields from the TEB
	//0:002 > dt ntdll!_TEB
	//	+0x2c8 ActivationContextStackPointer : Ptr64 _ACTIVATION_CONTEXT_STACK
	//	+0x1748 GuaranteedStackBytes : Uint4B
	//  +0x17c8 FlsData : Ptr64 Void
	PVOID tebFlsData = NULL;
	if (!ReadProcessMemory(hProcess, (LPCVOID)((uint64_t)tbi.TebBaseAddress + TebOffset_FlsData), &tebFlsData, sizeof(PVOID), NULL))
	{
		printf("[-] ReadProcessMemory Failed to read TebOffset_FlsData: %i\n", GetLastError());
		return false;
	}

	PVOID tebActivationContextStackPointer = NULL;
	if (!ReadProcessMemory(hProcess, (LPCVOID)((uint64_t)tbi.TebBaseAddress + TebOffset_ActivationContextStackPointer), &tebActivationContextStackPointer, sizeof(PVOID), NULL))
	{
		printf("[-] ReadProcessMemory Failed to read TebOffset_ActivationContextStackPointer: %i\n", GetLastError());
		return false;
	}

	ULONG tebGuaranteedStackBytes = NULL;
	if (!ReadProcessMemory(hProcess, (LPCVOID)((uint64_t)tbi.TebBaseAddress + TebOffset_GuaranteedStackBytes), &tebGuaranteedStackBytes, sizeof(ULONG), NULL))
	{
		printf("[-] ReadProcessMemory Failed to read TebOffset_GuaranteedStackBytes: %i\n", GetLastError());
		return false;
	}

	fiberFromTeb.tebFlsData = (TEB_FLS_DATA*)tebFlsData;
	fiberFromTeb.tebActivationContextStackPointer = tebActivationContextStackPointer;
	fiberFromTeb.tebGuaranteedStackBytes = tebGuaranteedStackBytes;

	return true;
}

//
// Uses SameTebFlags to determine if a thread is running fibers.
// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/teb/sametebflags.htm
//
BOOL IsThreadUsingFibers(HANDLE& hProcess, THREAD_BASIC_INFORMATION& tbi)
{
	SIZE_T nBytesRead = 0;
	USHORT sameTebFlags = 0; // SameTebFlags is a bit mask that can be used to determine if a thread is running fibers.

	if (!ReadProcessMemory(hProcess, (LPCVOID)((uint64_t)tbi.TebBaseAddress + TebOffset_SameTebFlags), &sameTebFlags, sizeof(USHORT), &nBytesRead))
	{
		printf("[-] ReadProcessMemory failed to read SameTebFlags: %i\n", GetLastError());
		return false;
	}

	if (!(sameTebFlags & HasFiberDataMask))
	{
		return false; // Thread isn't using fibers
	}

	return true;
}

//
// Enumerates currently running fibers
// Also collects list of NT heap block entries for processes with threads running fibers.
//
void EnumCurrentlyExecutingFibers(std::vector<TidPid> tidPidVector, std::vector<FiberFromTeb>& myFiberFromTebVector, std::vector<HeapEntryMeta>& heapEntryMetaVector)
{
	std::vector<DWORD> pidsScanned = {};
	DWORD scannerPid = NULL;
	scannerPid = GetCurrentProcessId();

	for (const auto& tidPid : tidPidVector)
	{
		NTSTATUS status = STATUS_SUCCESS;
		THREAD_BASIC_INFORMATION tbi = { 0 };
		FiberFromTeb fiberFromTeb = { 0 }; // This is the currently scheduled fiber on a thread.
		HANDLE hProcess = NULL;
		HANDLE hThread = NULL;
		BOOL wow64Process = false;

		// Skip system PID && self.
		if ((tidPid.pid == 4) || (tidPid.pid == scannerPid))
			continue;

		// Get Handles to the thread and owning process.
		hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, tidPid.pid);
		if (!hProcess)
		{
			goto Cleanup;
		}

		// Skip UWP apps since they use the 'Segment' type heap as opposed to the 'NT' type heap.
		// TODO : add 'Segment' type heap enumeration in future version.
		if (IsUwpProcess(hProcess))
		{
			continue;
		}

		// Skip WOW64 processes.
		IsWow64Process(hProcess, &wow64Process);
		if (wow64Process)
		{
			continue;
		}

		hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tidPid.tid);
		if (!hThread)
		{
			goto Cleanup;
		}

		// Get TEB
		status = NtQueryInfoThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
		if (status != STATUS_SUCCESS)
		{
			goto Cleanup;
		}

		// Skip if thread isn't running fibers.
		if (!IsThreadUsingFibers(hProcess, tbi))
		{
			goto Cleanup;
		}

		// Get currently running fiber info from TEB
		if (!EnumCurrentFiberFromTEB(hProcess, tbi, fiberFromTeb))
		{
			goto Cleanup;
		}

		fiberFromTeb.pid = tidPid.pid;
		fiberFromTeb.tid = tidPid.tid;
		myFiberFromTebVector.push_back(fiberFromTeb);

		// Only run once for each PID since heaps are kept /process not /thread.
		// We need this to find any dormant fibers sitting on the heap.
		if (!foundInVector(pidsScanned, tidPid.pid))
		{
			if (!EnumNtHeap(hProcess, heapEntryMetaVector))
			{
				printf("[-] Unable to enumerate or find NT heap for process running fibers using pid: %i\n", tidPid.pid);
			}

			pidsScanned.push_back(tidPid.pid);

		}

		// Cleanup handles for each Thread and owning process.
	Cleanup:
		if (hThread != NULL)
		{
			CloseHandle(hThread);
		}

		if (hProcess != NULL)
		{
			CloseHandle(hProcess);
		}
	}
}

//
// A Fiber object->FlsData point will point to a LIST_ENTRY linked list.
// Fibers running on the same thread will have their own LIST_ENTRY within the same shared linked list. 
// This function:
// 1. Enumerates the LINKED_ENTRIES * linked list until it circles back on itself, then stores this in a vector of LIST_ENTRY ptrs.
// 2. Creates a master list of LINKED_ENTRIES * which is later used to determine TIDs for dormant fibers on heap 
//		As dormant fibers have no tid reference in their heap fiber object, but the currently executing fibers which share the same LIST_ENTRY linked list will do (since it has been added from the TEB during previous enrichment)
//
void GetFlsLinkedEntries(MyFiber& myFiber, std::vector<MyFlsLinkedEntries>& myFlsLinkedEntiresVector)
{
	HANDLE hProcess = NULL;
	TEB_FLS_DATA flsData = {};
	LIST_ENTRY flsListHead = {};
	std::vector<LIST_ENTRY*> listEntryVector = {};

	// Check Fls Data for null value. As CS doesn't assign FLS data inside the artifact kit when using thread stack spoofing.
	if (myFiber.fiberObject.FlsData == NULL)
	{
		printf("[!] FlsData value == NULL for tid: %i. Not expected fiber behaviour!\n", myFiber.tid);
		return;
	}

	// Open process. 
	hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, myFiber.pid);
	if (!hProcess)
	{
		printf("[-] Failed to open process handle for pid: %i\n", myFiber.pid);
		return;
	}

	if (!ReadProcessMemory(hProcess, myFiber.fiberObject.FlsData, &flsData, sizeof(flsData), NULL))
	{
		printf("[-] ReadProcessMemory failed to read fls data: %i\n", GetLastError());
	}


	// pfls_list_head = flsData.fls_list_entry.Flink;
	if (!ReadProcessMemory(hProcess, flsData.flsListEntry.Flink, &flsListHead, sizeof(flsListHead), NULL))
	{
		printf("[-] ReadProcessMemory failed to read fls_list_head->Flink:%i\n", GetLastError());
	}

	while (true)
	{
		if (foundInVector(listEntryVector, flsListHead.Flink))
		{
			break;
		}

		listEntryVector.push_back(flsListHead.Flink);

		if (!ReadProcessMemory(hProcess, flsListHead.Flink, &flsListHead, sizeof(flsListHead), NULL))
		{
			printf("[-] ReadProcessMemory failed to read fls_list_head->Flink:%i\n", GetLastError());
		}
	}

	// Save complete LIST_ENTRY linked list to fiber object
	myFiber.flsListEntries = listEntryVector;
	
	// If a fiber object has been generated from TEB & TIB (i.e. a currently scheduled fiber) then it will have a TID associated with it.
	// Save the complete LIST_ENTRY linked list to a master list.
	// This list is later used to match up dormant fibers (found on the heap without a TID) with current fibers and their TID by matching the shared LIST_ENTRY linked lists.
	// If for whatever reason FlsData is NULL (CS artifact kit does this) then we won't be able to collect the LIST_ENTRY and match up dormant fibers.
	if (myFiber.tid != NULL)
	{
		// There should only be one of these/thread since only one fiber runs at a time.
		MyFlsLinkedEntries myFlsLinkedEntries = {};
		myFlsLinkedEntries.pid = myFiber.pid;
		myFlsLinkedEntries.tid = myFiber.tid;
		myFlsLinkedEntries.flsListEntries = listEntryVector;
		myFlsLinkedEntiresVector.push_back(myFlsLinkedEntries);
	}

	CloseHandle(hProcess);
}


//
// 1. Identifies which fiber object on heap belongs to currently scheduled fibers and enriches it with data from TEB & TIB
// 2. Calculates the number of bytes allocated to Fiber Local Storage (FLS) for each fiber object.
// 3. Enumerates FLS LIST_ENTRY linked lists and uses them to associate dormant fibers with correct TIDs from currently scheduled fibers LIST_ENTRY linked lists.
//
void EnrichMyFiberVector(std::vector<MyFiber>& myHeapFiberVector, std::vector<FiberFromTeb> myFiberFromTebVector, std::vector<HeapEntryMeta> heapEntryMetaVector)
{
	// Enrich heap entries of currently running fibers with data from TEB & TIB.
	for (auto& myFiber : myHeapFiberVector)
	{
		for (const auto& fiberFromTeb : myFiberFromTebVector)
		{
			if ((fiberFromTeb.pid == myFiber.pid) && (fiberFromTeb.tibFiberData == myFiber.addressOnHeap))
			{
				myFiber.currentFiber = true;
				myFiber.tid = fiberFromTeb.tid;

				myFiber.fiberObject.FlsData = fiberFromTeb.tebFlsData; // FlsData -0x10 are heap address allocations.
				myFiber.fiberObject.GuaranteedStackBytes = fiberFromTeb.tebGuaranteedStackBytes;
				myFiber.fiberObject.ActivationContextStackPointer = (ACTIVATION_CONTEXT_STACK*)fiberFromTeb.tebActivationContextStackPointer;

				myFiber.fiberObject.StackBase = fiberFromTeb.tibStackBase;
				myFiber.fiberObject.StackLimit = fiberFromTeb.tibStackLimit;
				myFiber.fiberObject.FiberData = fiberFromTeb.tibFiberData; // FiberData - 0x10 are heap address allocations.
				myFiber.tibFiberDataValue = fiberFromTeb.tibFiberDataValue;
			}
		}
	}

	// Each fiber has its own FiberData & FiberLocalStorage (FLS) heap entry. Use the HeapEntryMeta to determine the size allocated.
	for (auto& myFiber : myHeapFiberVector)
	{
		for (const auto& heapEntryMeta : heapEntryMetaVector)
		{
			// Match up the correct heaps
			if ((myFiber.pid == heapEntryMeta.pid) && (myFiber.ntHeapAddr == heapEntryMeta.ntHeapAddr))
			{

				// Found the heap entry allocated to a Fiber's FLS
				if (((uint64_t)myFiber.fiberObject.FlsData - 0x10) == heapEntryMeta.heapBlockAddr)
				{
					myFiber.flsDataSz = heapEntryMeta.requestedBytes;
				}

				if (((uint64_t)myFiber.fiberObject.FiberData - 0x10) == heapEntryMeta.heapBlockAddr)
				{
					myFiber.fiberDataSz = heapEntryMeta.requestedBytes;
				}

			}
		}
	}


	// Use FLS_DATA LINKED_LIST to associate fibers running on the same thread. 
	// Dormant fibers can't associate themselves with the current TEB/TIB unlike currently scheduled fibers.
	// However dormant and current fibers started on the same thread will share the same LIST_ENTRY linked list.
	// Looking for matching linked lists between dormant and currently scheduled fibers allows one to identify what a dormant fibers TID would be when switched to through when using KernelBase!SwitchToFiber
	std::vector<MyFlsLinkedEntries> myFlsLinkedEntiresVector = {};

	for (auto& myFiber : myHeapFiberVector)
	{
		GetFlsLinkedEntries(myFiber, myFlsLinkedEntiresVector);
	}

	// Fix-up TID of dormant fibers using flsLinkedEntries
	// NOTE: This will not work if FLS data value is invalid because there is no ptr to LINK_LIST entries.
	for (auto& myFlsLinkedEntires : myFlsLinkedEntiresVector)
	{
		for (auto& myFiber : myHeapFiberVector)
		{
			// Only fix-up dormant fiberObjects as running fibers will have TID already populated.
			if (myFiber.tid == 0) {

				// myFiber.flsListEntries.at(0) - We only need one LIST_ENTRY* to match since they all share the same linked list, just start at different initial positions/fiber
				if (foundInVector(myFlsLinkedEntires.flsListEntries, myFiber.flsListEntries.at(0)))
				{
					myFiber.tid = myFlsLinkedEntires.tid;
				}
			}
		}
	}
}

//
//  Takes a list of TIDs (From a snapshot) to:
//  1. Determine threads with currently running fibers.
//  2. Enumerate the process heaps of those threads to find dormant fibers.
//  2. Collects Fiber local storage for each fiber (including dormant ones).
//  3. Collect fiber local storage callbacks for each fiber (including dormant ones).
//
BOOL EnumFibersFromThreads(std::vector<TidPid>& tidPidVector, std::vector<MyFiber>& fibersVector)
{
	printf("[+] Enumerating Fibers from Threads\n");

	std::vector<HeapEntryMeta> heapEntryMetaVector;
	std::vector<FiberFromTeb> myFiberFromTebVector;
	std::vector<MyFiber> myHeapFiberVector;
	std::vector<MyFiber> validFibers;

	// Enumerates currently running fibers
	// Also collect list of NT heap block entries for processes with threads running fibers.
	EnumCurrentlyExecutingFibers(tidPidVector, myFiberFromTebVector, heapEntryMetaVector);

	// Enumerate Fibers from process heap blocks.
	EnumFibersFromHeapBlocks(heapEntryMetaVector, myHeapFiberVector);

	// Enrich fiber objects with meta-data
	EnrichMyFiberVector(myHeapFiberVector, myFiberFromTebVector, heapEntryMetaVector);

	// From this point onwards fibers from Windows store apps & those stored on the Segment Heap are ignored.

	// Enumerate FLS & callbacks. 
		// Index numbers will start at 0 for the first fiber/thread and then increase by one for every other FLS slot/thread regardless. 
		// So for instance if the first fiber has 5 FLS slots, then the second fiber's first FLS slot will start at index 6.
	GetFls(myHeapFiberVector, heapEntryMetaVector);

	// Perform some basic validation
	ValidateFiberObjects(myHeapFiberVector, heapEntryMetaVector, validFibers);

	fibersVector = validFibers;
	return true;
}

//
// Takes snapshot of TIDs and owning PIDs.
//
BOOL ListProcessThreads(std::vector<TidPid>& tidPidVector)
{
	printf("[+] Taking a snapshot of running Threads\n");

	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32 = {};

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hThreadSnap, &te32))
	{
		printf("[-] Thread32First failed\n");
		CloseHandle(hThreadSnap);
		return FALSE;
	}

	do
	{
		TidPid tidPid = {};
		tidPid.tid = te32.th32ThreadID;
		tidPid.pid = te32.th32OwnerProcessID;
		tidPidVector.push_back(tidPid);

	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return TRUE;
}

//
// https://learn.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c
//
BOOL SetTokenPrivilege(
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	HANDLE hProcess;
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	hProcess = GetCurrentProcess();

	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		printf("[-] OpenProcessToken failed\n");
		return FALSE;
	}

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("[-] LookupPrivilegeValue failed\n");
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("[-] AdjustTokenPrivileges failed\n");
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("[-] The token does not have the specified privilege\n");
		return FALSE;
	}

	CloseHandle(hProcess);
	return TRUE;
}

double Log2(double number) {
	return log(number) / log(2);
}

//
// Generate an entropy score. 
// Based on - https://rosettacode.org/wiki/Entropy#C++
// For random data, the Shannon entropy value is 1 for ordered data the value is 0.
	//  - 0 represents no randomness(i.e. All the bytes in the data have the same value) whereas 8, the maximum, represents a completely random string.
	//	- Standard English text usually falls somewhere between 3.5 and 5.
	//	- Properly encrypted or compressed data of a reasonable length should have an entropy of over 7.5.
//
double MyCalculateShannonEntropy(uint8_t* inputString, size_t inputStringSize) {

	if (inputStringSize == 0)
	{
		printf("[!] Input string size given to MyCalculateShannonEntropy == 0\n");
		return 0;
	}

	std::map<uint8_t, size_t> frequencies;
	for (size_t i = 0; i >= inputStringSize; i++)
	{
		uint8_t c = inputString[i];
		frequencies[c] ++;
	}
	size_t numlen = inputStringSize;
	double infocontent = 0;
	for (std::pair<uint8_t, size_t> p : frequencies)
	{
		double freq = static_cast<double>(p.second) / numlen;
		infocontent -= freq * Log2(freq);
	}

	return infocontent;
}

//
// Passes back memory basic information structure if heap of NT type.
//
BOOL IsNtHeapPtr(HANDLE hProcess, LPVOID heapPtr, MEMORY_BASIC_INFORMATION& mbi)
{
	SIZE_T result;
	uint32_t segmentSignature = 0;

	if (heapPtr == NULL)
	{
		return false;
	}

	result = VirtualQueryEx(hProcess, heapPtr, &mbi, sizeof(mbi));
	if (result != sizeof(mbi))
	{
		return false;
	}

	// Check if protections and state correspond match those of expected heapPtr
	// RtlAllocateHeap only accepts a handle from a private heap which has been created by RtlCreateHeap.
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateheap
	// Although NT heaps of Type == MEM_MAPPED exist fiber objects will not reside here, so skip.
	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
	if (!((mbi.State == MEM_COMMIT) && (mbi.Type == MEM_PRIVATE) && (mbi.Protect == PAGE_READWRITE)))
	{
		printf("[-] Skipped NTHeap of Type:MEM_MAPPED. Only interested in Type:MEM_PRIVATE\n");
		return false;
	}

	// Read segment signature of heap from _HEAP Header
	// dt ntdll!_HEAP
	// 0:002> dt ntdll!_HEAP
	//    + 0x000 Segment           : _HEAP_SEGMENT
	//    + 0x000 Entry             : _HEAP_ENTRY
	//    + 0x010 SegmentSignature  : Uint4B
	if (!ReadProcessMemory(hProcess, (LPCVOID)((uint64_t)heapPtr + 0x010), &segmentSignature, sizeof(uint32_t), NULL))
	{
		printf("[-] ReadProcessMemory failed to read heapPtr: %i\n", GetLastError());
		return false;
	}

	if (segmentSignature == SegmentHeap)
	{
		printf("[-] Fiber using Segment type heap, skipping\n");
		return false;
	}

	if (segmentSignature != NtHeap)
	{
		printf("[-] Fiber using unknown heap type, skipping\n");
		return false;
	}

	return true;
}

BOOL IsNtHeapBlockAddr(std::vector<HeapEntryMeta> heapEntryMetaVector, uint64_t addr)
{
	for (const auto heapEntryMeta : heapEntryMetaVector)
	{
		if (heapEntryMeta.heapBlockAddr == addr)
		{
			return true;
		}
	}

	return false;
}

//
// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/thread.c#L485
// 
static unsigned int GetFlsChunkSz(unsigned int chunk_index)
{
	return 0x10 << chunk_index;
}

// 
// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/thread.c#L495
//
static unsigned int GetFlsChunkIndexFromIndex(unsigned int index, unsigned int* index_in_chunk)
{
	unsigned int chunk_index = 0;

	while (index >= GetFlsChunkSz(chunk_index))
	{
		index -= GetFlsChunkSz(chunk_index++);
	}

	*index_in_chunk = index;
	return chunk_index;
}

//
// A modified reimplementation of ntdll!RtlFlsGetValue but that works with remote fibers.
// Returns true if valid FLS slot for fiber & index number is found.
//
BOOL RemoteFlsGetValue(HANDLE hProcess, ULONG index, TEB_FLS_DATA fls, std::vector<HeapEntryMeta> heapEntryMetaVector, MyFiber& myFiber, FlsSlot& flsSlot)
{
	unsigned int chunkIndex = 0;
	unsigned int idx = 0;
	PVOID pChunk = NULL;
	PVOID pFlsSlotData = NULL;
	PVOID flsSlotData = NULL;
	SIZE_T chunkSz = 0;
	SIZE_T flsSlotDataSize = 0;
	std::vector<PVOID> chunkBuff = {};

	chunkIndex = GetFlsChunkIndexFromIndex(index, &idx);
	pChunk = fls.flsDataChunks[chunkIndex];
	chunkSz = sizeof(PVOID) * (idx + 2);
	chunkBuff.resize(idx + 2);

	// Only continue if the pChunk is readable
	if ((!IsMemReadable(hProcess, pChunk)) || pChunk == NULL)
	{
		return false;
	}

	if (!ReadProcessMemory(hProcess, pChunk, chunkBuff.data(), chunkSz, NULL))
	{
		printf("[-] ReadProcessMemory failed :%i\n", GetLastError());
		return false;
	}

	pFlsSlotData = chunkBuff[idx + 1];
	if ((!IsMemReadable(hProcess, pFlsSlotData)) || pFlsSlotData == NULL)
	{
		return false;
	}

	// printf("ptr to FLS slot number:%i at address:%p\n", idx, pFlsSlotData);

	flsSlotDataSize = GetFlsValueSize(hProcess, myFiber, pFlsSlotData, heapEntryMetaVector);

	flsSlot.flsSlotDataSize = flsSlotDataSize;
	flsSlot.index = idx;
	flsSlot.addrOfFlsSlotData = (uint64_t)pFlsSlotData;

	return true;
}

// 
// Collects Fiber Local Storage slots data and callback table:
// 1. Enumerating a fibers FLS LIST_ENTRY linked list to populate the GLOBAL_FLS_DATA struct.
// 2. Looks for a valid flsCallbackChunk within each GLOBAL_FLS_DATA struct that points to a callback table.
// 3. Only one callback table exists / thread.
//
void GetFlsCallbackTable(HANDLE& hProcess, MyFiber& myFiber, std::vector<HeapEntryMeta> heapEntryMetaVector, ULONG index, std::vector<CallbackTable>& callbackTableVector)
{
	// When a fiber exits it terminates the thread. Fiber callbacks are called.
	// If a fiber calls DeleteFiber on another fiber this is undefined behavior.
	// FLS slots indexes correspond to an equivalent callback table index number.

	// Search a list of already enumerated threads & their FLS callback tables first before searching again. 
	// Add to fiber object if already found.
	for (const auto& callbackTable : callbackTableVector)
	{
		if (myFiber.pid == callbackTable.pid && callbackTable.tid == myFiber.tid)
		{
			// Callback table won't always be associated with a slot index, hence we want to record both.
			myFiber.callbackEntries = callbackTable.callbackEntries;
			return;
		}

	}

	// One flsListEntry(LIST_ENTRY)/Thread will contain a flsCallback chunk that points to the callback table.
	// The callback table will be stored in its own individual heap block entry.
	for (const auto& flsListEntry : myFiber.flsListEntries)
	{
		GLOBAL_FLS_DATA globalFlsData = {};
		std::vector<FLS_CALLBACK> callbackEntries = {};
		ULONG nCallbackEntries = 0;
		PVOID pCallbackTable = NULL;
		unsigned int chunkIndex = 0;
		unsigned int idx = 0;

		/*
		* Populate GLOBAL_FLS_DATA struct.
		* flsListEntry == flsListHead, so minus 0x40 to account for flsCallbackChunks[8].
		*
		* typedef struct GLOBAL_FLS_DATA
		{
			FLS_INFO_CHUNK* flsCallbackChunks[8];
			LIST_ENTRY      flsListHead;
			ULONG           flsHighIndex;
		}
		*
		typedef struct LIST_ENTRY
		{
			struct _LIST_ENTRY *Flink;
			struct _LIST_ENTRY *Blink;
		}
		*/
		if (!ReadProcessMemory(hProcess, (PVOID)((uint64_t)flsListEntry - 0x40), &globalFlsData, sizeof(GLOBAL_FLS_DATA), NULL))
		{
			printf("[-] ReadProcessMemory failed GLOBAL_FLS_DATA struct: %i\n", GetLastError());
			continue;
		}

		// Calculate which chunk index contains ptr to callback table
		// FLS_INFO_CHUNK* fls_callback_chunks[chunkIndex];
		chunkIndex = GetFlsChunkIndexFromIndex(index, &idx);
		pCallbackTable = globalFlsData.flsCallbackChunks[chunkIndex];

		/* Callback table example in mem
		*
		*	0:002> dd 0x000001af79c45a50
			000001af`79c45a50  0000000b 00000000 00000000 00000000		<- 0b Number of callbacks in table.
			000001af`79c45a60  ffffffff ffffffff 00000000 00000000		<- index 0
			000001af`79c45a70  6eb13f20 00007ffa 00000000 00000000		<- Index 1
			000001af`79c45a80  ffffffff ffffffff 00000000 00000000		<- Index 2
			000001af`79c45a90  6ea16d50 00007ffa 00000000 00000000		<- Index 3
			000001af`79c45aa0  806fb9a0 00007ffa 00000000 00000000		<- Index 4
			000001af`79c45ab0  44444444 44444444 00000000 00000000		<- 0x44444444 44444444 Callback address at index 5
			000001af`79c45ac0  45454545 45454545 00000000 00000000		<- 0x45454545 45454545 Callback address at index 6
		*/

		// Do some ptr verification
		if (IsInvalidPtr(pCallbackTable))
		{
			continue;
		}

		// Callback table should start with its own heap block.
		if (!IsNtHeapBlockAddr(heapEntryMetaVector, (uint64_t)pCallbackTable - 0x10))
		{
			continue;
		}

		// Read first ULONG to get the number of Callback table entries & thus how many entries to read next.
		if (!ReadProcessMemory(hProcess, pCallbackTable, &nCallbackEntries, sizeof(ULONG), NULL))
		{
			printf("[-] ReadProcessMemory failed :%i\n", GetLastError());
			continue;
		}

		// Number of callback entries must be less than FLS slot maximum.
		if (nCallbackEntries > 4096 && nCallbackEntries != 0)
		{
			continue;
		}

		// Read from the first callback entry which starts +0x8 from the callback table start.
		callbackEntries.resize(nCallbackEntries);
		if (!ReadProcessMemory(hProcess, (PVOID)((uint64_t)pCallbackTable + 0x8), callbackEntries.data(), sizeof(FLS_CALLBACK) * nCallbackEntries, NULL))
		{
			printf("[-] ReadProcessMemory failed to read FLS Callback table:%i\n", GetLastError());
			continue;
		}

		// Save callback entries to our fiber object.
		myFiber.callbackEntries = callbackEntries;

		// Save reference of our already collected callback table for thread & pid.
		CallbackTable callbackTable = {};
		callbackTable.pid = myFiber.pid;
		callbackTable.tid = myFiber.tid;
		callbackTable.callbackEntries = callbackEntries;
		callbackTableVector.push_back(callbackTable);

		// At this point we have found our callback for pid & tid. So stop enumerating the remaining LIST_ENTRIES for fiber.
		break;
	}
}

//
// For each fiber:
// 1. Collect the TEB_FLS_DATA, which contains the LIST_ENTRY for that fiber.
// 2. Uses the LIST_ENTRY to loop around all possible FLS index values and pull out the data stored in each FLS slot.
// 3. Collect the fls callback table.
// 4. Uses each FLS index number to match a FLS slot with the correct callback.
//
void GetFls(std::vector<MyFiber>& myHeapFiberVector, std::vector<HeapEntryMeta> heapEntryMetaVector)
{
	std::vector<CallbackTable> callbackTables = {};
	DWORD maxIndexes = 0;
	maxIndexes = GetMaxFlsIndexValue();

	// Loop through each fiber object.
	for (auto& myFiber : myHeapFiberVector)
	{
		HANDLE hProcess = NULL;
		FlsSlot flsSlot = {};

		if (myFiber.fiberObject.FlsData == NULL)
		{
			printf("[-] FlsData set to NULL value, unable to collect FLS Slot and callback entries for individual fiber\n");
			continue;
		}

		hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, myFiber.pid);
		if (!hProcess)
		{
			printf("[-] Unable to open process handle\n");
			continue;
		}

		MEMORY_BASIC_INFORMATION mbi;
		size_t szToRead = NULL;
		TEB_FLS_DATA fls_data = {};

		if (!IsMemReadable(hProcess, myFiber.fiberObject.FlsData, mbi))
		{
			printf("[-] Unable to read FlsData region\n");
			goto Cleanup;
		}

		// flsDataSz should have already been populated by EnrichMyFiberVector().
		// If flsDataSz == 0, set this to remaining readable bytes from the base allocation.
		if (myFiber.flsDataSz != NULL)
		{
			szToRead = myFiber.flsDataSz;
		}
		else
		{
			szToRead = GetRemainingRegionSize(myFiber.fiberObject.FlsData, mbi);
		}

		// Make sure the remaining region size doesn't exceed the max possible number of FLS entries.
		if (maxIndexes - 1 > 4078)
		{
			maxIndexes = 4079;
		}

		// Read FLS_DATA for the fiber
		// This points to the LIST_ENTRY associated with the fiber, allowing one to determine which FLS slots belong to which fiber.
		if (!ReadProcessMemory(hProcess, myFiber.fiberObject.FlsData, &fls_data, szToRead, NULL))
		{
			printf("ReadProcessMemory failed :%i\n", GetLastError());
			goto Cleanup;
		}

		// Test every possible index value.
		// Max value index value should be 4079 (a condition inside ntdll!RtlFlsGetValue to check valid max index supplied).
		for (DWORD index = 1; index <= maxIndexes; index++)
		{
			flsSlot = {};
			if (index - 1 > 4078)
			{
				continue;
			}

			GetFlsCallbackTable(hProcess, myFiber, heapEntryMetaVector, index, callbackTables);

			if (RemoteFlsGetValue(hProcess, index, fls_data, heapEntryMetaVector, myFiber, flsSlot))
			{
				// If FLS slot found check to see if we can match it up to a Callback address since they will use the same index.
				for (const auto& callbackTable : callbackTables)
				{
					if (callbackTable.pid == myFiber.pid && callbackTable.tid == myFiber.tid)
					{
						flsSlot.associatedCallback = (uint64_t)callbackTable.callbackEntries.at(index).callback;
					}
				}

				myFiber.flsSlotVector.push_back(flsSlot);
			}

		}

	Cleanup:
		CloseHandle(hProcess);
	}
}

void PrintHelp(char* name)
{
	printf("Usage: %s -o outputFile.json \n\n", name);
}

int main(int argc, char* argv[])
{

	printf(R"EOF(
					 __       __   _     
			 _    _____ ___ / /____ _/ /  (_)_ __
			| |/|/ / -_) -_) __/ _ `/ _ \/ /\ \ /
			|__,__/\__/\__/\__/\_,_/_.__/_//_\_\)EOF");

	printf("\n\n");

	if (argc < 2)
	{
		PrintHelp(argv[0]);
		return 1;
	}

	std::vector<TidPid> tidPidVector;
	std::vector<MyFiber> fibers;
	std::vector<FiberResult> fiberResultsVector;

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEBUG | SYMOPT_DEFERRED_LOADS);

	if (!SetTokenPrivilege(SE_DEBUG_NAME, true))
	{
		printf("[!] SetTokenPrivilege failed\n");
		return 1;
	}

	if (!InitializeFuncs())
	{
		printf("[!] InitializeFuncs failed\n");
		return 1;
	}

	if (!ListProcessThreads(tidPidVector))
	{
		printf("[!] ListProcessThreads failed\n");
		return 1;
	}

	if (!EnumFibersFromThreads(tidPidVector, fibers))
	{
		printf("[!] EnumFiberFromThreads failed\n");
		return 1;
	}

	if (!GetFiberResults(fibers, fiberResultsVector))
	{
		printf("[!] GetFiberResults failed\n");
		return 1;
	}

	if (!ResultsWriter(argv[2], fiberResultsVector))
	{
		printf("[!] ResultsWriter failed\n");
		return 1;
	}

	return 0;
}

// Unused funcs
//
// Is memory private executable commit
//
BOOL IsMemPrivExeCommit(HANDLE& hProcess, PVOID addrToRead)
{
	MEMORY_BASIC_INFORMATION mbi;

	if (!VirtualQueryEx(hProcess, addrToRead, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		printf("[-] VirtualQueryEx Failed\n");
		return false;
	}

	if (!(mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY))
		return false;

	if (!(mbi.State == MEM_COMMIT))
		return false;

	if (!(mbi.Type == MEM_PRIVATE))
		return false;

	return true;

}