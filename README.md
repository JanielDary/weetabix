# Weetabix

This tool demonstrates a PoC technique for enumerating Windows Fibers from process memory allowing defenders to distinguish legitimate from malicious Fiber use.

Weetabix identifies which Threads are running Fibers then extracts:
* The currently executing Fiber.
* Any associated Dormant Fibers.
* Their Fiber Data.
* Their Fiber local storage slots.
* And any associated Fiber callback functions in use.

Weetabix then applies a set of enrichments such as memory protections, symbol+module resolutions & entropy scores to allow one to distinguish legitimate from malicious fiber use.  

## Usage
![image](https://user-images.githubusercontent.com/60667846/230958277-66fc257d-7f2c-4c24-b79e-6380256b447f.png)

## Detection Use Cases with sample output

Unorthodox use of Fibers by CobaltStrike's Artifact kit when using Thread Stack Spoofing reveals only a single fiber being used. This is irregular since Fibers were designed with multi-tasking in mind so one would expect two or more fibers/Thread. In addition 
1. FiberData points to unbacked memory.
2. There is no Fiber local storage which is non-standard behaviour.
3. There are no callbacks functions which is non-standard behaviour.
![image](https://user-images.githubusercontent.com/60667846/230965528-5bfa4766-b04c-4262-84dc-5235acfe2a73.png)



## NOTE
* This tool requires symbols to be correctly configured on Windows for callback symbol resolution.
* PoC was tested on Windows 10 19044. Targets x64 processes.

## Credit
* Json.hpp project for NDJSON file output (https://github.com/nlohmann/json).
