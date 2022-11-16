# Weetabix
<image src="https://github.com/JanielDary/weetabix/assets/60667846/9c4c7b50-108f-4be9-9f8d-1963d5782ada" width="312" height="230">


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

## Detection use cases with sample output from Weetabix

### Malicious callback manipulation
Tested against a Fiber whoes default Fiber local storage callbacks have been overwritten with malicous callbacks. The malicious callbacks are executed whenever the fiber/thread exits or the associated Fiber Local Storage slot is freed. 

Weetabix finds two suspicous callbacks
1. A callback to a mapped module in the Downloads directory.
2. A callback into unbacked RWX memory.

![image](https://user-images.githubusercontent.com/60667846/230966652-f1e05128-90b4-46e7-ba2e-82662c1c0fe0.png)

### Unorthodox use of Fibers by CobaltStrike's Artifact kit when using Thread Stack Spoofing
This reveals only a single fiber being used on a thread. This is irregular since Fibers were designed with multi-tasking in mind so one would expect two or more fibers/Thread. In addition 
1. FiberData points to unbacked memory.
2. There is no Fiber local storage which is non-standard behaviour.
3. There are no callbacks functions which is non-standard behaviour.

![image](https://user-images.githubusercontent.com/60667846/230965528-5bfa4766-b04c-4262-84dc-5235acfe2a73.png)



## NOTES
* This tool requires symbols to be correctly configured on Windows for callback symbol resolution.
* PoC was tested on Windows 10 19044. Targets x64 processes.
* Built around newer implementation of Fiber Local Storage (Windows 10 1903 onwards).

## Credit
* Used the Json.hpp project for NDJSON file output (https://github.com/nlohmann/json).
