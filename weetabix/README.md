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
``

## Caveats 
*

## Credit
* Json.hpp project for NDJSON file output (https://github.com/nlohmann/json).