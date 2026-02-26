# ntleak

## Description
`ntleak` is a lightweight Windows native memory leak detection tool built using MinHook. It tracks heap and virtual memory allocations and reports unfreed memory blocks with detailed call stacks, helping developers identify and fix memory leaks.

## Usage
1. Compile your program with debug symbols enabled.  
2. Run your program under `ntleak`:

```powershell
ntleak.exe <your_program.exe>
