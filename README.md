# PE_Parser

A C++ tool that parses Windows **PE (Portable Executable)** files and extracts
their structure — the DOS header, NT headers, and section headers. Built to
understand PE internals hands-on — a core skill in Windows malware analysis
and reverse engineering.

## Features
- Parses the **DOS header** and **NT headers** (File + Optional)
- Extracts and lists the **section headers**
- From-scratch implementation, no external PE-parsing libraries

## Build & Run
```bash
g++ PE_Parser.cpp -o pe_parser
./pe_parser <path-to-pe-file>
```

Write-up series
I documented PE-file internals and parsing step by step (TR):

 - [PE Files 0x01](https://muraterdem.org/posts/pe_files/pe_files_0x01.html)
 - [PE Files 0x02](https://muraterdem.org/posts/pe_files/pe_files_0x02.html)
 - [PE Files 0x03](https://muraterdem.org/posts/pe_files/pe_files_0x03.html)
 - [PE Files 0x04](https://muraterdem.org/posts/pe_files/pe_files_0x04.html)
 - [PE Files 0x05](https://muraterdem.org/posts/pe_files/pe_files_0x05.html)
 - [PE Files 0x06](https://muraterdem.org/posts/pe_files/pe_files_0x06.html)
