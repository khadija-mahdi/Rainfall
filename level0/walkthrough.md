# Level 0 - RainFall CTF Walkthrough

## Challenge Overview
Level 0 is the first challenge in the RainFall CTF series. This is a simple privilege escalation challenge that requires basic reverse engineering skills to understand the program's logic.

## Initial Analysis

### File Information
- **Binary**: `level0` (located in `/home/user/level0/`)
- **Goal**: Obtain the password for level1 from `/home/user/level1/.pass`
- **Current User**: `level0`
- **Target User**: `level1`

### Static Analysis with GDB

First, let's examine the binary using GDB to understand its functionality:

```bash
level0@RainFall:~$ gdb -q level0
(gdb) set disassembly-flavor intel
(gdb) disassemble main
```

## Code Analysis

### Key Assembly Instructions Breakdown

1. **Argument Processing** (`0x08048ec9` - `0x08048ed4`):
   ```assembly
   mov    eax,DWORD PTR [ebp+0xc]  ; argv
   add    eax,0x4                  ; argv[1]
   mov    eax,DWORD PTR [eax]      ; dereference argv[1]
   mov    DWORD PTR [esp],eax      ; prepare for atoi call
   call   0x8049710 <atoi>         ; convert string to integer
   ```

2. **Critical Comparison** (`0x08048ed9` - `0x08048ede`):
   ```assembly
   cmp    eax,0x1a7                ; compare result with 423
   jne    0x8048f58 <main+152>     ; jump to failure if not equal
   ```

3. **Success Path** (privilege escalation):
   - Calls `strdup()` on a string at `0x80c5348`
   - Gets effective group ID (`getegid`) and user ID (`geteuid`)
   - Sets real, effective, and saved IDs using `setresgid` and `setresuid`
   - Executes a shell via `execv`

4. **Failure Path**:
   - Writes error message using `fwrite`

## Solution

### Step 1: Identify the Magic Number
From the assembly analysis, we can see the program compares the input with `0x1a7`:

```bash
(gdb) print 0x1a7
$1 = 423
```

The program expects the argument `423` to proceed with privilege escalation.

### Step 2: Execute with Correct Argument

```bash
level0@RainFall:~$ ./level0 423
$ whoami
level1
```

Success! The program has escalated our privileges to `level1`.

### Step 3: Retrieve the Password

```bash
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

