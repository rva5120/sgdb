# S-GDB: A usability-enhancing GDB interface geared to beginners

## Installation
**Clone the S-GDB repo**
```
git clone github.com/rva5120/sgdb
```

**Change .gdbinit to always source the sgdb.py script**
```
vim ~/.gdbinit
[add line ->] source <path>/<to>/sgdb/sgdb.py
```


## Running S-GDB
**Tutorial**
```
(gdb) tutorial
```

**x86 Instruction Information**
```
(gdb) instruction push
```

**Loops Highlighting**
```
(gdb) show loops main
```

**Recursion Highlighting**
```
(gdb) show recursion main
```

**Examining Memory**
```
(gdb) memory
````


## Troubleshooting
Tutorial Errors:
  - If needed, notes.c might need to be recompiled: gcc notes.c -o notes -ggdb


## Enhancing S-GDB
To add more commands, please refer to sgdb.py.
