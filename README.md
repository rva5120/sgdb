# S-GDB: GDB extension geared to beginners
Welcome to S-GDB! S-GDB is designed to help students and beginners get more familiar with GDB.

## Installation
**Clone the S-GDB repo**
```
git clone github.com/rva5120/sgdb
```

**Change .gdbinit to always source the sgdb.py script**
```
vim ~/.gdbinit
[add this line to the .gdbinit ->] source <path>/<to>/sgdb/sgdb.py
```


## Running S-GDB
S-GDB features 5 commands, including a tutorial. After installing S-GDB, you can start running GDB.
If you changed .gdbinit and added the line (as mentioned on the installation), you can start using
any othe the commands below.

**Tutorial**
```
(gdb) tutorial
```

**x86 Instruction Information**
```
(gdb) instruction <instruction name>
```

**Loops Highlighting**
```
(gdb) show loops <function name>
```

**Recursion Highlighting**
```
(gdb) show recursion <function name>
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
