#################################################
# S-GDB : Student GDB                           #
# -------------------                           #
# Colorful interface for students learning      #
# about reverse engineering for the first time. #
#                                               #
# Author : @rva5120                             #
#################################################

#####################
# Supported Commands
# ------------------
#  show loops <function name> : colors loops and nested loops on a function
#  show recursion <function name> : colors recursive calls on a function
#
#  info <instruction> : shows information about the x86 <instruction>
#
#  memory : this command is a wrapper around the original examine x/
#     memory < no arguments > - prompts you for details to help you
#                               examine memory at a given address
#     memory addr=<address> num_bytes=<number of bytes> format=<b,o,d,x,s> grouped_by=<1,2,4,8>
#     memory <address> <number of bytes> <format> <group>
#
#  tutorial : starts a tutorial to help you learn about GDB
#####################

#####################
# Commands under Dev
# ------------------
#  show data <function name> : disas with the data type of the value at the
#                               addresses in an instruction.
#  show stack : visualization of the stack at the current execution state
#####################

#########################################################################
# How do I run this script?                                             #
# -------------------------                                             #
#  GDB runs a python interpreter and has its own module available to    #
#  import (gdb). To use this script, you can use one of two methods:    #
# (1) Add the line "source sgdb.py" to your .gdbinit                    #
# (2) Directly run "source sgdb.py" on gdb                              #
#                                                                       #
# Can I import other modules (like nltk, for example)?                  #
#  Yes, just install the module like you normally would (using pip)     #
#                                                                       #
# How can I add new commands?                                           #
#  GDB expects commands to be wrapped in a gdb.Command subclass. So     #
#  you need to create a new class and define two methods:               #
# (1) __init__ : defines the command and argument types                 #
# (2) invoke : defines the behavior of the command                      #
#                                                                       #
# Useful resources:                                                     #
#  - Reversing: Secrets of Reverse Engineering (Wiley)                  #
#  - GDB Python API: https://sourceware.org/gdb/onlinedocs/gdb/         #
#     Python-API.html#Python-API                                        #
#  - Tutorial: http://tromey.com/blog/?p=501                            #
#  - Automatic Reverse Engineering of Data Structures from Binary       #
#     Execution by Lin et al. (Zhiqiang Lin)                            #
#  - x86: https://www.aldeid.com/wiki/X86-assembly/instructions         #
#########################################################################


# Imports
from __future__ import with_statement
from collections import OrderedDict
import gdb  # module defined by GDB, cannot be used outside of gdb
import re



# Example command
class ExampleCommand(gdb.Command):
  """Description of the example command"""

  # The command initializer (gdb.Command) sets up the "example" command
  # to be processed. In this example, we want to support "tab-complete"
  # where the completion shows files (gdb.COMPLETE_FILENAME).
  def __init__(self):
    super (ExampleCommand, self).__init__("example", 
              gdb.COMMAND_SUPPORT, 
              gdb.COMPLETE_FILENAME)

  # This method is called by gdb when the command is executed from the CLI
  # Two args are passed: a string (arg) if there is an argument or None 
  # otherwise the second argument is a boolean (from_tty), and is False if 
  # the cmd comes from a script. 
  def invoke(self, arg, from_tty):
    pass


# ======= AUX Structures =======
# Colors  
class colors():
  red = "\033[31m"
  green = "\033[32m"
  yellow = "\033[33m"
  blue = "\033[34m"
  pink = "\033[35m"
  cyan = "\033[36m"
  bold = "\033[1m"
  u = "\033[4m"
  i = "\033[3m"
  nc = "\033[0m"
  color_list = [red, green, yellow, blue, pink, cyan]

# Check that input is a number
def is_num(i):
  try:
    int(i)
    return True
  except ValueError:
    return False

# Stop executing the python script
def handle_quit(command):
  if ((command == "q") or (command == "quit")):
    exit()

# Instruction Switcher
class Switcher(object):

  def instruction_switcher(self, instruction):
    # Get the right instruction method based on instr. name
    method = getattr(self, "i_" + instruction, self.default)
    # Return a call to the method for that instruction
    return method()

  # === x86 Instructions ===
  # (70+ x86 instructions included here)

  def default(self):
    print colors.red + "Invalid instruction." 
    print "If applicable, please remove any suffix (such as q)" 
    print "at the end of the instruction." 
    print "Example: for movq -> mov, or cltq -> clt." + colors.nc

  # Push
  def i_push(self):
    print "Push Instruction"
    print "----------------"
    print "Usage: push <register>"
    print "       push <value>"
    print
    print "Info: Pushes the value onto the stack."
    print "      Typically used to save the value of a register"
    print "      to resue that register for other purpose."
    print ""

  # Pop
  def i_pop(self):
    print "Pop Instruction"
    print "---------------"
    print "Usage: pop <register>"
    print
    print "Info: Saves the value at the top of the stack into the register."
    print "      Used to restore a value back right before returning to the"
    print "      caller."
    print

  # Mov
  def i_mov(self):
    print "Mov Instruction"
    print "---------------"
    print "Usage: mov <src>, <dst>"
    print "       mov $0x0, %rdx"
    print 
    print "Info: Places the value at src in dst. For example, the first"
    print "      instruction puts the value 0x0 in the rdx register."
    print 

  # Call
  def i_call(self):
    print "Call Instruction"
    print "----------------"
    print "Usage: call <address>"
    print 
    print "Info: Calls the function pointed at by the address given."
    print "      It can be used for recursive calls or to call other"
    print "      functions. Beware: this is not a jump. Once the"
    print "      called function returns, the instruction after the call"
    print "      gets executed next."
    print

  # Ret
  def i_ret(self):
    print "Ret Instruction"
    print "---------------"
    print "Usage: ret"
    print 
    print "Info: Returns back to the calling function."
    print 

  # Rep
  def i_rep(self):
    print "Rep Instruction"
    print "---------------"
    print "Usage (1): rep <instruction>"
    print "      (2): rep ret"
    print
    print "Info: (1): Repeat string operation until tested-condition."
    print "           (more info: aldeid.com/wiki/x86-assembly/Instructions/rep"
    print "      (2): Used as a no-op if preceded by a conditional jump. This is"
    print "           used to fix an AMD-compiler inconsistency." 
    print "           More info: repzret.org/p/repzret"
    print

  # Repnz 
  def i_repnz(self):
    self.rep()

  # Repz
  def i_repz(self):
    self.rep()

  # Nop 
  def i_nop(self):
    print "Nop Instruction"
    print "---------------"
    print "Usage: nop"
    print
    print "Info: Spends a CPU cycle with no effect (no-operation)."
    print

  # Sub
  def i_sub(self):
    print "Sub Instruction"
    print "---------------"
    print "Usage: sub <src>, <dst>"
    print 
    print "Info: <dst> = <dst> - <src>, subtracts <src> from <dst> and"
    print "      stores the results in <dst>."
    print "      You may find sub being used with the registers rbp and"
    print "      rsp. This typically means that some space is being"
    print "      allocated in the stack (by pushing rsp down)."
    print
#10
  # Add
  def i_add(self):
    print "Add Instruction"
    print "---------------"
    print "Usage: add <src>, <dst>"
    print
    print "Info: <dst> = <dst> + <src>, adds <src> to <dst> and stores"
    print "      the result in <dst>."
    print

  # Lea 
  def i_lea(self):
    print "Lea (load effective address) Instruction"
    print "----------------------------------------"
    print "Usage: lea <src>, <dst>"
    print "       lea 3(%rax,%rax,4), %rdx"
    print 
    print "Info: Assuming that rax=x, lea will store 5x+3 in rdx."
    print

  # Sar 
  def i_sar(self):
    print "Sar (Arithmetic Rigth Shift) Instruction"
    print "---------------------------------------"
    print "Usage: sar k, <dst>"
    print 
    print "Info: Shifts the bits in <dst> by k to the right, filling"
    print "      the left side with sign bits. Example:"
    print "      sar 1, %rdx"
    print "       assuming rdx=-2, then 1110 >> 1 = 1111 ---> rdx=-1"
    print

  # Sal
  def i_sal(self):
    print "Sal (Arithmentic Left Shift) Instruction"
    print "----------------------------------------"
    print "Usage: sal k, <dst>"
    print
    print "Info: Shifts the bits in <dst> by k to the left, filling"
    print "      the right with 0s. Example:"
    print "      sal 2, %rdx"
    print "       assuming rdx=2, then 0010 >> 2 = 1000 ---> rdx=4"
    print

  # Shr
  def i_shr(self):
    print "Shr (Logical Right Shift) Instruction"
    print "-------------------------------------"
    print "Usage: shr k, <dst>"
    print 
    print "Info: Shifts the bits in <dst> by k to the right, filling"
    print "      the left with 0s. Example:"
    print "      shr 1, %rdx"
    print "       assuming rdx=-1, then 1111 >> 1 = 0111 ---> rdx=3"
    print

  # Shl
  def i_shl(self):
    print "Shl (Logical Left Shift) Instruction"
    print "------------------------------------"
    print "Usage: shl k, <dst>"
    print 
    print "Info: Shifts the bits in <dst> by k to the left, filling"
    print "      the right with 0s. Example:"
    print "      shl 2, %rdx"
    print "       assuming rdx=2, then 0010 >> 2 = 1000 ---> rdx=4"
    print

  # Or
  def i_or(self):
    print "OR Instruction"
    print "--------------"
    print "Usage: or <src>, <dst>"
    print
    print "Info: <dst> = <dst> | <src>, performs a logical OR and "
    print "      stores the result in <dst>."
    print

  # Xor
  def i_xor(self):
    print "XOR Instruction"
    print "---------------"
    print "Usage: xor <src>, <dst>"
    print
    print "Info: <dst> = <dst> ^ <src>, performs an exclusive-OR"
    print "      and stores the result in <dst>."
    print

  # And
  def i_and(self):
    print "AND Instruction"
    print "---------------"
    print "Usage: and <src>, <dst>"
    print
    print "Info: <dst> = <dst> & <src>, performs a logical AND"
    print "      and stores the result in <dst>."
    print

  # Not
  def i_not(self):
    print "Not Instruction"
    print "---------------"
    print "Usage: not <dst>"
    print
    print "Info: <dst> = ~<dst>, performs the complement of <dst>"
    print "      and stores it in <dst>. Beware, this is not the"
    print "      same as the ! operator!"
    print
#20
  # Inc
  def i_inc(self):
    print "Inc Instruction"
    print "---------------"
    print "Usage: inc <dst>"
    print
    print "Info: <dst> = <dst> + 1, increments <dst> by 1."
    print

  # Dec
  def i_dec(self):
    print "Dec Instruction"
    print "---------------"
    print "Usage: dec <dst>"
    print
    print "Info: <dst> = <dst> - 1, decrements <dst> by 1."
    print

  # Neg
  def i_neg(self):
    print "Neg Instruction"
    print "---------------"
    print "Usage: neg <dst>"
    print
    print "Info: <dst> = (-1) * <dst>, negates <dst>."
    print

  # iMul
  def i_imul(self):
    print "iMul/Mul Instruction"
    print "----------------"
    print "Usage: (1) imul <src>, <dst>"
    print "       (2) imul <dst>"
    print "           mul <dst>"
    print
    print "Info: (1) <dst> = <dst> * <src>, multiplies <dst>*<src> and stores"
    print "      the value in <dst>."
    print "      (2) edx:eax = <dst> * eax, stores the results across edx and eax"
    print "          (edx has top 32 bits, and eax the lower 32 bits)."
    print

  # Mul
  def i_mul(self):
    self.i_imul()

  # Cqto
  def i_cqto(self):
    print "Not currently documented."

  # Cqo
  def i_cqo(self):
    print "Not currently documented."

  # iDiv
  def i_idiv(self):
    print "iDiv/Div Instruction"
    print "--------------------"
    print "Usage: (1) idiv <arg>"
    print "       (2) div k"
    print 
    print "Info: (1) eax = edx:eax / <arg>, the quotient goes into eax and"
    print "          the remainder goes into edx."
    print "      (2) eax = edx:eax / k, the quotient goes into eax and"
    print "          the remainder goes into edx."
    print

  # Div
  def i_div(self):
    self.i_idiv()

  # Cmp 
  def i_cmp(self):
    print "Cmp Instruction"
    print "---------------"
    print "Usage: cmp <a1>, <a2>"
    print
    print "Info: Performs the operation <a2> - <a1>, which sets the SF if"
    print "      the result is negative (meaning <a2> < <a1>). This is used"
    print "      for control flow and conditional jumps."
    print
#30
  # Test
  def i_test(self):
    print "Test Instruction"
    print "----------------"
    print "Usage: test <a1>, <a2>"
    print
    print "Info: Performs the operation <a1> & <a2>, which sets the ZF if"
    print "      the result is 0x0. This is typically used to test if a"
    print "      value is 0. For example:"
    print "       if rax = 0, then test %rax,%rax will set the ZF flag"
    print "       if rax = 1, then test %rax,%rax won't set the ZF flag"
    print "      This instruction is useful for control flow."
    print

  # Sete
  def i_sete(self):
    print "Sete/Setz (Set when Equal) Instruction"
    print "----------------"
    print "Usage: sete <dst>"
    print "       setz <dst>"
    print 
    print "Info: Typically <dst> will be either a memory address or a single byte"
    print "      register (such as al). This instruction sets the first byte at"
    print "      the <dst> memory address or the value of the single-byte register"
    print "      to 0 or 1 depending on the ZF condition code."
    print "      Useful for control flow after cmp or test instructions."
    print

  # Setz
  def i_setz(self):
    self.i_sete()

  # Setne
  def i_setne(self):
    print "Setne (Set when Not Equal) Instruction"
    print "--------------------------------------"
    print "Usage: setne <dst>"
    print
    print "Info: Typically <dst> will be either a memory address or a single byte"
    print "      register (such as al). This instruction sets the first byte at"
    print "      the <dst> memory address or the value of the single-byte register"
    print "      to 0 or 1, acording to ~ZF."
    print "      Useful for control flow after cmp or test instructions."
    print

  # Setnz 
  def i_setnz(self):
    self.i_setne()

  # Sets
  def i_sets(self):
    print "Sets (Set when negative) Instruction"
    print "----------------"
    print "Usage: sets <dst>"
    print
    print "Info: Typically <dst> will be either a memory address or a single byte"
    print "      register (such as al). This instruction sets the first byte at"
    print "      the <dst> memory address or the value of the single-byte register"
    print "      to 0 or 1, acording to SF."
    print "      Useful for control flow after cmp or test instructions."
    print

  # Setns
  def i_setns(self):
    print "Setns (Set when nonnegative) Instruction"
    print "-----------------"
    print "Usage: setns <dst>"
    print
    print "Info: Typically <dst> will be either a memory address or a single byte"
    print "      register (such as al). This instruction sets the first byte at"
    print "      the <dst> memory address or the value of the single-byte register"
    print "      to 0 or 1, acording to ~SF."
    print "      Useful for control flow after cmp or test instructions."
    print

  # Setg
  def i_setg(self):
    print "Setg (Set when greater) Instruction"
    print "----------------"
    print "Usage: setg <dst>"
    print
    print "Info: Typically <dst> will be either a memory address or a single byte"
    print "      register (such as al). This instruction sets the first byte at"
    print "      the <dst> memory address or the value of the single-byte register"
    print "      to 0 or 1, acording to ~(SF ^ OF) & ZF."
    print "      Useful for control flow after cmp or test instructions."
    print

  # Setnle
  def i_setnle(self):
    self.setg()

  # Setge
  def i_setge(self):
    print "Setge (Set when greater or equal) Instruction"
    print "---------------------------------------------"
    print "Usage: setge <dst>"
    print
    print "Info: Typically <dst> will be either a memory address or a single byte"
    print "      register (such as al). This instruction sets the first byte at"
    print "      the <dst> memory address or the value of the single-byte register"
    print "      to 0 or 1, acording to ~(SF ^ OF)."
    print "      Useful for control flow after cmp or test instructions."
    print
#40
  # Setnl
  def i_setnl(self):
    self.i_setge()

  # Setnge 
  def i_setnge(self):
    self.i_setl()
# --
  # Setl
  def i_setl(self):
    print "Setl (Set when less) Instruction"
    print "--------------------------------"
    print "Usage: setl <dst>"
    print
    print "Info: Typically <dst> will be either a memory address or a single byte"
    print "      register (such as al). This instruction sets the first byte at"
    print "      the <dst> memory address or the value of the single-byte register"
    print "      to 0 or 1, acording to (SF ^ OF)."
    print "      Useful for control flow after cmp or test instructions."
    print

  # Setle
  def i_setle(self):
    print "Setle (Set when less or equal) Instruction"
    print "------------------------------------------"
    print "Usage: setle <dst>"
    print
    print "Info: Typically <dst> will be either a memory address or a single byte"
    print "      register (such as al). This instruction sets the first byte at"
    print "      the <dst> memory address or the value of the single-byte register"
    print "      to 0 or 1, acording to ~(SF ^ OF) | ZF."
    print "      Useful for control flow after cmp or test instructions."
    print

  # Setng
  def i_setng(self):
    self.i_setle()

  # Seta
  def i_seta(self):
    print "Seta (Set when above) Instruction"
    print "---------------------------------"
    print "Usage: seta <dst>"
    print
    print "Info: Typically <dst> will be either a memory address or a single byte"
    print "      register (such as al). This instruction sets the first byte at"
    print "      the <dst> memory address or the value of the single-byte register"
    print "      to 0 or 1, acording to ~CF & ~ZF."
    print "      Useful for control flow after cmp or test instructions."
    print "      Equivalent to setg, but for unsigned numbers."
    print

  # Setnbe
  def i_setnbe(self):
    self.i_seta()

  # Setae
  def i_setae(self):
    print "Setae (Set when above or equal) Instruction"
    print "-------------------------------------------"
    print "Usage: setae <dst>"
    print
    print "Info: Typically <dst> will be either a memory address or a single byte"
    print "      register (such as al). This instruction sets the first byte at"
    print "      the <dst> memory address or the value of the single-byte register"
    print "      to 0 or 1, acording to ~CF."
    print "      Useful for control flow after cmp or test instructions."
    print "      Equivalent to setge, but for unsigned numbers."
    print

  # Setnb
  def i_setnb(self):
    self.i_setae()

  # Setb
  def i_setb(self):
    print "Setb (Set when below) Instruction"
    print "---------------------------------"
    print "Usage: setb <dst>"
    print
    print "Info: Typically <dst> will be either a memory address or a single byte"
    print "      register (such as al). This instruction sets the first byte at"
    print "      the <dst> memory address or the value of the single-byte register"
    print "      to 0 or 1, acording to CF."
    print "      Useful for control flow after cmp or test instructions."
    print "      Equivalent to setl, but for unsigned numbers."
    print
#50
  # Setnae
  def i_setnae(self):
    self.i_setb()

  # Setbe
  def i_setbe(self):
    print "Setbe (Set when below or equal) Instruction"
    print "-------------------------------------------"
    print "Usage: setbe <dst>"
    print
    print "Info: Typically <dst> will be either a memory address or a single byte"
    print "      register (such as al). This instruction sets the first byte at"
    print "      the <dst> memory address or the value of the single-byte register"
    print "      to 0 or 1, acording to CF | ZF."
    print "      Useful for control flow after cmp or test instructions."
    print "      Equivalent to setle, but for unsigned numbers."
    print

  # Setna
  def i_setna(self):
    self.i_setbe()

  # Jmp
  def i_jmp(self):
    print "Jmp Instruction"
    print "---------------"
    print "Usage: (1) jmp <target>"
    print "       (2) jmp *<target>"
    print
    print "Info: Jump to the target address unconditionally (an address of any"
    print "      labeled instruction is a target)."
    print "       (1) Direct jump: jump target is encoded as a label."
    print "       (2) Indirect Jump: jump target is read from memory or a register."
    print

  # Je
  def i_je(self):
    print "Je/Jz Instruction"
    print "---------------"
    print "Usage: je <target>"
    print "       jz <target>"
    print
    print "Info: Jump to the target when ZF is set (an address of any"
    print "      labeled instruction is a target)."
    print

  # Jz 
  def i_jz(self):
    self.i_je()

  # Jne
  def i_jne(self):
    print "Jne/Jnz Instruction"
    print "---------------"
    print "Usage: jne <target>"
    print "       jnz <target>"
    print
    print "Info: Jump to the target when ~ZF is set (an address of any"
    print "      labeled instruction is a target)."
    print

  # Jnz
  def i_jnz(self):
    self.i_jne()

  # Js
  def i_js(self):
    print "Js Instruction"
    print "--------------"
    print "Usage: js <target>"
    print
    print "Info: Jump to the target when SF is set (an address of any"
    print "      labeled instruction is a target)."
    print

  # Jns
  def i_jns(self):
    print "Jns Instruction"
    print "---------------"
    print "Usage: jns <target>"
    print
    print "Info: Jump to the target when ~SF (an address of any"
    print "      labeled instruction is a target)."
    print
#60
  # Jg
  def i_jg(self):
    print "Jg/Jnle Instruction"
    print "-------------------"
    print "Usage: jg <target>"
    print "       jnle <target>"
    print
    print "Info: Jump to the target when ~(SF ^ OF) & ~ZF is set (an address of any"
    print "      labeled instruction is a target)."
    print

  # Jnle
  def i_jnle(self):
    self.i_jg()

  # Jge
  def i_jge(self):
    print "Jge/Jnl Instruction"
    print "-------------------"
    print "Usage: jge <target>"
    print "       jnl <target>"
    print
    print "Info: Jump to the target when ~(SF ^ OF) is set (an address of any"
    print "      labeled instruction is a target)."
    print

  # Jnl
  def i_jnl(self):
    self.i_jge()

  # Jl
  def i_jl(self):
    print "Jl/Jnge Instruction"
    print "-------------------"
    print "Usage: jl <target>"
    print "       jnge <target>"
    print
    print "Info: Jump to the target when SF ^ OF is set (an address of any"
    print "      labeled instruction is a target)."
    print

  # Jnge 
  def i_jnge(self):
    self.i_jl()

  # Jle
  def i_jle(self):
    print "Jle/Jng Instruction"
    print "-------------------"
    print "Usage: jle <target>"
    print "       jng <target>"
    print
    print "Info: Jump to the target when (SF ^ OF) | ZF is set (an address of any"
    print "      labeled instruction is a target)."
    print

  # Jng
  def i_jng(self):
    self.i_jle()

  # Ja
  def i_ja(self):
    print "Ja/Jnbe Instruction"
    print "-------------------"
    print "Usage: ja <target>"
    print "       jnbe <target>"
    print
    print "Info: Jump to the target when ~CF & ~ZF is set (an address of any"
    print "      labeled instruction is a target)."
    print

  # Jnbe
  def i_jnbe(self):
    self.i_ja()

  # Jae
  def i_jae(self):
    print "Jae/Jnb Instruction"
    print "-------------------"
    print "Usage: jae <target>"
    print "       jnb <target>"
    print
    print "Info: Jump to the target when ~CF is set (an address of any"
    print "      labeled instruction is a target)."
    print

  # Jnb
  def i_jnb(self):
    self.i_jae()

  # Jb
  def i_jb(self):
    print "Jb/Jnae Instruction"
    print "-------------------"
    print "Usage: jb <target>"
    print "       jnae <target>"
    print
    print "Info: Jump to the target when CF is set (an address of any"
    print "      labeled instruction is a target)."
    print

  # Jnae
  def i_jnae(self):
    self.i_jb()

  # Jbe
  def i_jbe(self):
    print "Jbe/Jna Instruction"
    print "-------------------"
    print "Usage: jbe <target>"
    print "       jna <target>"
    print
    print "Info: Jump to the target when CF | ZF is set (an address of any"
    print "      labeled instruction is a target)."
    print

  # Jna
  def i_jna(self):
    self.i_jbe()
# 76
  # Cmove
  def i_cmove(self):
    print "Cmove/Cmovz (Conditional Mov when Equal) Instruction"
    print "----------------------------------------------------"
    print "Usage: cmove <src>, <dst>"
    print "       cmovz <src>, <dst>"
    print
    print "Info: mov <src>, <dst> is executed if ZF is set."
    print

  # Cmovz
  def i_cmovz(self):
    self.i_cmove()

  # Cmovne
  def i_cmovne(self):
    print "Cmovne/Cmovnz (Conditional Mov when Not Equal) Instruction"
    print "----------------------------------------------------------"
    print "Usage: cmovne <src>, <dst>"
    print "       cmovnz <src>, <dst>"
    print
    print "Info: mov <src>, <dst> is executed if ~ZF is set."
    print

  # Cmovnz
  def i_cmovnz(self):
    self.i_cmovne()
#80
  # Cmovs
  def i_cmovs(self):
    print "Cmovs (Conditional Mov when Negative) Instruction"
    print "-------------------------------------------------"
    print "Usage: cmovs <src>, <dst>"
    print
    print "Info: mov <src>, <dst> is executed if SF is set."
    print

  # Cmovns
  def i_cmovns(self):
    print "Cmovns (Conditional Mov when Positive) Instruction"
    print "--------------------------------------------------"
    print "Usage: cmovns <src>, <dst>"
    print
    print "Info: mov <src>, <dst> is executed if ~SF is set."
    print

  # Cmovg
  def i_cmovg(self):
    print "Cmovg/Cmovnle (Conditional Mov when Greater) Instruction"
    print "--------------------------------------------------------"
    print "Usage: cmovg <src>, <dst>"
    print "       cmovnle <src>, <dst>"
    print
    print "Info: mov <src>, <dst> is executed if ~(SF ^ OF) & ~ZF is set."
    print

  # Cmovnle
  def i_cmovnle(self):
    self.i_cmovg()

  # Cmovge
  def i_cmovge(self):
    print "Cmovge/Cmovnl (Conditional Mov when Greater or Equal) Instruction"
    print "-----------------------------------------------------------------"
    print "Usage: cmovge <src>, <dst>"
    print "       cmovnl <src>, <dst>"
    print
    print "Info: mov <src>, <dst> is executed if ~(SF ^ OF) is set."
    print

  # Cmovnl
  def i_cmovnl(self):
    self.i_cmovge()

  # Cmovl
  def i_cmovl(self):
    print "Cmovl/Cmovnge (Conditional Mov when Less) Instruction"
    print "-----------------------------------------------------"
    print "Usage: cmovl <src>, <dst>"
    print "       cmovnge <src>, <dst>"
    print
    print "Info: mov <src>, <dst> is executed if SF ^ OF is set."
    print

  # Cmovnge
  def i_cmovnge(self):
    self.i_cmovl()

  # Cmovle
  def i_cmovle(self):
    print "Cmovle/Cmovng (Conditional Mov when Less or Equal) Instruction"
    print "--------------------------------------------------------------"
    print "Usage: cmovle <src>, <dst>"
    print "       cmovng <src>, <dst>"
    print
    print "Info: mov <src>, <dst> is executed if (SF ^ OF) | ZF is set."
    print

  # Cmovng
  def i_cmovng(self):
    self.i_cmovle()
#90
  # Cmova
  def i_cmova(self):
    print "Cmova/Cmovnbe (Conditional Mov when Above) Instruction"
    print "------------------------------------------------------"
    print "Usage: cmova <src>, <dst>"
    print "       cmovnbe <src>, <dst>"
    print
    print "Info: mov <src>, <dst> is executed if ~CF & ~ZF is set."
    print
  
  # Cmovnbe
  def i_cmovnbe(self):
    self.i_cmova()

  # Cmovae
  def i_cmovae(self):
    print "Cmovae/Cmovnb (Conditional Mov when Above or Equal) Instruction"
    print "---------------------------------------------------------------"
    print "Usage: cmovae <src>, <dst>"
    print "       cmovnb <src>, <dst>"
    print
    print "Info: mov <src>, <dst> is executed if ~CF is set."
    print

  # Cmovnb
  def i_cmovnb(self):
    self.i_cmovae()

  # Cmovb
  def i_cmovb(self):
    print "Cmovb/Cmovnae (Conditional Mov when Below) Instruction"
    print "------------------------------------------------------"
    print "Usage: cmovb <src>, <dst>"
    print "       cmovnae <src>, <dst>"
    print
    print "Info: mov <src>, <dst> is executed if CF is set."
    print
  
  # Cmovnae
  def i_cmovnae(self):
    self.i_cmovb()

  # Cmovbe
  def i_cmovbe(self):
    print "Cmovbe/Cmovna (Conditional Mov when Below or Equal) Instruction"
    print "---------------------------------------------------------------"
    print "Usage: cmovbe <src>, <dst>"
    print "       cmovna <src>, <dst>"
    print
    print "Info: mov <src>, <dst> is executed if CF | ZF is set."
    print

  # Cmovna
  def i_cmovna(self):
    self.i_cmovna()

  # Clt
  def i_clt(self):
    print "Clt Instruction"
    print "---------------"
    print "Usage: clt"
    print 
    print "Info: Sign extends eax to rax."
    print

  # Leave
  def i_leave(self):
    print "Leave Instruction"
    print "-----------------"
    print "Usage: leave"
    print
    print "Info: Restores the caller's stack registers (rbp and rsp),"
    print "      to prepare for the current function to end and return"
    print "      execution to the caller."
    print
#90
# ============================



# x86 Instructions
class InstructionsCommand(gdb.Command):
  """ Prints info about a given x86 instruction

  Usage: instruction info <instruction name> """

  def __init__(self):
    super(InstructionsCommand, self).__init__("instruction", gdb.COMMAND_SUPPORT)

  def invoke(self, arg, from_tty):
    instruction = arg
    print colors.bold
    s = Switcher()
    s.instruction_switcher(instruction)
    print colors.nc



# Loops
class LoopsCommand(gdb.Command):
  """ Prints the current disassembled function
  and highligts the loops, if any.
  
  Usage: show loops <function_name>"""

  # Describe the command to be processed: show loops in function_name
  # Argument: function name
  def __init__(self):
    super(LoopsCommand, self).__init__("show loops",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_SYMBOL)

  # Task: run "disas func_name", get the output from GDB,
  # find the loops, and wrap the proper lines with color changing tags
  def invoke(self, arg, from_tty):
    print "Looking for loops...\n"
    # get the output of disas
    disas = gdb.execute("disas " + arg, to_string=True)
    #print disas
    # get a list of all instructions
    instruction_statements = disas.split('\n')
    # skip the first line
    instruction_statements = instruction_statements[1:]
    # get fields for each instruction that are needed to identify loops
    instructions = OrderedDict()
    color = 0
    first_instruction = True
    loop = 1
    for i in instruction_statements:
      # Regex:
      # Address of Instruction: 0x[0-9a-f]{3,}   ---> "0x"+ 3 or more hex numbers
      # Instruction offset: <\+[0-9]+>
      #   Instruction: [a-z]{3,}
      # Jumping address: (same as address of instruction, but second match of the regex)
      addresses = re.findall(r"0x[0-9a-f]+", i)
      if len(addresses) > 0:
        #print addresses[0]
        addr = int(addresses[0], 16)
        instructions[addr] = i

        inst = re.findall(r"[a-z]{2,}", i)
        if len(inst) > 0:
          inst = inst[0]
          #print inst

        if first_instruction:
          entry_addr = addr
          first_instruction = False

        #print "spliting instr " + str(i)
        if len(addresses) > 1:
          #if "jmpq" == inst or "jge" == inst or "jb" == inst or "jmp" == inst or "jle" == inst:
          if "jmp" == inst or "je" == inst or "jne" == inst or "js" == inst or \
            "jns" == inst or "jg" == inst or "jge" == inst or "jl" == inst or \
            "jle" == inst or "ja" == inst or "jae" == inst or "jb" == inst or \
            "jbe" == inst or "jz" == inst or "jnz" == inst or "jns" == inst or \
            "jnle" == inst or "jnl" == inst or "jnge" == inst or "jng" == inst or \
            "jnbe" == inst or "jnb" == inst or "jnae" == inst or "jna":
            jmp_to_addr = int(addresses[1], 16)
            #print "Processing jump to " + str(jmp_to_addr)
            if jmp_to_addr < addr and jmp_to_addr >= entry_addr:
              print colors.color_list[1] + \
              "We found a loop! From " \
              + str(hex(jmp_to_addr)) + \
              " to " + str(hex(addr)) + colors.nc
              # add color to lines from jump_to_addr to inst_addr
              # needs optimization...
              for a in instructions.keys():
                if a == jmp_to_addr:
                  instructions[a] = " " + \
                      colors.u + \
                      colors.bold + \
                      colors.color_list[color] + \
                      instructions[a] + \
                      "\t\t# loop " + \
                      str(loop) + " starts here!" + colors.nc
                if a > jmp_to_addr and a < addr:
                  # adding color to lines that were alreaddy colored has no effect!!
                  instructions[a] = " " + \
                      colors.color_list[color] + \
                      instructions[a]
                if a == addr:
                  instructions[a] = " " + \
                      colors.u + \
                      colors.bold + \
                      colors.color_list[color] + \
                      instructions[a] + \
                      "\t# loop " + str(loop) + " ends here!" + colors.nc
              # setup next color flag
              if color+1 == len(colors.color_list):
                color = 0
              else:
                color += 1
              # update loop counter
              loop += 1

    # Print colored/non-colored instructions
    for i in instructions.values():
      print i



# Recursion
class RecursionCommand(gdb.Command):
  """ Highlights recursive calls, if any. 

      Usage: show recursion <function_name>"""

  def __init__(self):
    super(RecursionCommand, self).__init__("show recursion",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_SYMBOL)

  def invoke(self, arg, from_tty):
    print "Looking for recursive calls...\n"
    # disassmble the function
    disas = gdb.execute("disas " + arg, to_string=True)
    # make list of instructions
    instruction_statements = disas.split('\n')
    # skip the first line
    instruction_statements = instruction_statements[1:]
    # dictionary of instructions
    instructions = OrderedDict()
    color = 0
    first_instruction = True
    entry_addr = 0x0
    for i in instruction_statements:
      # Find the address of the instruction
      addresses = re.findall(r"0x[0-9a-f]+", i)
      if len(addresses) > 0:
        addr = int(addresses[0], 16)
        instructions[addr] = i

        # Find the instruction
        if first_instruction:
          entry_addr = addr
          first_instruction = False

        inst = re.findall(r"[a-z]{2,}", i)
        if len(inst) > 0:
          inst = inst[0]

        # Check if the instruction is a call/callq
        if len(addresses) > 1:
          if "callq" == inst or "call" == inst:
            # Get the address we are jumping to
            jmp_to_addr = int(addresses[1], 16)

            # If the address is the same as the function entry, it's recursive!
            if jmp_to_addr == entry_addr:
              print colors.color_list[1] + \
              "We found a recursive call! @" + str(addr) + colors.nc
              # Color the disas output line, and add it to our list
              instructions[addr] = colors.u + \
                  colors.bold + \
                  colors.color_list[color] + \
                  instructions[addr] + \
                  "\t# this is a recursive call!" + colors.nc
              # Update the color pointer to the next color
              if color+1 == len(colors.color_list):
                color = 0
              else:
                color += 1
    # Print the colored disas output
    for i in instructions.values():
      print i



# Code
class CodeCommand(gdb.Command):
  """ GDB list function wrapper command. 

      Usage: show code <function_name>"""

  def __init__(self):
    super (CodeCommand, self).__init__("show code",
              gdb.COMMAND_SUPPORT,
              gdb.COMPLETE_SYMBOL)

  def invoke(self, arg, from_tty):
    print colors.bold
    command = "list %s" % arg
    gdb.execute(command)
    print colors.nc



# Memory
class MemoryCommand(gdb.Command):
  """ GDB examine memory wrapper command. 

      Usage: memory"""

  def __init__(self):
    super (MemoryCommand, self).__init__("memory", 
              gdb.COMMAND_SUPPORT)

  def invoke(self, arg, from_tty):
    # Beginners
    if len(arg) == 0:
      # Get the address
      print colors.bold
      address = raw_input("* What is the starting address? ")
      print colors.nc
      # Get the format
      print colors.bold
      print "Available Formats (to display binary, for example, enter b):"
      print colors.nc
      print "  t : binary - 0110 0001"
      print "  o : octal  - 75"
      print "  d : signed decimal - 97"
      print "  u : unsigned decimal - 97"
      print "  x : hexadecimal - 0x61"
      print "  s : string - a"
      print colors.bold
      print_format = raw_input("* What format do you want? ")
      print colors.nc
      #if ((print_format != 't') && (print_format != 'o') && (print_format != 'd') && (print_format != 'u') && (print_format != 'x') && (print_format != 's')):
      # print "Invalid format %s" % print_format
      # return

      # String/Bytes
      if (print_format == 's'):
        # Execute the examine GDB command
        command = "x/s " + address
        print "Executing GDB command... %s" % command
        print colors.bold + colors.green
        gdb.execute(command)
        print colors.nc
      else:
        # Get the number of bytes
        print colors.bold
        num_bytes = raw_input("* How many bytes do you want to display? ")
        print colors.nc
        if int(num_bytes) == 0:
          print "Number of bytes must be a number, not %s" % num_bytes
          return
        # Get the grouping
        print colors.bold
        print "Available Groupings (examples show in hexadcimal):"
        print colors.nc
        print "  b : 0xDE 0xAD 0xBE 0xEF 0xDE 0xAD 0xC0 0xDE"
        print "  h : 0xDEAD 0xBEEF 0xDEAD 0xCODE"
        print "  w : OxDEADBEEF 0xDEADCODE"
        print "  g : 0xDEADBEEFDEADCODE"
        print colors.bold
        groups = raw_input("* What grouping do you want? ")
        print colors.nc
        #if (groups != 'b' && groups != 'h' && groups != 'w' && groups != 'g'):
        # print "Invalid group %s\n" % groups
        # return
        # Execute the examine GDB command
        command = "x/" + num_bytes + groups + print_format + " " + address
        print "Executing GDB command... %s" % command
        print colors.nc
        gdb.execute(command)
        print colors.nc



# Tutorial
class TutorialCommand(gdb.Command):

  def __init__(self):
    super(TutorialCommand, self).__init__("tutorial",
            gdb.COMMAND_SUPPORT)

  def invoke(self, args, from_tty):

    # String for prompt
    prompt = "(s-gdb) "
    wrong_command_1 = "Wrong command! Enter "
    wrong_command_2 = " or quit (to quit this tutorial)."

    # Intro and instructions
    print colors.bold + colors.green
    print "----------------------------------------------------------------"
    print " S-GDB Tutorial"
    print "----------------------------------------------------------------"
    print ""
    print "Welcome! This tutorial features an interactive excersice for"
    print "beginner users to learn more about the power behind binary"
    print "analysis. But with great power, comes great responsability."
    print colors.u + "So please, use these powers responsibly." + colors.nc
    print colors.bold + colors.green + colors.i
    print "You noticed one day that your parents use an interesting program"
    print "to keep track of important things. You birthday is coming up,"
    print "and while you have been hinting for months that you want one of"
    print "those new iPhone 6174, you want to make sure that they really"
    print "got it. You are pretty sure that they wrote down on this secret"
    print "program what gift they got you. You run the program... and bam!"
    print "You parents aren't dumb... their secrets are protected by a"
    print "password.\n" 
    print "The only problem is that you only see the executable... no code!"
    print "This means that you cannot open the notes.c file and read the"
    print "source code to figure out how the program works."
    print "Well... luckily, you have been paying attention during your" 
    print "computer security class. So let's see if we can analyze the"
    print "program and get to the bottom of this: your birthday present!"
    print colors.nc + colors.bold + colors.green
    print " --- To exit this tutorial enter q or quit. ---\n"
    
    # 1. Loading Executable
    print "(1) The first task is to learn more about the program itself."
    print "    So first, let's give GDB access to the binary so we can"
    print "    further analyze it. Since the name of the executable is"
    print "    notes, run the command: file notes" + colors.nc
    # Process command to load the executable into GDB
    command = raw_input(prompt)
    handle_quit(command)
    # Handle input errors
    while (command != "file notes"):
      print wrong_command_1 + "file notes" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    # Execute the actual command
    gdb.execute(command)
  
    # 2. Learning about the program: function list
    print colors.bold + colors.green
    print "(2) Now that the program is loaded, GDB can tell us more about"
    print "    it. Let's see if we can find a list of functions."
    print "    Enter the command: info functions" + colors.nc
    # Process command to list functions in a program
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "info functions"):
      print wrong_command_1 + "into functions" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    # Execute the actual command
    gdb.execute(command)

    # 3. Learning about the program: display function code
    print colors.bold + colors.green
    print "(3) You can see that there is a main function listed. As you"
    print "    know, main is typically where a program starts executing"
    print "    so let's start looking at instructions there."
    print "    Enter the command: disas main" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "disas main"):
      print wrong_command_1 + "disas main" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    # Execute the actual command
    gdb.execute(command)

    # 4, Learning about the program: display info about ????
    print colors.bold + colors.green
    print "(4) By disassembling main, we now have access to the"
    print "    instructions that will be executed when the program"
    print "    is running. There are a lot of hints here, so let's"
    print "    take a deeper look."
    print "    If these instructions look confusing to you, you can"
    print "    use the command: instruction info push, for example." 
    print "    This will display information about the push" 
    print "    instructions."
    print ""
    print "    Enter the command: instruction push" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "instruction push"):
      print wrong_command_1 + "instruction push" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    # Execute command
    gdb.execute(command)

    # 5. Binary Analysis: interpreting instructions & breakpoints
    print colors.bold + colors.green
    print "(5) Let's start by looking at the first 3 instructions in"
    print "    main. The first instruction, push %rbp, and the third"
    print "    instruction, push %rbx, save the current values on"
    print "    those registers so that they function can use them."
    print "    The second instruction, mov %rsp,%rbp, sets the new"
    print "    base of the stack (where the stack begins)."
    print ""
    print "    The fourth instruction, sub $0x186e8,%rsp, moves the"
    print "    stack pointer downwards. This increases the size of"
    print "    the stack by 0x186e8."
    print ""
    print "    The next 5 instructions seem to be setting some values"
    print "    (such as 0x68 into address $rbp-0x186d8)."
    print ""
    print "    If we keep reading down, we find the first clue:fopen."
    print "    The program seems to be using the function fopen to"
    print "    open some file. Let's explore this clue."
    print ""
    print "    Since we know we are looking for either the contents of"
    print "    of your parents secrets or the actual password we are"
    print "    supposed to enter correctly, we can start examining the"
    print "    contents of the memory at each stage. But before we do"
    print "    that, we need to start running the program."
    print ""
    print "    Setup a breakpoint so the program stops running at that"
    print "    point. We choose to stop at the instruction +57."
    print "    Enter the command: b *main+57" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "b *main+57"):
      print wrong_command_1 + "b *main+57" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    gdb.execute(command)

    # 6. Binary Analysis: running a program
    print colors.bold + colors.green
    print "(6) Now, we are ready to start running the program, since"
    print "    we know it will stop at the instruction: mov $0x400988,%edx"
    print "    Enter the command: run" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "run" and command != "r"):
      print wrong_command_1 + "run" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    gdb.execute(command, to_string=True)

    # 7. Binary Analysis: finding the next instruction
    print colors.bold + colors.green
    print "(7) Let's see where we are at right now. To do that, we can"
    print "    use the disassemble command. This command prints all the"
    print "    instructions of the current function executing. Also, there"
    print "    is an arrow on the left that marks the next instruction to"
    print "    be executed."
    print ""
    print "    Enter the command: disas" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "disas" and command != "disassemble"):
      print wrong_command_1 + "disas" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    gdb.execute(command)

    # 8. Binary Analysis: stepping through the instructions
    print colors.bold + colors.green
    print "(8) As expected (since we added a breakpoint at main+57), the"
    print "    instruction to be executed will be: mov $0x400988,%edx."
    print "    Let's run the program for 4 instructions so the next"
    print "    instruction to be executed is callq 0x4005e8."
    print "    Enter the command: stepi 4" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "stepi 4" and command != "si 4"):
      print wrong_command_1 + "stepi 4" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    gdb.execute(command, to_string=True)

    # 9. Binary Analysis: reading strings in memory
    print colors.bold + colors.green
    print "(9) Let's take a look at the arguments passed to the fopen"
    print "    function. We might be able to find some useful string"
    print "    at addresses 0x400988 and 0x40098a. So let's use the"
    print "    memory command to help us."
    print "    Enter the command: memory"
    print "    When asked, enter 0x400988 for the address and s for"
    print "    the format (since we want to print strings at that"
    print "    address, if there are any)" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "memory"):
      print wrong_command_1 + "memory" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    gdb.execute(command)

    # 10. Binary Analysis: reading more strings
    print colors.bold + colors.green
    print "(10) Mmmm.. So at address 0x400988 there is a \"r\"."
    print "     That probably means that the program is opening"
    print "     a file with the reading flag. Let's look at the"
    print "     next address (0x40098a) and see if there is also"
    print "     a useful string there as well."
    print "     Enter the command: memory" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "memory"):
      print wrong_command_1 + "memory" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    gdb.execute(command)

    # 11. Binary Analysis: stepping through
    print colors.bold + colors.green
    print "(11) Awesome! Looks like the secrets are in some file"
    print "     called user.db. Okay, now let's keep executing"
    print "     instructions."
    print "     Enter the command: stepi" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "stepi" and command != "si"):
      print wrong_command_1 + "stepi" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    gdb.execute(command, to_string=True)

    # 12/13. Binary Analysis: the finish command
    print colors.bold + colors.green
    print "(12) Since the instruction we just executed was a call"
    print "     instruction, the program's current function is no"
    print "     longer main. We can see that by running disas again."
    print "     Enter the command: disas" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "disas"):
      print wrong_command_1 + "disas" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    gdb.execute(command)

    print colors.bold + colors.green
    print "(13) Looks like the current function being run is fopen"
    print "     (which is expected). Let's get back to main. To do"
    print "     do this, run the finish command (which executes all"
    print "     instructions until it gets back to the caller: main)."
    print "     Enter the command: finish" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "finish" and command != "fin"):
      print wrong_command_1 + "finish" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    gdb.execute(command)

    # 14. Binary Analysis: analyzing fscanf
    print colors.bold + colors.green
    print "(14) Now we are back in main, and if we look further to"
    print "     instruction +109, we can see that there is a call"
    print "     being made to fscanf. Typically, fscanf is used to"
    print "     read contents into some buffer (perhaps an array),"
    print "     so let's look at the arguments being passed to"
    print "     fscanf."
    print "     Enter the command: memory"
    print "     (Address: 0x400992 and Format: s)" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "memory"):
      print wrong_command_1 + "memory" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    gdb.execute(command)

    # 15. Binary Analysis: analyzing fscanf
    print colors.bold + colors.green
    print "(15) So at address 0x400992, we find what looks like a"
    print "     string formatter. %[^~] matches all characters until"
    print "     the character: ~. Let's keep looking ahead. The next"
    print "     instruction seems to be saving the address of the"
    print "     stack at offset 0x186d0 into the register rdx. This"
    print "     might be a useful address after fscanf gets executed,"
    print "     so let's not forget about it."
    print "     The instruction: mov -0x18(%rbp),%rax will put the"
    print "     value that was at address rbp-0x18 into rax."
    print "     What could be so special about the value in rbp-0x18?"
    print "     If we look back to instruction +78, we can see that"
    print "     the returned value by fopen (which is a pointer to a"
    print "     file) is being stored in rbp-0x18. This makes sense,"
    print "     the program must be reading the contents of the file"
    print "     and placing them in the stack (at address rbp-0x186d0)"
    print "     until the ~ character is found on the file."
    print "     Let's execute the code until fscanf to test our theory."
    print "     Enter the command: stepi 8" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "stepi 8" and command != "si 8"):
      print wrong_command_1 + "stepi 8" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    gdb.execute(command, to_string=True)

    print colors.bold + colors.green
    print "     Now, enter the command: finish" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "finish" and command != "fin"):
      print wrong_command_1 + "finish" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    gdb.execute(command, to_string=True)

    # 16. Binary Analysis: examining the stack
    print colors.bold + colors.green
    print "(16) Now, let's use the memory command to see if there is"
    print "     any useful string at address rbp-0x186d0. To do this,"
    print "     we can use the memory command, and when asked for the"
    print "     starting address, we can use the variable name $rbp,"
    print "     since GDB automatically has variables (they all start"
    print "     with $) for all the registers."
    print "     Enter the command: memory"
    print "     (Address: $rbp-0x186d0 and Format: s)" + colors.nc
    command = raw_input(prompt)
    handle_quit(command)
    while (command != "memory"):
      print wrong_command_1 + "memory" + wrong_command_2
      command = raw_input(prompt)
      handle_quit(command)
    gdb.execute(command)

    # We found the secret!
    print colors.nc + colors.i
    print "Woohoo!! There it is!! Looks like we are getting an iPhone 6174"
    print "after all... and a trip to Miami!"
    print ""
    print "Can you keep using these techniques to find the actual password?"
    print "You might find these commands useful:"
    print " show loops main"
    print " instruction info cmp"
    print ""
    print "Good luck on your quest!"
    print colors.nc


# Make commands available!
print colors.bold
print "Loading S-GDB..."
print colors.nc
InstructionsCommand()
LoopsCommand()
RecursionCommand()
CodeCommand()
MemoryCommand()
TutorialCommand()
