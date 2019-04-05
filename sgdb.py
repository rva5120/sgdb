#################################################
# S-GDB : Student GDB				#
# 						#
# Colorful interface for students learning	#
# about reverse engineering for the first time.	#
#						#
# Author : @rva5120				#
#################################################

#####################
# Supported Commands:
#	show loops <function name> : colors loops and nested loops on a function
#	show recursion <function name> : colors recursive calls on a function
#	
#####################

#########################################################################
# How do I run this script?						#
#  GDB runs a python interpreter and has its own module available to	#
#  import (gdb). To use this script, you can use one of two methods:	#
#	(1) Add the line "source sgdb.py" to your .gdbinit		#
#	(2) Directly run "source sgdb.py" on gdb			#
#									#
# Can I import other modules (like nltk, for example)?			#
#  Yes, just install the module like you normally would (using pip)	#
#									#
# How can I add new commands?						#
#  GDB expects commands to be wrapped in a gdb.Command subclass. So	#
#  you need to create a new class and define two methods:		#
#	(1) __init__ : defines the command and argument types		#
#	(2) invoke : defines the behavior of the command		#
#									#
# Useful resources:							#
# 	Reversing: Secrets of Reverse Engineering (Wiley)		#
#	GDB Python API: https://sourceware.org/gdb/onlinedocs/gdb/	#
#				Python-API.html#Python-API		#
#	Tutorial: http://tromey.com/blog/?p=501				#
#########################################################################


# Imports
from __future__ import with_statement
from collections import OrderedDict
import gdb 	# module defined by GDB, cannot be used outside of gdb
import re



# Example command
class SaveBreakpointsCommand(gdb.Command):
	"""Save the current breakpoints to a file.
	This command takes a single argumen, a file
	name.
	The breakpoint can be restored using the
	'source' command."""

	# The Command initializer (gdb.Command) sets up the "save breakpoints" command
	# to be processed.
	# Agument: filename (we use built-in gdb.COMPLETE_FILENAME completer to indicate this)
	# completion on the cmd line will work properly with files
	#
	# __init__(name, command_class [, completer_class [,prefix]])
	# 	 name: 
	def __init__(self):
		super (SaveBreakpointsCommand, self).__init__("save breakpoints", 
							gdb.COMMAND_SUPPORT, 
							gdb.COMPLETE_FILENAME)

	# this method is called by gdb when the command is executed from the CLI
	# two args are passed: a string (arg) if there is an argument or None otherwise
	# the second argument is a boolean (from_tty), and is False if the cmd comes from a script
	# task: loop over all breakpoints, and write a representation of each one to f
	#       
	def invoke(self, arg, from_tty):
		with open(arg, 'w') as f:
			for bp in gdb.get_breakpoints():
				print >> f, "break", bp.get_location(),
				if bp.get_thread() is not None:
					print >> f, " thread", bp.get_thread(),
				if bp.get_condition() is not None:
					print >> f, " if", bp.get_condition(),
				print >> f
				if not bp.is_enabled():
					print >> f, "disable $bpnum"
				# Note: we do not save the ignore count; no point.
				commands = bp.get_commands()
				if commads is not None:
					print >> f, "commands"
					# COMMANDS has a trailing newline
					print >> f, commands,
					print >> f, "end"
				print >> f

class colors():
	red = "\033[31m"
	green = "\033[32m"
	yellow = "\033[33m"
	blue = "\033[34m"
	pink = "\033[35m"
	cyan = "\033[36m"
	bold = "\033[1m"
	u = "\033[4m"
	nc = "\033[0m"
	color_list = [red, green, yellow, blue, pink, cyan]


# Loops
class LoopsCommand(gdb.Command):
	""" Prints the current disassembled function
	and highligts the loops, if any."""

	# Describe the command to be processed: show loops in function_name
	# Argument: function name
	def __init__(self):
		super(LoopsCommand, self).__init__("show loops",
						gdb.COMMAND_SUPPORT,
						gdb.COMPLETE_SYMBOL)

	# Task: run "disas func_name", get the output from GDB,
	#	find the loops, and wrap the proper lines with color changing tags
	def invoke(self, arg, from_tty):
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
		loop = 1
		for i in instruction_statements:
			# Regex:
			#	Address of Instruction: 0x[0-9a-f]{3,}   ---> "0x"+ 3 or more hex numbers
			#	Instruction offset: <\+[0-9]+>
			# 	Instruction: [a-z]{3,}
			#	Jumping address: (same as address of instruction, but second match of the regex)
			addresses = re.findall(r"0x[0-9a-f]+", i)
			if len(addresses) > 0:
				#print addresses[0]
				addr = int(addresses[0], 16)
				instructions[addr] = i

				inst = re.findall(r"[a-z]{2,}", i)
				if len(inst) > 0:
					inst = inst[0]
					#print inst

				#print "spliting instr " + str(i)
				if len(addresses) > 1:
					if "jmpq" == inst or "jge" == inst:
						jmp_to_addr = int(addresses[1], 16)
						#print "Processing jump to " + str(jmp_to_addr)
						if jmp_to_addr < addr:
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
	""" Highlights recursive calls, if any. """

	def __init__(self):
		super(RecursionCommand, self).__init__("show recursion",
						gdb.COMMAND_SUPPORT,
						gdb.COMPLETE_SYMBOL)

	def invoke(self, arg, from_tty):
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



LoopsCommand()
RecursionCommand()
