#################################################
# S-GDB : Student GDB														#
# -------------------														#
# Colorful interface for students learning			#
# about reverse engineering for the first time.	#
#																								#
# Author : @rva5120															#
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
#																examine memory at a given address
#     memory addr=<address> num_bytes=<number_of_bytes> format=<b,o,d,x,s> grouped_by=<1,2,4,8>
#     memory <address> <number_of_bytes> <format> <group>
#
#  tutorial : starts a tutorial to help you learn about GDB
#####################

#########################################################################
# How do I run this script?																							#
# -------------------------																							#
#  GDB runs a python interpreter and has its own module available to		#
#  import (gdb). To use this script, you can use one of two methods:		#
#	(1) Add the line "source sgdb.py" to your .gdbinit										#
#	(2) Directly run "source sgdb.py" on gdb															#
#																																				#
# Can I import other modules (like nltk, for example)?									#
#  Yes, just install the module like you normally would (using pip)			#
#																																				#
# How can I add new commands?																						#
#  GDB expects commands to be wrapped in a gdb.Command subclass. So			#
#  you need to create a new class and define two methods:								#
#	(1) __init__ : defines the command and argument types									#
#	(2) invoke : defines the behavior of the command											#
#																																				#
# Useful resources:																											#
# 	Reversing: Secrets of Reverse Engineering (Wiley)										#
#	GDB Python API: https://sourceware.org/gdb/onlinedocs/gdb/						#
#				Python-API.html#Python-API																			#
#	Tutorial: http://tromey.com/blog/?p=501																#
#########################################################################


# Imports
from __future__ import with_statement
from collections import OrderedDict
import gdb 	# module defined by GDB, cannot be used outside of gdb
import re



# Example command
class SaveBreakpointsCommand(gdb.Command):
	"""Description of the command"""

	# The Command initializer (gdb.Command) sets up the "save breakpoints" command
	# to be processed.
	# Agument: filename (we use built-in gdb.COMPLETE_FILENAME completer to indicate this)
	# completion on the cmd line will work properly with files
	#
	# __init__(name, command_class [, completer_class [,prefix]])
	# 	 name: 
	def __init__(self):
		super (SaveBreakpointsCommand, self).__init__("command name", 
							gdb.COMMAND_SUPPORT, 
							gdb.COMPLETE_FILENAME)

	# this method is called by gdb when the command is executed from the CLI
	# two args are passed: a string (arg) if there is an argument or None otherwise
	# the second argument is a boolean (from_tty), and is False if the cmd comes from a script
	# task: loop over all breakpoints, and write a representation of each one to f
	#       
	def invoke(self, arg, from_tty):
		pass



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
	nc = "\033[0m"
	color_list = [red, green, yellow, blue, pink, cyan]

# Check that input is a number
def is_num(i):
	try:
		int(i)
		return True
	except ValueError:
		return False



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
	""" Highlights recursive calls, if any. 

			Usage: show recursion <function_name>"""

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
			#	print "Invalid format %s" % print_format
			#	return

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
				#	print "Invalid group %s\n" % groups
				#	return
				# Execute the examine GDB command
				command = "x/" + num_bytes + groups + print_format + " " + address
				print "Executing GDB command... %s" % command
				print colors.bold + colors.green
				gdb.execute(command)
				print colors.nc



# Tutorial



# Make commands available!
print colors.bold
print "Loading S-GDB..."
print colors.nc
LoopsCommand()
RecursionCommand()
CodeCommand()
MemoryCommand()
