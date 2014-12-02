#!/usr/bin/python

'''
Author: 
	upbit
Date:
	2014-12-02
Purpose:
	disassemble code by Capstone Engine
Usage:
	add the following line to ~/.lldbinit
	command script import ~/.lldb/dis_capstone.py
'''

import lldb
import shlex
import optparse
from capstone import *
from capstone.arm import *

bytes_to_hex = lambda bytes: " ".join([ "%.2X"%int(bytes[i]) for i in range(len(bytes)) ])

def __lldb_init_module (debugger, dict):
	debugger.HandleCommand('command script add -f dis_capstone.dis_capstone discs')
	print 'The "discs (dis_capstone)" command has been installed'

def _is_cpsr_thumb(frame):
	""" Check Thumb flag from CPSR """
	try:
		regs = frame.GetRegisters()[0]
		cpsr = [reg for reg in regs if reg.GetName()=='cpsr'][0]
		thumb_bit = int(cpsr.GetValue(), 16) and 0x20
		return thumb_bit >> 5
	except:
		return 0

def create_command_arguments(command):
	return shlex.split(command)

def create_options_parser():
	usage = "Usage: %prog (-s <addr>) (-l <len>) (-A <arm|arm64>) (-M <arm|thumb>)"
	parser = optparse.OptionParser(prog='discs', usage=usage)
	parser.add_option('-s', '--start-addr', dest='start_addr', help='start address (default: pc)', default=None)
	parser.add_option('-l', '--length', dest='length', help='decode bytes length (default: 32)', default=32)
	parser.add_option('-A', '--arch', dest='arch', help='arch type: arm,arm64 (default: arm)', default="arm")
	parser.add_option('-M', '--mode', dest='mode', help='mode type: arm,thumb (auto select by cpsr[b:5])', default=None)
	return parser


def real_disassemble(debugger, start_addr, disasm_length, disasm_arch, disasm_mode):
	""" Disassemble code with target arch/mode """

	target = debugger.GetSelectedTarget()
	process = target.GetProcess()
	thread = process.GetSelectedThread()
	frame = thread.GetSelectedFrame()

	# read bytes
	error = lldb.SBError()
	bytes = process.ReadMemory(start_addr, disasm_length, error)

	if error.Success():
		# decode with capstone
		md = Cs(disasm_arch, disasm_mode)
		isFirstLine = True
		for insn in md.disasm(bytes, start_addr):
			if (isFirstLine):
				print("-> 0x%x:  %-16s %-8s %s" % (insn.address, bytes_to_hex(insn.bytes), insn.mnemonic, insn.op_str))
				isFirstLine = False
				continue

			print("   0x%x:  %-16s %-8s %s" % (insn.address, bytes_to_hex(insn.bytes), insn.mnemonic, insn.op_str))

	else:
		print "[ERROR] ReadMemory(0x%x): %s" % (start_addr, error)


def dis_capstone(debugger, command, result, dict):
	""" command entry: dis_capstone """

	cmd_args = create_command_arguments(command)
	parser = create_options_parser()

	try:
		(options, args) = parser.parse_args(cmd_args)
	except:
		return

	target = debugger.GetSelectedTarget()
	process = target.GetProcess()
	thread = process.GetSelectedThread()
	frame = thread.GetSelectedFrame()

	# start_addr
	try:
		start_addr = int(options.start_addr, 0)
	except:
		start_addr = frame.GetPCAddress().GetLoadAddress(target)
	# length
	disasm_length = options.length

	# arch
	disasm_arch = CS_ARCH_ARM
	if (options.arch == "arm64"):
		disasm_arch = CS_ARCH_ARM64

	# auto select mode by cpsr
	if _is_cpsr_thumb(frame):
		disasm_mode = CS_MODE_THUMB
	else:
		disasm_mode = CS_MODE_ARM


	# force apply --mode options
	if (options.mode == "arm"):
		disasm_mode = CS_MODE_ARM
	elif (options.mode == "thumb"):
		disasm_mode = CS_MODE_THUMB

	# force arm64 use arm mode
	if (options.arch == "arm64"):
		disasm_mode = CS_MODE_ARM


	##
	real_disassemble(debugger, start_addr, disasm_length, disasm_arch, disasm_mode)

