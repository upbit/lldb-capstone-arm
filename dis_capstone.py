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

def create_command_arguments(command):
	return shlex.split(command)

def create_options_parser():
	usage = """Usage: %prog (-s 0x0001E045)
		-s   --start-addr     start address (default: pc)
		-l   --length         decode bytes length (default: 32)
		-A   --arch           arch type: arm,arm64 (default: arm)
		-M   --mode           mode type: arm,thumb (default: thumb)
	"""
	parser = optparse.OptionParser(prog='discs', usage=usage)
	parser.add_option('-s', '--start-addr', dest='start_addr', default="")
	parser.add_option('-l', '--length', dest='length', default=32)
	parser.add_option('-A', '--arch', dest='arch', default="arm")
	parser.add_option('-M', '--mode', dest='mode', default="thumb")
	return parser

def dis_capstone(debugger, command, result, dict):
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

	# start_addr and length
	addr_string = options.start_addr.strip()
	if (len(addr_string) > 0):
		start_addr = int(addr_string, 0)
	else:
		start_addr = frame.GetPCAddress().GetLoadAddress(target)
	disa_length = options.length

	#print "[-] dis_capstone 0x%x with (%s,%s):" % (start_addr, options.arch, options.mode)

	# arch and mode
	disa_mode = CS_MODE_THUMB
	if (options.mode == "arm"):
		disa_mode = CS_MODE_ARM
	disa_arch = CS_ARCH_ARM
	if (options.arch == "arm64"):
		disa_arch = CS_ARCH_ARM64
		disa_mode = CS_MODE_ARM			# arm64 has no thumb mode, so default to mode arm

	# read bytes
	error = lldb.SBError()
	bytes = process.ReadMemory(start_addr, disa_length, error)

	if error.Success():
		# decode with capstone
		md = Cs(disa_arch, disa_mode)
		isFirstLine = True
		for insn in md.disasm(bytes, start_addr):
			if (isFirstLine):
				print("-> 0x%x:  %-16s %-8s %s" % (insn.address, bytes_to_hex(insn.bytes), insn.mnemonic, insn.op_str))
				isFirstLine = False
				continue

			print("   0x%x:  %-16s %-8s %s" % (insn.address, bytes_to_hex(insn.bytes), insn.mnemonic, insn.op_str))

	else:
		print "[ERROR] ReadMemory(0x%x): %s" % (start_addr, error)

