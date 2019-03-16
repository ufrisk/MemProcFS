#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from pypykatz.commons.common import KatzSystemArchitecture, KatzSystemInfo

from vmmpy import *
import copy

class Module:
	def __init__(self):
		self.name = None
		self.baseaddress = None
		self.size = None
		self.endaddress = None
		self.pages = []
		
		self.versioninfo = None
		self.checksum = None
		self.timestamp = None
		
	def inrange(self, addr):
		return self.baseaddress <= addr < self.endaddress
		
	def parse(data, timestamp = None):
		m = Module()
		m.name = data['name']
		m.baseaddress = data['va']
		m.size = data['size']
		m.endaddress = m.baseaddress + m.size
		
		m.timestamp = timestamp
		
		return m
		
	
		
		"""
			m.versioninfo = None
			m.checksum = None
			m.timestamp = None
		"""
		
	def __str__(self):
		return '%s %s %s %s %s' % (self.name, hex(self.baseaddress), hex(self.size), hex(self.endaddress), self.timestamp )
		
class Page:
	def __init__(self):
		self.BaseAddress = None
		self.AllocationBase  = None
		self.AllocationProtect  = None
		self.RegionSize  = None
		self.EndAddress = None
		
		self.data = None
	
	@staticmethod
	def parse(page_info, module):
		p = Page()
		p.BaseAddress = page_info['VirtualAddress'] + module.baseaddress
		p.AllocationBase  = None #page_info['VirtualAddress'] ???? TODO
		p.AllocationProtect  = None #page_info['VirtualAddress'] ???? TODO
		p.RegionSize  = min(page_info['SizeOfRawData'], 100*1024*1024) # TODO: need this currently to stop infinite search
		p.EndAddress  = p.BaseAddress + p.RegionSize
		return p
	
	@staticmethod
	def parse_raw(page_info):
		p = Page()
		p.BaseAddress = page_info['va']
		p.AllocationBase  = None #page_info['VirtualAddress'] ???? TODO
		p.AllocationProtect  = None #page_info['VirtualAddress'] ???? TODO
		p.RegionSize  = min(page_info['size'], 100*1024*1024) # TODO: need this currently to stop infinite search
		p.EndAddress  = p.BaseAddress + p.RegionSize
		return p
		
	def read_data(self, pid):
		self.data = VmmPy_MemRead(pid, self.BaseAddress, self.RegionSize)
		
	def inrange(self, addr):
		return self.BaseAddress <= addr < self.EndAddress
		
	def search(self, pattern, pid):
		if len(pattern) > self.RegionSize:
			return []
		data = VmmPy_MemRead(pid, self.BaseAddress, self.RegionSize)
		fl = []
		offset = 0
		while len(data) > len(pattern):
			marker = data.find(pattern)
			if marker == -1:
				return fl
			fl.append(marker + offset + self.BaseAddress)
			data = data[marker+1:]
			offset = marker + 1
				
		return fl
	
	def __str__(self):
		return '0x%08x 0x%08x %s 0x%08x' % (self.BaseAddress, self.AllocationBase, self.AllocationProtect, self.RegionSize)
		
		
class MemProcFsReader:
	def __init__(self, process_name = 'lsass.exe', filename = None):
		self.filename = filename
		self.process_name = process_name
		self.sysinfo = None
		self.process_pid = None
		self.current_position = None
		self.modules = []
		
		
		self.setup()
		
	def get_sysinfo(self):
		self.sysinfo = KatzSystemInfo()
		
		
		print('[+] Getting BuildNumer')
		self.sysinfo.buildnumber = 15063 #TODO: get author to give an api that retrieves the actual buildnumber!
		print('[+] Found BuildNumber %s' % self.sysinfo.buildnumber)
		
		print('[+] Getting msv_dll_timestamp')
		self.sysinfo.msv_dll_timestamp = 1552469969#TODO: get author to give an api that retrieves the actual timestamp!
		print('[+] Found msv_dll_timestamp %s' % self.sysinfo.msv_dll_timestamp)
		
		
		print('[+] Getting arch')
		self.sysinfo.architecture = KatzSystemArchitecture.X64 #TODO: ask author where I can poll this info from!
		print('[+] Got arch %s' % self.sysinfo.architecture)

		
	def setup(self):
		
		if self.filename:
			# if filename is specified we dont want to use the virtual FS, but then we need to init the vmmpy module
			VmmPy_Initialize(["-device", self.filename,'-vv'])
		
		self.get_sysinfo()
		
		print('[+] Searching LSASS')
		self.process_pid = VmmPy_PidGetFromName(self.process_name)
		print('[+] Found LSASS on PID %s' % self.process_pid)
		
		print('[+] Getting modules info')
		for moduleinfo in VmmPy_ProcessGetModuleMap(self.process_pid):
			#print('moduleinfo: %s' % str(moduleinfo))
			m = Module.parse(moduleinfo)
			for pageinfo in VmmPy_ProcessGetSections(self.process_pid, m.name):
				#print('pageinfo: %s' % str(pageinfo))
				m.pages.append(Page.parse(pageinfo, m))
				
			self.modules.append(m)
				
		print('[+] Got modules info')	
			
		
	def get_module_by_name(self, module_name):
		for mod in self.modules:
			if mod.name.lower().find(module_name.lower()) != -1:
				return mod
		return None	
	
	def find_in_module(self, module_name, pattern):
		mod = self.get_module_by_name(module_name)
		if mod is None:
			raise Exception('Could not find module! %s' % module_name)
		t = []
		for page in mod.pages:
			t += self.find(page.BaseAddress, page.EndAddress, pattern)
		return t
		
	@staticmethod
	def find_all_pattern(data, pattern):
		substring_length = len(pattern)    
		def recurse(locations_found, start):
			location = data.find(pattern, start)
			if location != -1:
				return recurse(locations_found + [location], location+substring_length)
			else:
				return locations_found

		return recurse([], 0)
		
	def find(self, start, end, pattern):
		"""
		Searches for all occurrences of a pattern in the current memory segment, returns all occurrences as a list
		"""
		data = VmmPy_MemRead(self.process_pid, start, end - start)
		pos = []
		for p in MemProcFsReader.find_all_pattern(data, pattern):
			pos.append( p + start)
		return pos
		
	def seek(self, offset, whence = 0):
		"""
		Changes the current address to an offset of offset. 
		"""
		self.current_position += offset
		return
		
	def move(self, address):
		"""
		Moves the buffer to a virtual address specified by address
		"""
		self.current_position = address
		return
		
	def align(self, alignment = None):
		"""
		Repositions the current reader to match architecture alignment
		"""
		if alignment is None:
			if self.sysinfo.architecture == KatzSystemArchitecture.X64:
				alignment = 8
			else:
				alignment = 4
		offset = self.current_position % alignment
		if offset == 0:
			return
		offset_to_aligned = (alignment - offset) % alignment
		self.seek(offset_to_aligned, 1)
		return
		
	def tell(self):
		"""
		Returns the current virtual address
		"""
		return self.current_position
		
	def peek(self, length):
		t = self.current_position
		data = self.read(length)
		self.current_position = t
		
		return data
	
	def read(self, size = -1):
		data = VmmPy_MemRead(self.process_pid, self.current_position, size)
		self.current_position += size
		return data
	
	def read_int(self):
		"""
		Reads an integer. The size depends on the architecture. 
		Reads a 4 byte small-endian singed int on 32 bit arch
		Reads an 8 byte small-endian singed int on 64 bit arch
		"""
		if self.sysinfo.architecture == KatzSystemArchitecture.X64:
			return int.from_bytes(self.read(8), byteorder = 'little', signed = True)
		else:
			return int.from_bytes(self.read(4), byteorder = 'little', signed = True)
	
	def read_uint(self):
		"""
		Reads an integer. The size depends on the architecture. 
		Reads a 4 byte small-endian unsinged int on 32 bit arch
		Reads an 8 byte small-endian unsinged int on 64 bit arch
		"""
		if self.sysinfo.architecture == KatzSystemArchitecture.X64:
			return int.from_bytes(self.read(8), byteorder = 'little', signed = False)
		else:
			return int.from_bytes(self.read(4), byteorder = 'little', signed = False)
		
	def get_ptr(self, pos):
		self.move(pos)
		return self.read_uint()
	
	def get_ptr_with_offset(self, pos):
		if self.sysinfo.architecture == KatzSystemArchitecture.X64:
			self.move(pos)
			ptr = int.from_bytes(self.read(4), byteorder = 'little', signed = True)
			return pos + 4 + ptr
		else:
			self.move(pos)
			return self.read_uint()
		
