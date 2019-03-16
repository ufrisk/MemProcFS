from vmmpy import *
from vmmpyplugin import *
import json
import traceback
import datetime

# globals needed for FS
lsass_pid = None
all_secrets = '' #all secrets extracted from lsass in json format
luids = {} #secrets per-luid (logon session) in txt format
domains = {}
kerberos = {}

last_refresh_time = None
refresh_needed = False
refresh_interval = 30
first_run = True

import_failed = None
parsing_failed = None

import_error_text_template = """
The imports for pypykatz plugin have failed at some point.
Common causes:
	1. You dont have pypykatz installed
	2. Python runtime environment used by MemProcFs is not the same as you have installed pypykatz in.
	3. You are not using the correct python version
	
Error traceback:
%s
"""

parsing_error_template = """
pypykatz plugin tried to parse the lsass.exe process in your memory dump but failed.
This could be caused by multiple things:
	1. The pypykatz's parser code is potato
	2. MemProcFs could not fully parse the memory, usually this happens with incorrect memory dump files.
		Check for error strings like "Could not load segment data"
		
In case you are cretain the problem is caused by the parser, 
please submit an issue with the info below this line:
%s

%s
"""

import_error_text = None
parsing_error_text = None

try:
	from pypykatz.pypykatz import pypykatz
	from pypykatz.commons.common import UniversalEncoder
	from plugins.pym_pypykatz.pypyreader import MemProcFsReader
	
	#this needs to be the last line!
	import_failed = False
	
	
except Exception as e:
	import_failed = True
	traceback.print_exc()
	import_error_text = import_error_text_template % traceback.format_exc()
	pass

def process_lsass():
	"""
	Processing lsass.exe with pypykatz, storing the results in the globals
	
	"""
	global all_secrets
	global luids
	global lsass_pid
	global domains
	global kerberos
	global last_refresh_time
	global parsing_error_text
	global parsing_failed
	
	basic_info = ''
	try:
		memreader = MemProcFsReader()
		
		basic_info =  '===== BASIC INFO. SUBMIT THIS IF THERE IS AN ISSUE =====\r\n'
		basic_info += 'CPU arch: %s\r\n' % memreader.sysinfo.architecture.name
		basic_info += 'OS: %s\r\n' % memreader.sysinfo.operating_system
		basic_info += 'BuildNumber: %s\r\n' % memreader.sysinfo.buildnumber
		basic_info += 'MajorVersion: %s\r\n' % memreader.sysinfo.major_version
		basic_info += 'MSV timestamp: %s\r\n' % memreader.sysinfo.msv_dll_timestamp
		
		
		lsass_pid = memreader.process_pid

		mimi = pypykatz(memreader, memreader.sysinfo)
		mimi.start()
		
		all_secrets = json.dumps(mimi, cls = UniversalEncoder, indent=4, sort_keys=True)
		for luid in mimi.logon_sessions:
			luids[str(luid)] = str(mimi.logon_sessions[luid])
			for kc in mimi.logon_sessions[luid].kerberos_creds:
				for ticket in kc.tickets:
					if str(luid) not in kerberos:
						kerberos[str(luid)] = []
					kerberos[str(luid)].append(ticket.to_asn1().dump())
			domain = mimi.logon_sessions[luid].domainname
			user = mimi.logon_sessions[luid].username
			
			if domain == '':
				domain = 'local'
			
			if user == '':
				user = 'empty'
			
			if domain not in domains:
				domains[domain] = {}
			if user not in domains[domain]:
				domains[domain][user] = {}
				
			domains[domain][user][str(luid)] = str(mimi.logon_sessions[luid])
		
		last_refresh_time = datetime.datetime.utcnow()
		parsing_failed = False
			
	except Exception as e:
		parsing_failed = True
		traceback.print_exc()
		parsing_error_text = parsing_error_template % (basic_info, traceback.format_exc()) 
		pass
		
	
def ReadAllResults(pid, file_name, file_attr, bytes_length, bytes_offset):
	"""
	reads the all_results data as file on the virtual FS
	"""
	if pid != lsass_pid:
		return None
	
	return all_secrets[bytes_offset:bytes_offset+bytes_length].encode()

def ReadLuid(pid, file_name, file_attr, bytes_length, bytes_offset):
	"""
	reads the secrets for a specific luid data as file on the virtual FS
	"""
	try:
		if pid != lsass_pid:
			return None
		
		luid = file_name.rsplit('.', 1)[0]
		if luid.find('_') != -1:
			luid = luid.split('_')[1]
		return luids[luid].encode()[bytes_offset:bytes_offset+bytes_length]
	
	except Exception as e:
		traceback.print_exc()
		return None
		
def ReadKerberos(pid, file_name, file_attr, bytes_length, bytes_offset):
	try:
		if pid != lsass_pid:
			return None
		
		t = file_name.rsplit('.', 1)[0]
		luid, pos = t.split('_')
		data = kerberos[luid][int(pos)]
		
		return data[bytes_offset:bytes_offset+bytes_length]
		
	except Exception as e:
		traceback.print_exc()
		return None
		
def ReadErrors(pid, file_name, file_attr, bytes_length, bytes_offset):
	try:
		if pid != lsass_pid:
			return None
			
		if file_name == 'import_error.txt':
			return import_error_text.encode()[bytes_offset:bytes_offset+bytes_length]
		if file_name == 'parsing_error.txt':
			return parsing_error_text.encode()[bytes_offset:bytes_offset+bytes_length]
			
	except Exception as e:
		traceback.print_exc()
		return None	

def List(pid, path):
	#
	# List function - this module employs a dynamic list function - which makes
	# it responsible for providing directory listings of its contents in a
	# highly optimized way. It is very important that the List function is as
	# speedy as possible - to avoid locking up the file system.
	#
	# First check the directory to be listed. Only the module root directory is
	# allowed. If it's not the module root directory return None.
	global first_run
	try:
		
		if pid != lsass_pid:
			return None
			
		if path[:7] != 'secrets':
			return None
			
		if first_run == True:
			process_lsass()
			first_run = False
			
		if import_failed == True:
			print(import_failed)
			result = {
				'import_error.txt': {'size': len(import_error_text), 'read': ReadErrors, 'write': None},
			}
			return result
		
		if parsing_failed == True:
			result = {
				'parsing_error.txt': {'size': len(parsing_error_text), 'read': ReadErrors, 'write': None},
			}
			return result
		

		if (datetime.datetime.utcnow() - last_refresh_time).total_seconds() > refresh_interval and refresh_needed == True:
			# invoking function that processes the lsass.exe
			process_lsass()
		
		if path == 'secrets':
			result = {
				'all_results.json': {'size': len(all_secrets), 'read': ReadAllResults, 'write': None},
			}
			result['by_luid'] = {'dirs' : True}
			result['by_domain'] = {'dirs' : True}
			result['kerberos'] = {'dirs' : True}
			return result
		
		if path == 'secrets/by_luid':
			result = {}
			for luid in luids:
				result['%s.txt' % luid] = {'size': len(luids[luid]), 'read': ReadLuid, 'write': None}
			return result
		
		if path == 'secrets/by_domain':
			result = {}
			for domain in domains:
				result[domain] = {'dirs' : True}			
			return result
		
		if path.find('secrets/by_domain/') == 0:
			result = {}
			domain = path.rsplit('/',1)[1]
			for user in domains[domain]:
				for luid in domains[domain][user]:
					result['%s_%s.txt' % (user, luid)] = {'size': len(luids[luid]), 'read': ReadLuid, 'write': None}
			return result
		
		if path == 'secrets/kerberos':
			result = {}
			for luid in kerberos:
				result[luid] = {'dirs' : True}			
			return result
			
		if path.find('secrets/kerberos/') == 0:
			
			luid = path.rsplit('/',1)[1]
			result = {}
			for i, ticket in enumerate(kerberos[luid]):
				result['%s_%s.kirbi' % (luid, i)] = {'size': len(ticket), 'read': ReadKerberos, 'write': None}
			
			return result
	
	except Exception as e:
		traceback.print_exc()
		return None
	
	else:
		return result


def Close():
	# Nothing to clean up here for this plugin -> do nothing!
	pass


def Initialize(target_system, target_memorymodel):
	global lsass_pid
	global refresh_needed
	# Check that the operating system is 32-bit or 64-bit Windows. If it's not
	# then raise an exception to terminate loading of this module.
	if target_system != VMMPY_SYSTEM_WINDOWS_X64 and target_system != VMMPY_SYSTEM_WINDOWS_X86:
		raise RuntimeError("Only Windows is supported by the pym_pypykatz module.")
	
	lsass_pid = VmmPy_PidGetFromName('lsass.exe')
	refresh_needed = bool(int(VmmPy_ConfigGet(VMMPY_OPT_CONFIG_IS_REFRESH_ENABLED)))
	
	VmmPyPlugin_FileRegisterDirectory(False, 'secrets', List)
	
	