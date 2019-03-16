from vmmpy import *
from vmmpyplugin import *
import json
import traceback

try:
	from pypykatz.pypykatz import pypykatz
	from pypykatz.commons.common import UniversalEncoder
	from plugins.pym_pypykatz.pypyreader import MemProcFsReader
	
except Exception as e:
	traceback.print_exc()
	print('Pypykatz import error, do you have it installed?')
	raise


# globals needed for FS
lsass_pid = None
all_secrets = '' #all secrets extracted from lsass in json format
luids = {} #secrets per-luid (logon session) in txt format
domains = {}
kerberos = {}

## TODO: kerberos tickets as file


def process_lsass():
	"""
	Processing lsass.exe with pypykatz, storing the results in the globals
	
	"""
	global all_secrets
	global luids
	global lsass_pid
	global domains
	global kerberos
	
	print('process_lsass!')
	
	try:
		memreader = MemProcFsReader()
		lsass_pid = memreader.process_pid
		print('lsass_pid %s' % lsass_pid)
		mimi = pypykatz(memreader, memreader.sysinfo)
		mimi.start()
		
		all_secrets = json.dumps(mimi, cls = UniversalEncoder, indent=4, sort_keys=True)
		for luid in mimi.logon_sessions:
			luids[str(luid)] = str(mimi.logon_sessions[luid])
			kerberos[str(luid)] = []
			for kc in mimi.logon_sessions[luid].kerberos_creds:
				ticket = kc.ticket.to_asn1()
				kerberos[str(luid)].append(ticket)
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
			
			
			
		# comment out the following debug prints in the final version
		print(all_secrets)
		print('==== No more secrets ====')
			
	except Exception as e:
		traceback.print_exc()
		print('pypykatz processing failed!')
		raise
		
	
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
			
		print('ReadLuid')
		print(file_name)
		luid = file_name.rsplit('.', 1)[0]
		if luid.find('_') != -1:
			luid = luid.split('_')[1]
		return luids[luid][bytes_offset:bytes_offset+bytes_length].encode()
	
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
	try:
		if pid != lsass_pid:
			return None
			
		if path[:7] != 'secrets':
			return None
		
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
			print(path)
			result = {}
			domain = path.rsplit('/',1)[1]
			print(domain)
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
	# Check that the operating system is 32-bit or 64-bit Windows. If it's not
	# then raise an exception to terminate loading of this module.
	if target_system != VMMPY_SYSTEM_WINDOWS_X64 and target_system != VMMPY_SYSTEM_WINDOWS_X86:
		raise RuntimeError("Only Windows is supported by the pym_procstruct module.")
	
	# invoking function that processes the lsass.exe
	process_lsass()
	
	VmmPyPlugin_FileRegisterDirectory(False, 'secrets', List)
	
	