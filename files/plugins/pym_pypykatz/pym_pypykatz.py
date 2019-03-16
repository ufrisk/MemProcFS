from vmmpy import *
from vmmpyplugin import *


from pypykatz.pypykatz import pypykatz
from pypykatz.commons.common import UniversalEncoder

from plugins.pym_pypykatz.pypyreader import MemProcFsReader
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

## TODO: kerberos tickets as file


def process_lsass():
	"""
	Processing lsass.exe with pypykatz, storing the results in the globals
	
	"""
	global all_secrets
	global luids
	global lsass_pid
	
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
	
	return all_secrets[bytes_offset:bytes_offset+bytes_length]

def ReadLuid(pid, file_name, file_attr, bytes_data, bytes_offset):
	"""
	reads the secrets for a specific luid data as file on the virtual FS
	"""
	
	global lsass_pid
	if pid != lsass_pid:
		return None
		
	luid = file_name.split('_')[1].split('.')[0]
	return luids[luid][bytes_offset:bytes_offset+bytes_length]


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
		global lsass_pid
		if pid != lsass_pid:
			return None
			
		if path != 'secrets':
			return None
		
		# creating the all_secrets file
		result = {
			'all_results.json': {'size': len(all_secrets), 'read': ReadAllResults, 'write': None},
		}
		
		# for ewach luid we create a text file in the form of "luid_<luid>.txt"
		
		for luid in luids:
			result['luid_%s.txt' % luid] = {'size': len(luids), 'read': ReadLuid, 'write': None}
	
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
	
	