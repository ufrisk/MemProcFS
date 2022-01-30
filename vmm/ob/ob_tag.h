// ob.h : definitions of object tags.
//
// (c) Ulf Frisk, 2021-2022
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __OB_TAG_H__
#define __OB_TAG_H__

#include "ob.h"

#define OB_TAG_INFODB_CTX               'IDBC'
#define OB_TAG_MAP_PTE                  'Mpte'
#define OB_TAG_MAP_VAD                  'Mvad'
#define OB_TAG_MAP_VADEX                'Mvae'
#define OB_TAG_MAP_MODULE               'Mmod'
#define OB_TAG_MAP_UNLOADEDMODULE       'Mumd'
#define OB_TAG_MAP_EAT                  'Meat'
#define OB_TAG_MAP_IAT                  'Miat'
#define OB_TAG_MAP_POOL                 'Mpol'
#define OB_TAG_MAP_THREAD               'Mthr'
#define OB_TAG_MAP_HANDLE               'Mhnd'
#define OB_TAG_MAP_OBJECT               'Mobj'
#define OB_TAG_MAP_KDRIVER              'Mdrv'
#define OB_TAG_MAP_PHYSMEM              'Mmem'
#define OB_TAG_MAP_USER                 'Musr'
#define OB_TAG_MAP_SERVICE              'Msvc'
#define OB_TAG_MAP_NET                  'Mnet'
#define OB_TAG_MAP_PFN                  'Mpfn'
#define OB_TAG_MAP_EVIL                 'Mevl'
#define OB_TAG_MAP_TASK                 'Mtsk'
#define OB_TAG_MOD_MINIDUMP_CTX         'mMDx'
#define OB_TAG_MOD_SEARCH_CTX           'mSHx'
#define OB_TAG_OBJ_ERROR                'Oerr'
#define OB_TAG_OBJ_FILE                 'Ofil'
#define OB_TAG_OBJ_DISPLAY              'Odis'
#define OB_TAG_PDB_CTX                  'PdbC'
#define OB_TAG_PDB_ENTRY                'PdbE'
#define OB_TAG_PFN_CONTEXT              'PfnC'
#define OB_TAG_PFN_PROC_TABLE           'PfnT'
#define OB_TAG_REG_HIVE                 'Rhve'
#define OB_TAG_REG_KEY                  'Rkey'
#define OB_TAG_REG_KEYVALUE             'Rval'
#define OB_TAG_VMM_PROCESS              'Ps__'
#define OB_TAG_VMM_PROCESS_CLONE        'PsC_'
#define OB_TAG_VMM_PROCESS_PERSISTENT   'PsSt'
#define OB_TAG_VMM_PROCESSTABLE         'PsTb'
#define OB_TAG_VMMVFS_DUMPCONTEXT       'CDmp'

#endif /* __OB_TAG_H__ */
