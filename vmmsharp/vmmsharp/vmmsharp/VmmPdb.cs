/*  
 *  C# API wrapper 'vmmsharp' for MemProcFS 'vmm.dll' and LeechCore 'leechcore.dll' APIs.
 *  
 *  Please see the example project in vmmsharp_example for additional information.
 *  
 *  Please consult the C/C++ header files vmmdll.h and leechcore.h for information about parameters and API usage.
 *  
 *  (c) Ulf Frisk, 2020-2025
 *  Author: Ulf Frisk, pcileech@frizk.net
 *  
 */

/* Contributions by imerzan (Frostchi)
 * BSD Zero Clause License
 * 
 * Copyright (c) 2024 imerzan
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

using System.Text;
using Vmmsharp.Internal;

namespace Vmmsharp
{
    /// <summary>
    /// The PDB sub-system requires that MemProcFS supporting DLLs/.SO’s for debugging and symbol server are put alongside vmm.dll.
    /// Also it’s recommended that the file info.db is put alongside vmm.dll.
    /// </summary>
    public class VmmPdb
    {
        #region Base Functionality

        protected readonly string _module;
        protected readonly Vmm _hVmm;

        private VmmPdb()
        {
            ;
        }

        internal VmmPdb(Vmm hVmm, string module)
        {
            this._hVmm = hVmm;
            this._module = module;
        }

        internal VmmPdb(Vmm hVmm, uint pid, ulong vaModuleBase)
        {
            string szModuleName = "";
            byte[] data = new byte[260];
            unsafe
            {
                fixed (byte* pb = data)
                {
                    bool result = Vmmi.VMMDLL_PdbLoad(hVmm, pid, vaModuleBase, pb);
                    if(result)
                    {
                        szModuleName = Encoding.UTF8.GetString(data);
                        szModuleName = szModuleName.Substring(0, szModuleName.IndexOf((char)0));
                        this._hVmm = hVmm;
                        this._module = szModuleName;
                        return;
                    }
                }
            }
            throw new VmmException("Failed to load PDB for module");
        }

        /// <summary>
        /// ToString override.
        /// </summary>
        public override string ToString()
        {
            return $"VmmPdb:{_module}";
        }

        #endregion

        #region Specific Functionality

        /// <summary>
        /// The module name of the PDB.
        /// </summary>
        public string Module
        {
            get { return _module; }
        }

        /// <summary>
        /// Get the symbol name given an address or offset.
        /// </summary>
        /// <param name="cbSymbolAddressOrOffset"></param>
        /// <param name="szSymbolName"></param>
        /// <returns></returns>
        public unsafe bool SymbolName(ulong cbSymbolAddressOrOffset, out string szSymbolName)
        {
            uint pdwSymbolDisplacement;
            return SymbolName(cbSymbolAddressOrOffset, out szSymbolName, out pdwSymbolDisplacement);
        }

        /// <summary>
        /// Get the symbol name given an address or offset.
        /// </summary>
        /// <param name="cbSymbolAddressOrOffset"></param>
        /// <param name="szSymbolName"></param>
        /// <param name="pdwSymbolDisplacement"></param>
        /// <returns></returns>
        public unsafe bool SymbolName(ulong cbSymbolAddressOrOffset, out string szSymbolName, out uint pdwSymbolDisplacement)
        {
            szSymbolName = "";
            pdwSymbolDisplacement = 0;
            byte[] data = new byte[260];
            fixed (byte* pb = data)
            {
                bool result = Vmmi.VMMDLL_PdbSymbolName(_hVmm, _module, cbSymbolAddressOrOffset, pb, out pdwSymbolDisplacement);
                if (!result) { return false; }
                szSymbolName = Encoding.UTF8.GetString(data);
                szSymbolName = szSymbolName.Substring(0, szSymbolName.IndexOf((char)0));
            }
            return true;
        }

        /// <summary>
        /// Get the symbol address given a symbol name.
        /// </summary>
        /// <param name="szSymbolName"></param>
        /// <param name="pvaSymbolAddress"></param>
        /// <returns></returns>
        public bool SymbolAddress(string szSymbolName, out ulong pvaSymbolAddress)
        {
            return Vmmi.VMMDLL_PdbSymbolAddress(_hVmm, _module, szSymbolName, out pvaSymbolAddress);
        }

        /// <summary>
        /// Get the size of a type.
        /// </summary>
        /// <param name="szTypeName"></param>
        /// <param name="pcbTypeSize"></param>
        /// <returns></returns>
        public bool TypeSize(string szTypeName, out uint pcbTypeSize)
        {
            return Vmmi.VMMDLL_PdbTypeSize(_hVmm, _module, szTypeName, out pcbTypeSize);
        }

        /// <summary>
        /// Get the child offset of a type.
        /// </summary>
        /// <param name="szTypeName"></param>
        /// <param name="wszTypeChildName"></param>
        /// <param name="pcbTypeChildOffset"></param>
        /// <returns></returns>
        public bool TypeChildOffset(string szTypeName, string wszTypeChildName, out uint pcbTypeChildOffset)
        {
            return Vmmi.VMMDLL_PdbTypeChildOffset(_hVmm, _module, szTypeName, wszTypeChildName, out pcbTypeChildOffset);
        }

        #endregion
    }
}
