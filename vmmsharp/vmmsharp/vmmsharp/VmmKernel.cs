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

namespace Vmmsharp
{
    /// <summary>
    /// The kernel class gives easy access to:
    /// - The system process(pid 4).
    /// - Kernel build number.
    /// - Kernel debug symbols(nt).
    /// </summary>
    public class VmmKernel
    {
        #region Base Functionality

        protected readonly Vmm _hVmm;

        private VmmKernel()
        {
            ;
        }

        internal VmmKernel(Vmm hVmm)
        {
            this._hVmm = hVmm;
        }

        /// <summary>
        /// ToString override.
        /// </summary>
        public override string ToString()
        {
            return "VmmKernel";
        }

        #endregion

        #region Specific Functionality

        /// <summary>
        /// The system process (PID 4).
        /// </summary>
        /// <returns>The system process (PID 4).</returns>
        public VmmProcess Process => new VmmProcess(_hVmm, 4);

        /// <summary>
        /// Build number of the current kernel / system.
        /// </summary>
        /// <returns>The build number of the kernel on success, 0 on fail.</returns>
        public uint Build => (uint)_hVmm.GetConfig(Vmm.CONFIG_OPT_WIN_VERSION_BUILD);

        /// <summary>
        /// Retrieve the VmmPdb object for the kernel "nt" debug symbols.
        /// </summary>
        /// <returns></returns>
        public VmmPdb Pdb => new VmmPdb(_hVmm, "nt");

        #endregion
    }
}
