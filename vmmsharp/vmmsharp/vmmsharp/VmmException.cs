/*  
 *  C# API wrapper 'vmmsharp' for MemProcFS 'vmm.dll' and LeechCore 'leechcore.dll' APIs.
 *  
 *  Please see the example project in vmmsharp_example for additional information.
 *  
 *  Please consult the C/C++ header files vmmdll.h and leechcore.h for information about parameters and API usage.
 *  
 *  (c) Ulf Frisk, 2020-2024
 *  Author: Ulf Frisk, pcileech@frizk.net
 *  
 */

using System;

namespace Vmmsharp
{
    /// <summary>
    /// Thrown when an exception occurs within Vmmsharp (MemProcFS).
    /// </summary>
    public class VmmException : Exception
    {
        public VmmException()
        {
        }

        public VmmException(string message)
            : base(message)
        {
        }

        public VmmException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
