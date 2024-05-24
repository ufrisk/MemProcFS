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
