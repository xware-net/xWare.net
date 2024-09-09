using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    internal enum DemangledNameFlags : byte
    {
        DEMNAM_MASK = 3, //< mask for name form
        DEMNAM_CMNT = 0, //< display demangled names as comments
        DEMNAM_NAME = 1, //< display demangled names as regular names
        DEMNAM_NONE = 2, //< don't display demangled names
        DEMNAM_GCC3 = 4, //< assume gcc3 names (valid for gnu compiler)
        DEMNAM_FIRST = 8, //< override type info
    }
}
