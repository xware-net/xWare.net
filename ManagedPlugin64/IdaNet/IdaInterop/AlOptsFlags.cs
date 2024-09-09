using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    public enum AlOptsFlags : byte
    {
    ALOPT_IGNHEADS = 0x01, ///< don't stop if another data item is encountered.
    ALOPT_IGNPRINT = 0x02, ///< if set, don't stop at non-printable codepoints,
    ALOPT_IGNCLT   = 0x04, ///< if set, don't stop at codepoints that are not
    ALOPT_MAX4K    = 0x08, ///< if string length is more than 4K, return the
    }
}
