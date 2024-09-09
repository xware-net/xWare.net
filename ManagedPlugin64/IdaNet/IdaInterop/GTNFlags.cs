using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    public enum GTNFlags : int
    {
        GN_VISIBLE = 0x0001, ///< replace forbidden characters by SUBSTCHAR
        GN_COLORED = 0x0002, ///< return colored name
        GN_DEMANGLED = 0x0004, ///< return demangled name
        GN_STRICT = 0x0008, ///< fail if cannot demangle
        GN_SHORT = 0x0010, ///< use short form of demangled name
        GN_LONG = 0x0020, ///< use long form of demangled name
        GN_LOCAL = 0x0040, ///< try to get local name first; if failed, get global
        GN_ISRET = 0x0080, ///< for dummy names: use retloc
        GN_NOT_ISRET = 0x0100, ///< for dummy names: do not use retloc
        GN_NOT_DUMMY = 0x0200, ///< do not return a dummy name
    }
}
