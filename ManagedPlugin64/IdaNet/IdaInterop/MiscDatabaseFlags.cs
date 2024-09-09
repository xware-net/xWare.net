using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    internal enum MiscDatabaseFlags : UInt32
    {
        LFLG_PC_FPP = 0x00000001, //< decode floating point processor instructions?
        LFLG_PC_FLAT = 0x00000002, //< 32-bit program (or higher)?
        LFLG_64BIT = 0x00000004, //< 64-bit program?
        LFLG_IS_DLL = 0x00000008, //< Is dynamic library?
        LFLG_FLAT_OFF32 = 0x00000010, //< treat ::REF_OFF32 as 32-bit offset for 16bit segments (otherwise try SEG16:OFF16)
        LFLG_MSF = 0x00000020, //< Byte order: is MSB first?
        LFLG_WIDE_HBF = 0x00000040, //< Bit order of wide bytes: high byte first?
        LFLG_DBG_NOPATH = 0x00000080, //< do not store input full path in debugger process options
        LFLG_SNAPSHOT = 0x00000100, //< memory snapshot was taken?
        LFLG_PACK = 0x00000200, //< pack the database?
        LFLG_COMPRESS = 0x00000400, //< compress the database?
        LFLG_KERNMODE = 0x00000800, //< is kernel mode binary?
    }
}
