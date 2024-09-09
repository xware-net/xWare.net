using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    internal enum IDBPackMode : Int32
    {
        IDB_UNPACKED = 0, //< leave database components unpacked
        IDB_PACKED = 1, //< pack database components into .idb
        IDB_COMPRESSED = 2, //< compress & pack database components
    }
}
