using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using AtypeT = System.Int32;
using EaT = System.UInt64;
using IdastateT = System.Int32;

using static IdaPlusPlus.IdaInterop;

namespace IdaNet.IdaInterop
{
    public class AutoDisplayT
    {
        const IdastateT st_Ready = 0;          ///< READY:             IDA is doing nothing
        const IdastateT st_Think = 1;          ///< THINKING:          Autoanalysis on, the user may press keys
        const IdastateT st_Waiting = 2;        ///< WAITING:           Waiting for the user input
        const IdastateT st_Work = 3;           ///< BUSY:              IDA is busy

        const AtypeT AU_NONE = 00;             ///< placeholder; not used
        const AtypeT AU_UNK = 10;              ///<  0: convert to unexplored
        const AtypeT AU_CODE = 20;             ///<  1: convert to instruction
        const AtypeT AU_WEAK = 25;             ///<  2: convert to instruction (ida decision)
        const AtypeT AU_PROC = 30;             ///<  3: convert to procedure start
        const AtypeT AU_TAIL = 35;             ///<  4: add a procedure tail
        const AtypeT AU_FCHUNK = 38;           ///<  5: find func chunks
        const AtypeT AU_USED = 40;             ///<  6: reanalyze
        const AtypeT AU_TYPE = 50;             ///<  7: apply type information
        const AtypeT AU_LIBF = 60;             ///<  8: apply signature to address
        const AtypeT AU_LBF2 = 70;             ///<  9: the same; second pass
        const AtypeT AU_LBF3 = 80;             ///< 10: the same; third pass
        const AtypeT AU_CHLB = 90;             ///< 11: load signature file (file name is kept separately)
        const AtypeT AU_FINAL = 200;           ///< 12: final pass

        AtypeT type = AU_NONE;
        EaT ea = DefineConstants.BADADDR;
        IdastateT state = st_Ready;
    };

    public class Auto
    {
        public static bool AutoIsOk()
        {
            return ida_auto_is_ok();
        }
    }
}
