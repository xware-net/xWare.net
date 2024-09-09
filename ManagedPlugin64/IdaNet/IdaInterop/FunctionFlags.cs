using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    public enum FunctionFlags : UInt64
    {
        FUNC_NORET = 0x00000001,     ///< Function doesn't return
        FUNC_FAR = 0x00000002,     ///< Far function
        FUNC_LIB = 0x00000004,     ///< Library function

        FUNC_STATICDEF = 0x00000008,     ///< Static function

        FUNC_FRAME = 0x00000010,     ///< Function uses frame pointer (BP)
        FUNC_USERFAR = 0x00000020,     ///< User has specified far-ness
                                       ///< of the function
        FUNC_HIDDEN = 0x00000040,     ///< A hidden function chunk
        FUNC_THUNK = 0x00000080,     ///< Thunk (jump) function
        FUNC_BOTTOMBP = 0x00000100,     ///< BP points to the bottom of the stack frame
        FUNC_NORET_PENDING = 0x00200,     ///< Function 'non-return' analysis must be performed.
                                          ///< This flag is verified upon func_does_return()
        FUNC_SP_READY = 0x00000400,     ///< SP-analysis has been performed.
                                        ///< If this flag is on, the stack
                                        ///< change points should not be not
                                        ///< modified anymore. Currently this
                                        ///< analysis is performed only for PC
        FUNC_FUZZY_SP = 0x00000800,     ///< Function changes SP in untraceable way,
                                        ///< for example: and esp, 0FFFFFFF0h
        FUNC_PROLOG_OK = 0x00001000,     ///< Prolog analysis has be performed
                                         ///< by last SP-analysis
        FUNC_PURGED_OK = 0x00004000,     ///< 'argsize' field has been validated.
                                         ///< If this bit is clear and 'argsize'
                                         ///< is 0, then we do not known the real
                                         ///< number of bytes removed from
                                         ///< the stack. This bit is handled
                                         ///< by the processor module.
        FUNC_TAIL = 0x00008000,     ///< This is a function tail.
                                    ///< Other bits must be clear
                                    ///< (except #FUNC_HIDDEN).
        FUNC_LUMINA = 0x00010000,     ///< Function info is provided by Lumina.

        FUNC_RESERVED = 0x8000000000000000, ///< Reserved (for internal usage)
    }
}
