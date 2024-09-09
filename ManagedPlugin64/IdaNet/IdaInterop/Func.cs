using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

using ea_t = System.UInt64;
using tid_t = System.UInt64;
using sel_t = System.UInt64;
using size_t = System.UInt64;
using asize_t = System.UInt64;
using adiff_t = System.Int64;
using uval_t = System.UInt64;
using bgcolor_t = System.UInt32;
using flags_t = System.UInt32;

using static IdaPlusPlus.IdaInterop;

namespace IdaNet.IdaInterop
{
    public class Func : RangeT
    {
        public UInt64 flags;

        uval_t frame;        ///< netnode id of frame structure - see frame.hpp
        asize_t frsize;      ///< size of local variables part of frame in bytes.
                             ///< If #FUNC_FRAME is set and #fpd==0, the frame pointer
                             ///< (EBP) is assumed to point to the top of the local
                             ///< variables range.
        ushort frregs;       ///< size of saved registers in frame. This range is
                             ///< immediately above the local variables range.
        asize_t argsize;     ///< number of bytes purged from the stack
                             ///< upon returning
        asize_t fpd;         ///< frame pointer delta. (usually 0, i.e. realBP==typicalBP)
                             ///< use update_fpd() to modify it.

        bgcolor_t color;     ///< user defined function color

        // the following fields should not be accessed directly:

        UInt32 pntqty;       ///< number of SP change points
        //stkpnt_t* points;    ///< array of SP change points.
        ///< use ...stkpnt...() functions to access this array.

        int regvarqty;       ///< number of register variables (-1-not read in yet)
                             ///< use find_regvar() to read register variables
        //regvar_t* regvars;   ///< array of register variables.
        ///< this array is sorted by: start_ea.
        ///< use ...regvar...() functions to access this array.

        int llabelqty;       ///< number of local labels
        //llabel_t* llabels;   ///< local labels.
        ///< this array shouldn't be accessed directly; name.hpp
        ///< functions should be used instead.

        int regargqty;       ///< number of register arguments.
                             ///< During analysis IDA tries to guess the register
                             ///< arguments. It stores store the guessing outcome
                             ///< in this field. As soon as it determines the final
                             ///< function prototype, regargqty is set to zero.
        //regarg_t* regargs;   ///< unsorted array of register arguments.
        ///< use ...regarg...() functions to access this array.
        ///< regargs are destroyed when the full function
        ///< type is determined.

        int tailqty;         ///< number of function tails
        //range_t* tails;      ///< array of tails, sorted by ea.
        ///< use func_tail_iterator_t to access function tails.

        public struct Entry
        {
            //
            // Stack frame of the function. It is represented as a structure:
            //
            //    +------------------------------------------------+
            //    | function arguments                             |
            //    +------------------------------------------------+
            //    | return address (isn't stored in func_t)        |
            //    +------------------------------------------------+
            //    | saved registers (SI, DI, etc - func_t::frregs) |
            //    +------------------------------------------------+ <- typical BP
            //    |                                                |  |
            //    |                                                |  | func_t::fpd
            //    |                                                |  |
            //    |                                                | <- real BP
            //    | local variables (func_t::frsize)               |
            //    |                                                |
            //    |                                                |
            //    +------------------------------------------------+ <- SP
            //
            uval_t frame;        ///< netnode id of frame structure - see frame.hpp
            asize_t frsize;      ///< size of local variables part of frame in bytes.
                                 ///< If #FUNC_FRAME is set and #fpd==0, the frame pointer
                                 ///< (EBP) is assumed to point to the top of the local
                                 ///< variables range.
            ushort frregs;       ///< size of saved registers in frame. This range is
                                 ///< immediately above the local variables range.
            asize_t argsize;     ///< number of bytes purged from the stack
                                 ///< upon returning
            asize_t fpd;         ///< frame pointer delta. (usually 0, i.e. realBP==typicalBP)
                                 ///< use update_fpd() to modify it.

            bgcolor_t color;     ///< user defined function color

                                 // the following fields should not be accessed directly:

            UInt32 pntqty;       ///< number of SP change points
            //stkpnt_t* points;  ///< array of SP change points.
                                 ///< use ...stkpnt...() functions to access this array.

            int regvarqty;       ///< number of register variables (-1-not read in yet)
                                 ///< use find_regvar() to read register variables
            //regvar_t* regvars; ///< array of register variables.
                                 ///< this array is sorted by: start_ea.
                                 ///< use ...regvar...() functions to access this array.

            int llabelqty;       ///< number of local labels
            //llabel_t* llabels; ///< local labels.
                                 ///< this array shouldn't be accessed directly; name.hpp
                                 ///< functions should be used instead.

            int regargqty;       ///< number of register arguments.
                                 ///< During analysis IDA tries to guess the register
                                 ///< arguments. It stores store the guessing outcome
                                 ///< in this field. As soon as it determines the final
                                 ///< function prototype, regargqty is set to zero.
            //regarg_t* regargs; ///< unsorted array of register arguments.
                                 ///< use ...regarg...() functions to access this array.
                                 ///< regargs are destroyed when the full function
                                 ///< type is determined.

            int tailqty;         ///< number of function tails
            //range_t* tails;    ///< array of tails, sorted by ea.
                                 ///< use func_tail_iterator_t to access function tails.
        };

        public struct Tail
        {
            ea_t owner;          ///< the address of the main function possessing this tail
            int refqty;          ///< number of referers
            //ea_t* referers;    ///< array of referers (function start addresses).
        };

        public Func(ea_t start = 0, ea_t end = 0, flags_t f = 0)
        {
            start_ea = start;
            end_ea = end;
            flags = f | (uint)FunctionFlags.FUNC_NORET_PENDING;
            //frame = BADNODE;
            frsize = 0;
            frregs = 0;
            argsize = 0;
            fpd = 0;
            color = 0xffffffff;
            pntqty = 0;
            // points = null;
            regvarqty = 0;
            // regvars = null;
            llabelqty = 0;
            // llabels = null;
            regargqty = 0;
            // regargs = null
            tailqty = 0;
            // tails = null;

        }

        public Func(IntPtr funcPtr)
        {
            UnmanagedPtr = funcPtr;
            IntPtr nativeBuffer = IntPtr.Zero;

            start_ea = ida_get_func_start_ea(funcPtr);
            end_ea = ida_get_func_end_ea(funcPtr);
            flags = ida_get_func_flags(funcPtr);
        }

        public IntPtr UnmanagedPtr { get; set; }

        public asize_t size()
        {
            return ida_get_func_size(UnmanagedPtr);
        }

        public bool is_far()
        {
            return (flags & (UInt64)FunctionFlags.FUNC_FAR) != 0;
        }

        public bool does_return()
        {
            return (flags & (UInt64)FunctionFlags.FUNC_NORET) == 0;
        }

        public bool analyzed_sp()
        {
            return (flags & (UInt64)FunctionFlags.FUNC_SP_READY) != 0;
        }

        public bool need_prolog_analysis()
        {
            return (flags & (UInt64)FunctionFlags.FUNC_PROLOG_OK) == 0;
        }

        //public static void AddFunc(ea_t ea1, ea_t ea2 = 0xffffffffffffffff)
        //{
        //    var f = new func_t(ea1, ea2);
        //    IntPtr ptr = Marshal.AllocHGlobal((int)IdaPlusPlus.IdaInterop.ida_func_t_size());
        //    IdaPlusPlus.IdaInterop.ida_add_func_ex(ptr);
        //    Marshal.FreeHGlobal(ptr);
        //}

        //public static func_t ToManaged(IntPtr ptr)
        //{
        //    func_t f = new func_t();

        //    f.start_ea = IdaPlusPlus.IdaInterop.ida_get_func_start_ea(ptr);
        //    return f;
        //}
    }
}