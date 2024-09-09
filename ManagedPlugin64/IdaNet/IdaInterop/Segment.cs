using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using ea_t = System.UInt64;
using sel_t = System.UInt64;
using size_t = System.UInt64;
using asize_t = System.UInt64;
using adiff_t = System.Int64;
using uval_t = System.UInt64;
using bgcolor_t = System.UInt32;

using ManagedPlugin;
using System.Runtime.InteropServices;

using static IdaPlusPlus.IdaInterop;

namespace IdaNet.IdaInterop
{
    public enum SegmentAlignement : byte
    {
        saAbs = 0, // Absolute segment.
        saRelByte = 1, // Relocatable, byte aligned.
        saRelWord = 2, // Relocatable, word (2-byte) aligned.
        saRelPara = 3, // Relocatable, paragraph (16-byte) aligned.
        saRelPage = 4, // Relocatable, aligned on 256-byte boundary
        saRelDble = 5, // Relocatable, aligned on a double word (4-byte) boundary.
        saRel4K = 6, // This value is used by the PharLap OMF for page (4K) alignment. It is not supported by LINK.
        saGroup = 7, // Segment group
        saRel32Bytes = 8, // 32 bytes
        saRel64Bytes = 9, // 64 bytes
        saRelQword = 10, // 8 bytes
        saRel128Bytes = 11, // 128 bytes
        saRel512Bytes = 12, // 512 bytes
        saRel1024Bytes = 13, // 1024 bytes
        saRel2048Bytes = 14, // 2048 bytes
    }

    [Flags()]
    public enum SegmentPermission : byte
    {
        Execute = 1, // Execute
        Write = 2, // Write
        Read = 4, // Read
    }

    public enum SegmentBitness : byte
    {
        Bitness16 = 0, // 0 - 16 bits
        Bitness32 = 1, // 1 - 32 bits
        Bitness64 = 2, // 2 - 64 bits
    }

    public enum SegmentCombination : byte
    {
        scPriv = 0,    // Private. Do not combine with any other program segment.
        scGroup = 1,    // Segment group
        scPub = 2,    // Public. Combine by appending at an offset that meets the alignment requirement.
        scPub2 = 4,    // As defined by Microsoft, same as C=2 (public).
        scStack = 5,    // Stack. Combine as for C=2. This combine type forces byte alignment.
        scCommon = 6,    // Common. Combine by overlay using maximum size.
        scPub3 = 7,    // As defined by Microsoft, same as C=2 (public).
    }

    [Flags()]
    public enum SegmentFlags : ushort
    {
        SFL_COMORG = 0x01, // IDP dependent field (IBM PC: if set, ORG directive is not commented out)
        SFL_OBOK = 0x02, // orgbase is present? (IDP dependent field)
        SFL_HIDDEN = 0x04, // is the segment hidden?
        SFL_DEBUG = 0x08, // is the segment created for the debugger? such segments are temporary and do not have permanent flags
        SFL_LOADER = 0x10, // is the segment created by the loader?
        SFL_HIDETYPE = 0x20, // hide segment type (do not print it in the listing)
        SFL_HEADER = 0x40, // header segment
    }

    public enum SegmentType : byte
    {
        SEG_NORM = 0,       // Unknown type, no assumptions
        SEG_XTRN = 1,       // * segment with 'extern' definitions no instructions are allowed
        SEG_CODE = 2,       // code segment
        SEG_DATA = 3,       // data segment
        SEG_IMP = 4,       // java: implementation segment
        SEG_GRP = 6,       // * group of segments
        SEG_NULL = 7,       // zero-length segment
        SEG_UNDF = 8,       // undefined segment type (not used)
        SEG_BSS = 9,       // uninitialized segment
        SEG_ABSSYM = 10,       // * segment with definitions of absolute symbols
        SEG_COMM = 11,       // * segment with communal definitions
        SEG_IMEM = 12,       // internal processor memory & sfr (8051)
        SEG_MAX_SEGTYPE_CODE = SEG_IMEM
    }

    public class SegmentT : RangeT
    {
        public string name;             //< use get/set_segm_name() functions
        public string sclass;           //< use get/set_segm_class() functions
        public asize_t orgbase;         //< this field is IDP dependent.
                                        //< you may keep your information about
                                        //< the segment here
        public SegmentAlignement align; //< \ref sa_
        public SegmentCombination comb; //< \ref sc_
        public SegmentPermission perm;  //< \ref SEGPERM_ (0 means no information)
        public SegmentBitness bitness;  //< Number of bits in the segment addressing
                                        //<   - 0: 16 bits
                                        //<   - 1: 32 bits
                                        //<   - 2: 64 bits
        public SegmentFlags flags;      //< \ref SFL_
        public sel_t sel;               //< segment selector - should be unique. You can't
                                        //< change this field after creating the segment.
                                        //< Exception: 16bit OMF files may have several
                                        //< segments with the same selector, but this is not
                                        //< good (no way to denote a segment exactly)
                                        //< so it should be fixed in the future.
                                        //public sel_t[] defsr = Arrays.InitializeWithDefaultInstances<sel_t>(DefineConstants.SREG_NUM); //< default segment register values.
        public SegmentType type;        //< segment type (see \ref SEG_).
                                        //< The kernel treats different segment types differently.
                                        //< Segments marked with '*' contain no instructions
                                        //< or data and are not declared as 'segments' in
                                        //< the disassembly.
        public uint color;              //< the segment color

        public SegmentT()
        {
            this.name = null;
            this.sclass = null;
            this.orgbase = 0;
            this.align = 0;
            this.comb = 0;
            this.perm = 0;
            this.bitness = 0;
            this.flags = 0;
            this.sel = 0;
            this.type = SegmentType.SEG_NORM;
            this.color = DefineConstants.DEFCOLOR;
        }

        public SegmentT(IntPtr segPtr)
        {
            UnmanagedPtr = segPtr;
            IntPtr nativeBuffer = IntPtr.Zero;

            // name
            try
            {
                var requiredSize = ida_get_segm_name(IntPtr.Zero, UnmanagedPtr, 0);
                if (-1 == requiredSize)
                {
                    name = string.Empty;
                }
                else
                {
                    nativeBuffer = Marshal.AllocCoTaskMem((int)requiredSize);
                    requiredSize = ida_get_segm_name(nativeBuffer, UnmanagedPtr, 0);
                    if (0 <= requiredSize)
                    {
                        name = Marshal.PtrToStringAnsi(nativeBuffer, (int)requiredSize);
                    }
                }
            }
            catch (Exception ex)
            {
                PluginBase.WriteDebugMessage("Exception {0}\n stack trace {1}", ex.Message, ex.StackTrace);
                name = ex.Message;
            }
            finally
            {
                if (IntPtr.Zero != nativeBuffer)
                {
                    Marshal.FreeCoTaskMem(nativeBuffer);
                    nativeBuffer = IntPtr.Zero;
                }
            }

            // sclass
            try
            {
                var requiredSize = ida_get_segm_class(IntPtr.Zero, UnmanagedPtr);
                if (-1 == requiredSize)
                {
                    sclass = string.Empty;
                }
                else
                {
                    nativeBuffer = Marshal.AllocCoTaskMem((int)requiredSize);
                    requiredSize = ida_get_segm_class(nativeBuffer, UnmanagedPtr);
                    if (0 <= requiredSize)
                    {
                        sclass = Marshal.PtrToStringAnsi(nativeBuffer, (int)requiredSize);
                    }
                }
            }
            catch (Exception ex)
            {
                PluginBase.WriteDebugMessage("Exception {0}\n stack trace {1}", ex.Message, ex.StackTrace);
                sclass = ex.Message;
            }
            finally
            {
                if (IntPtr.Zero != nativeBuffer)
                {
                    Marshal.FreeCoTaskMem(nativeBuffer);
                    nativeBuffer = IntPtr.Zero;
                }
            }

            start_ea = ida_get_segm_start_ea(UnmanagedPtr);
            end_ea = ida_get_segm_end_ea(UnmanagedPtr);
            orgbase = ida_get_segm_orgbase(UnmanagedPtr);
            align = (SegmentAlignement)ida_get_segm_align(UnmanagedPtr);
            comb = (SegmentCombination)ida_get_segm_comb(UnmanagedPtr);
            perm = (SegmentPermission)ida_get_segm_perm(UnmanagedPtr);
            bitness = (SegmentBitness)ida_get_segm_bitness(UnmanagedPtr);
            flags = (SegmentFlags)ida_get_segm_flags(UnmanagedPtr);
            type = (SegmentType)ida_get_segm_type(UnmanagedPtr);
            color = DefineConstants.DEFCOLOR;
        }

        public IntPtr UnmanagedPtr { get; set; }

        public int is_16bit()
        {
            return bitness == SegmentBitness.Bitness16 ? 1 : 0;
        }

        public int is_32bit()
        {
            return bitness == SegmentBitness.Bitness32 ? 1 : 0;
        }

        public int is_64bit()
        {
            return bitness == SegmentBitness.Bitness64 ? 1 : 0;
        }

        public int abits()
        {
            return 1 << ((int)bitness + 4);
        }

        public int abytes()
        {
            return abits() / 8;
        }

        public int comorg()
        {
            return (flags & SegmentFlags.SFL_COMORG) != 0 ? 1 : 0;
        }

        public void set_comorg()
        {
            flags |= SegmentFlags.SFL_COMORG;
        }

        public void clr_comorg()
        {
            flags &= ~SegmentFlags.SFL_COMORG;
        }

        public int ob_ok()
        {
            return (flags & SegmentFlags.SFL_OBOK) != 0 ? 1 : 0;
        }

        public void set_ob_ok()
        {
            flags |= SegmentFlags.SFL_OBOK;
        }

        public void clr_ob_ok()
        {
            flags &= ~SegmentFlags.SFL_OBOK;
        }

        public int is_visible_segm()
        {
            return (flags & SegmentFlags.SFL_HIDDEN) == 0 ? 1 : 0;
        }

        public void set_visible_segm(int visible)
        {
            Globals.setflag(ref flags, SegmentFlags.SFL_HIDDEN, visible == 0 ? 1 : 0);
        }

        public int is_debugger_segm()
        {
            return (flags & SegmentFlags.SFL_DEBUG) != 0 ? 1 : 0;
        }

        public void set_debugger_segm(int debseg)
        {
            Globals.setflag(ref flags, SegmentFlags.SFL_DEBUG, debseg);
        }

        public int is_loader_segm()
        {
            return (flags & SegmentFlags.SFL_LOADER) != 0 ? 1 : 0;
        }
        public void set_loader_segm(int ldrseg)
        {
            Globals.setflag(ref flags, SegmentFlags.SFL_LOADER, ldrseg);
        }

        public int is_hidden_segtype()
        {
            return (flags & SegmentFlags.SFL_HIDETYPE) != 0 ? 1 : 0;
        }
        public void set_hidden_segtype(int hide)
        {
            Globals.setflag(ref flags, SegmentFlags.SFL_HIDETYPE, hide);
        }

        public int is_header_segm()
        {
            return (flags & SegmentFlags.SFL_HEADER) != 0 ? 1 : 0;
        }
        public void set_header_segm(int on)
        {
            Globals.setflag(ref flags, SegmentFlags.SFL_HEADER, on);
        }

        public int is_ephemeral_segm()
        {
            return (flags & (SegmentFlags.SFL_DEBUG | SegmentFlags.SFL_LOADER)) == SegmentFlags.SFL_DEBUG ? 1 : 0;
        }

        public bool update()
        {
            return ida_update_segm(UnmanagedPtr);
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append($"Segment ");
            sb.Append($"name=\"{name}\", ");
            sb.Append($"sclass={sclass}, ");
            sb.Append($"start_ea=0x{start_ea:X16}, ");
            sb.Append($"end_ea=0x{end_ea:X16}, ");
            sb.Append($"align={align}, ");
            sb.Append($"comb={comb}, ");
            sb.Append($"perm=({perm}), ");
            sb.Append($"bitness={bitness}, ");
            sb.Append($"flags={flags}, ");
            sb.Append($"type={type}");
            return sb.ToString();
        }
    }

    public class LockSegment
    {
        SegmentT seg;

        public LockSegment(SegmentT segm)
        {
            seg = segm;
            ida_lock_segm(segm.UnmanagedPtr, true);
        }
    }
}
