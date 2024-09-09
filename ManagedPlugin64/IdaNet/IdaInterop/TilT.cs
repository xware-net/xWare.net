using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using ea_t = System.UInt64;
using tid_t = System.UInt64;
using sel_t = System.UInt64;
using size_t = System.UInt64;
using asize_t = System.UInt64;
using adiff_t = System.Int64;
using uval_t = System.UInt64;
using bgcolor_t = System.UInt32;
using flags_t = System.UInt32;

using System.Runtime.InteropServices;
using System.IO.Compression;
using System.IO;

namespace IdaNet.IdaInterop
{
    public enum til_t_flags : uint
    {
        TIL_ZIP = 0x0001,  ///< pack buckets using zip
        TIL_MAC = 0x0002,  ///< til has macro table
        TIL_ESI = 0x0004,  ///< extended sizeof info (short, long, longlong)
        TIL_UNI = 0x0008,  ///< universal til for any compiler
        TIL_ORD = 0x0010,  ///< type ordinal numbers are present
        TIL_ALI = 0x0020,  ///< type aliases are present (this bit is used only on the disk)
        TIL_MOD = 0x0040,  ///< til has been modified, should be saved
        TIL_STM = 0x0080,  ///< til has extra streams
        TIL_SLD = 0x0100,  ///< sizeof(long double)
    }

    public struct til_bucket_t
    {
        private readonly BinaryReader Reader;
        private readonly List<object> Types;
        public byte[] Buffer;
        private readonly UInt32 NOrds;
        public Int32 NDefs;
        private readonly Int32 Size;

        public til_bucket_t(UInt32 flags, BinaryReader reader)
        {
            this.Reader = reader;
            Types = new();
            if ((flags & (uint)til_t_flags.TIL_ORD) != 0)
            {
                NOrds = reader.ReadUInt32();
            }

            if ((flags & (uint)til_t_flags.TIL_ALI) != 0)
            {
                // aliases presnt
            }

            NDefs = reader.ReadInt32();
            Size = reader.ReadInt32();
            if ((flags & (uint)til_t_flags.TIL_ZIP) != 0)
            {
                var csize = reader.ReadInt32();
                // mircea
                //Buffer = ZlibStream.UncompressBuffer(reader.ReadBytes(csize));
            }
            else
            {
                Buffer = reader.ReadBytes(Size);
            }
        }

        public void AddType(object t)
        {
            Types.Add(t);
        }

        public List<object> GetTypes()
        {
            return Types;
        }

        public IEnumerable<object> Iterator()
        {
            foreach (var typ in Types)
                yield return typ;
        }
    }

    public struct til_stream_t
    {

    }

    public struct TilT
    {
        public TilT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
            bases = new List<TilT> ();
            cc = new compiler_info_t(MarshalingUtils.GetBytes(UnmanagedPtr, 36, 10));

            using StreamReader sr = new(@"c:\idafreeware83\til\pc\" + name + ".til");
            using BinaryReader br = new(sr.BaseStream);

            syms = new til_bucket_t(flags & 0xcf, br);
            types = new til_bucket_t(flags, br);
            macros = new til_bucket_t(flags & 0xcf, br);
        }

        public IntPtr UnmanagedPtr { get; set; }

        public string name                 ///< short file name (without path and extension)
        {
            get { return MarshalingUtils.GetString(UnmanagedPtr, 0); }
        }
        public string desc                 ///< human readable til description
        {
            get { return MarshalingUtils.GetString(UnmanagedPtr, 8); }
        }
        public int nbases              ///< number of base tils
        {
            get { return MarshalingUtils.GetInt32(UnmanagedPtr, 16); }
        }
        public List<TilT> bases;             ///< tils that our til is based on
        public UInt32 flags                ///< \ref TIL_
        {
            get { return MarshalingUtils.GetUInt32(UnmanagedPtr, 32); }
            set {  MarshalingUtils.SetUInt32(UnmanagedPtr , 32, value); }
        }
                                            /// Has the til been modified? (#TIL_MOD)
        public bool is_dirty()
        {
            return (flags & (uint)(til_t_flags.TIL_MOD)) != 0;
        }

        /// Mark the til as modified (#TIL_MOD)
        public void set_dirty()
        {
            flags |= (uint)(til_t_flags.TIL_MOD);
        }

        compiler_info_t cc;                 ///< information about the target compiler
        til_bucket_t syms;                  ///< symbols
        til_bucket_t types;                 ///< types
        til_bucket_t macros;                ///< macros
        int nrefs = 0;                      ///< number of references to the til
        int nstreams = 0;                   ///< number of extra streams
        List<til_stream_t> streams;         ///< symbol stream storage
    }
}
