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
using ssize_t = System.Int64;
using nodeidx_t = System.UInt64;

using System.Runtime.InteropServices;
using static IdaPlusPlus.IdaInterop;
using System.Drawing;

namespace IdaNet.IdaInterop
{
    public class Netnode : IDisposable
    {
        private nodeidx_t netnodenumber;
        public IntPtr UnmanagedPtr { get; set; }

        #region CONSTRUCTORS
        internal Netnode()
        {
            UnmanagedPtr = Marshal.AllocCoTaskMem(sizeof(nodeidx_t));
            return;
        }

        // Constructor to create a netnode to access information about the specified linear address
        internal Netnode(nodeidx_t index)
            : this()
        {
            netnodenumber = index;
            return;
        }

        // Construct an instance of netnode class to access the specified netnode
        //      name      - name of netnode
        //      namlen    - length of the name. may be omitted, in this
        //                  case the length will be calcuated with strlen()
        //      do_create - true:  create the netnode if it doesn't exist yet.
        //                  false: don't create the netnode, set netnumber to BADNODE if
        //                         it doesn't exist
        internal Netnode(string name)
            : this(name, false)
        {
            return;
        }

        public Netnode(string name, bool do_create)
            : this()
        {
            IntPtr nativeName = (null == name) ? IntPtr.Zero : Marshal.StringToCoTaskMemAnsi(name);
            try
            {
                ida_netnode_check(UnmanagedPtr, nativeName, (size_t)(string.IsNullOrEmpty(name) ? 0 : name.Length), do_create);
            }
            finally
            {
                Marshal.FreeCoTaskMem(nativeName);
            }

            return;
        }

        ~Netnode()
        {
            Dispose(false);
            return;
        }
        #endregion

        #region PROPERTIES
        internal byte[] BlobValue
        {
            get
            {
                IntPtr nativeBuffer = Marshal.AllocCoTaskMem(MAXSPECSIZE);

                try
                {
                    int blobLength = (int)ida_netnode_valobj(Index, nativeBuffer, MAXSPECSIZE);

                    if (-1 == blobLength) { return null; }
                    byte[] result = new byte[(int)blobLength];

                    Marshal.Copy(nativeBuffer, result, 0, (int)blobLength);
                    return result;
                }
                finally
                {
                    Marshal.FreeCoTaskMem(nativeBuffer);
                }
            }
            set
            {
                if (null == value)
                {
                    ida_netnode_delvalue(Index);
                    return;
                }

                IntPtr nativeBuffer = Marshal.AllocCoTaskMem(value.Length);
                try
                {
                    Marshal.Copy(value, 0, nativeBuffer, value.Length);
                    ida_netnode_set(Index, nativeBuffer, (size_t)value.Length);
                }
                finally
                {
                    Marshal.FreeCoTaskMem(nativeBuffer);
                }
            }
        }

        internal nodeidx_t Index
        {
            get => (nodeidx_t)Marshal.ReadInt64(UnmanagedPtr);
            private set => Marshal.WriteInt64(UnmanagedPtr, (long)(nodeidx_t)value);
        }

        internal string Name
        {
            get
            {
                IntPtr nativeBuffer = Marshal.AllocCoTaskMem(MAXNAMESIZE);

                try
                {
                    int nameLength = (int)ida_netnode_get_name(Index, nativeBuffer);
                    if (-1 == nameLength) { return null; }
                    byte[] buffer = new byte[Math.Min((int)nameLength, nameLength)];

                    Marshal.Copy(nativeBuffer, buffer, 0, (int)nameLength);
                    return ASCIIEncoding.ASCII.GetString(buffer);
                }
                finally { Marshal.FreeCoTaskMem(nativeBuffer); }
            }
            set
            {
                IntPtr nativeBuffer;

                if (string.IsNullOrEmpty(value)) { nativeBuffer = IntPtr.Zero; }
                else
                {
                    byte[] localBuffer = ASCIIEncoding.ASCII.GetBytes(value);
                    nativeBuffer = Marshal.AllocCoTaskMem(localBuffer.Length);

                    Marshal.Copy(localBuffer, 0, nativeBuffer, localBuffer.Length);
                }

                ida_netnode_rename(Index, nativeBuffer, 0);
                return;
            }
        }

        #endregion

        #region OPERATORS
        public static bool operator ==(Netnode first, Netnode second)
        {
            if ((object)null == (object)first)
            {
                return ((object)null == (object)second);
            }

            if ((object)null == (object)second)
            {
                return false;
            }

            return (first.netnodenumber == second.netnodenumber);
        }

        public static bool operator !=(Netnode first, Netnode second)
        {
            return !(first == second);
        }

        public override bool Equals(Object obj)
        {
            // Perform an equality check on two rectangles (Point object pairs).
            if (obj == null || GetType() != obj.GetType())
                return false;
            Netnode n = (Netnode)obj;
            return netnodenumber.Equals(n.netnodenumber);
        }

        public override int GetHashCode()
        {
            return netnodenumber.GetHashCode();
        }
        #endregion

        #region FIELDS
        internal const nodeidx_t BadNode = nodeidx_t.MaxValue;

        // Tags internally used in netnodes. You should not use them for your tagged alt/sup/char/hash arrays.
        internal const byte atag = (byte)'A'; // Array of altvals
        internal const byte stag = (byte)'S'; // Array of supvals
        internal const byte htag = (byte)'H'; // Array of hashvals
        internal const byte vtag = (byte)'V'; // Value of netnode
        internal const byte ntag = (byte)'N'; // Name of netnode
        internal const byte ltag = (byte)'L'; // Links between netnodes

        // The BTREE page size. This is not interesting for the end-users.
        internal const int BTREE_PAGE_SIZE = 8192;  // don't use the default 2048 page size
        // Maximum length of a netnode name
        internal const int MAXNAMESIZE = 512;
        // Maximum length of strings or objects stored in supval array element
        internal const int MAXSPECSIZE = 1024;
        #endregion

        #region METHODS
        bool Create(string name)
        {
            bool ret = false;
            IntPtr nativeName = (null == name) ? IntPtr.Zero : Marshal.StringToCoTaskMemAnsi(name);
            try
            {
                ret = ida_netnode_check(UnmanagedPtr, nativeName, (size_t)(string.IsNullOrEmpty(name) ? 0 : name.Length), true);
            }
            finally
            {
                Marshal.FreeCoTaskMem(nativeName);
            }

            return ret;
        }

        public bool Create()
        {
            return Create(null);
        }

        public void Kill()
        {
            ida_netnode_kill(UnmanagedPtr);
        }

        public IntPtr MarshalToNative(byte[] data)
        {
            return MarshalToNative(data, 0, data.Length);
        }

        public IntPtr MarshalToNative(byte[] data, int offset, int length)
        {
            IntPtr result = Marshal.AllocCoTaskMem(length);

            Marshal.Copy(data, offset, result, length);
            return result;
        }

        public delegate bool AdjusterDelegate(nodeidx_t ea);

        public void AdjustAlternateValuesRange(nodeidx_t from, nodeidx_t to, nodeidx_t size, AdjusterDelegate shouldSkip)
        {
            IntPtr callback = (null == shouldSkip)
                ? IntPtr.Zero
                : Marshal.GetFunctionPointerForDelegate(shouldSkip);

            ida_netnode_altadjust(this.Index, from, to, size, callback);
            return;
        }

        public bool Check(string oldName)
        {
            IntPtr nativeName = (null == oldName) ? IntPtr.Zero : Marshal.StringToCoTaskMemAnsi(oldName);

            try
            {
                return ida_netnode_check(this.UnmanagedPtr, nativeName, (ulong)oldName.Length, false);
            }
            finally
            {
                Marshal.FreeCoTaskMem(nativeName);
            }
        }
        public size_t MoveTo(Netnode target, nodeidx_t count)
        {
            return ida_netnode_copy(netnodenumber, count, target.netnodenumber, true);
        }

        public size_t CopyTo(Netnode target, nodeidx_t count)
        {
            return ida_netnode_copy(netnodenumber, count, target.netnodenumber, false);
        }

        public static bool Inited()
        {
            return ida_netnode_inited();
        }

        public static bool IsAvailable()
        {
            return ida_netnode_is_available();
        }

        public static bool Exist(nodeidx_t index)
        {
            IntPtr nativeBuffer = Marshal.AllocCoTaskMem(sizeof(nodeidx_t));

            try
            {
                Marshal.WriteInt64(nativeBuffer, (long)index);
                return ida_netnode_exist(nativeBuffer);
            }
            finally { Marshal.FreeCoTaskMem(nativeBuffer); }
        }

        public void Altadjust2(nodeidx_t from, nodeidx_t to, nodeidx_t size, ref altadjust_visitor_t av)
        {
            //ida_netnode_altadjust2(this.Index, from, to, size, );
        }

        public nodeidx_t GetFirstSupplementaryValue(byte tag)
        {
            return ida_netnode_supfirst(this.Index, tag);
        }

        public nodeidx_t GetLastSupplementaryValue(byte tag)
        {
            return ida_netnode_suplast(this.Index, tag);
        }

        public nodeidx_t GetNextSupplementaryValue(nodeidx_t cur, byte tag)
        {
            return ida_netnode_supnext(this.Index, cur, tag);
        }

        public nodeidx_t GetPreviousSupplementaryValue(nodeidx_t cur, byte tag)
        {
            return ida_netnode_supprev(this.Index, cur, tag);
        }

        public ssize_t GetSupplementaryValue(nodeidx_t alt, byte tag, out byte[] buffer)
        {
            IntPtr nativeBuffer = Marshal.AllocCoTaskMem(MAXSPECSIZE);

            try
            {
                ssize_t result = ida_netnode_supval(this.Index, alt, nativeBuffer, MAXSPECSIZE, tag);
                if (-1 == (int)result) { buffer = null; }
                else
                {
                    buffer = new byte[(int)result];
                    Marshal.Copy(nativeBuffer, buffer, 0, (int)result);
                }
                return result;
            }

            finally { Marshal.FreeCoTaskMem(nativeBuffer); }
        }

        internal bool SetSupplementaryValue(nodeidx_t at, byte[] value, int length, byte tag)
        {
            IntPtr nativeBuffer = MarshalToNative(value, 0, length);

            try { return ida_netnode_supset(this.Index, at, nativeBuffer, (UInt64)length, tag); }
            finally { Marshal.FreeCoTaskMem(nativeBuffer); }
        }

        public int GetFirstHashedValue(byte tag, out string key)
        {
            IntPtr nativeBuffer = Marshal.AllocCoTaskMem(MAXSPECSIZE);

            try
            {
                int result = (int)ida_netnode_hashfirst(this.Index, nativeBuffer, MAXSPECSIZE, tag);

                if (-1 == result) { key = null; }
                else
                {
                    byte[] localBuffer = new byte[result];

                    Marshal.Copy(nativeBuffer, localBuffer, 0, (int)result);
                    key = ASCIIEncoding.ASCII.GetString(localBuffer);
                }
                return result;
            }
            finally { Marshal.FreeCoTaskMem(nativeBuffer); }
        }

        public int GetLastHashedValue(byte tag, out string key)
        {
            IntPtr nativeBuffer = Marshal.AllocCoTaskMem(MAXSPECSIZE);

            try
            {
                int result = (int)ida_netnode_hashlast(this.Index, nativeBuffer, MAXSPECSIZE, tag);
                key = Marshal.PtrToStringAnsi(nativeBuffer);
                return result;
            }
            finally 
            {
                Marshal.FreeCoTaskMem(nativeBuffer); 
            }
        }

        public int GetNextHashedValue(string currentKey, byte tag, out string nextKey)
        {
            IntPtr nativeCurrentKey = Marshal.StringToCoTaskMemAnsi(currentKey);
            IntPtr nativeNextKey = IntPtr.Zero;

            try
            {
                nativeNextKey = Marshal.AllocCoTaskMem(MAXNAMESIZE);
                int result = (int)ida_netnode_hashnext(this.Index, nativeCurrentKey, nativeNextKey, MAXNAMESIZE, tag);
                nextKey = (-1 == result) ? null : Marshal.PtrToStringAnsi(nativeNextKey);
                return result;
            }
            finally
            {
                Marshal.FreeCoTaskMem(nativeCurrentKey);
                if (IntPtr.Zero != nativeNextKey) { Marshal.FreeCoTaskMem(nativeNextKey); }
            }
        }

        internal int GetPreviousHashedValue(string currentKey, byte tag, out string previousKey)
        {
            IntPtr nativeCurrentKey = Marshal.StringToCoTaskMemAnsi(currentKey);
            IntPtr nativePreviousKey = IntPtr.Zero;

            try
            {
                nativePreviousKey = Marshal.AllocCoTaskMem(MAXNAMESIZE);
                int result = (int)ida_netnode_hashprev(this.Index, nativeCurrentKey, nativePreviousKey, MAXNAMESIZE, tag);
                previousKey = (-1 == result) ? null : Marshal.PtrToStringAnsi(nativePreviousKey);
                return result;
            }
            finally
            {
                Marshal.FreeCoTaskMem(nativeCurrentKey);
                if (IntPtr.Zero != nativePreviousKey) { Marshal.FreeCoTaskMem(nativePreviousKey); }
            }
        }

        internal ssize_t GetHashedValue(string key, out byte[] buf, byte tag)
        {
            IntPtr nativeKey = Marshal.StringToCoTaskMemAnsi(key);
            IntPtr nativeBuffer = IntPtr.Zero;

            try
            {
                nativeBuffer = Marshal.AllocCoTaskMem(MAXSPECSIZE);
                ssize_t result = ida_netnode_hashval(this.Index, nativeKey, nativeBuffer, MAXSPECSIZE, tag);

                buf = new byte[(int)result];
                Marshal.Copy(nativeBuffer, buf, 0, (int)result);
                return result;
            }
            finally
            {
                Marshal.FreeCoTaskMem(nativeKey);
                if (IntPtr.Zero != nativeBuffer) { Marshal.FreeCoTaskMem(nativeBuffer); }
            }
        }

        internal bool SetBlob(byte[] buf, nodeidx_t start, byte tag)
        {
            IntPtr nativeBuffer = Marshal.AllocCoTaskMem(buf.Length);

            try
            {
                Marshal.Copy(buf, 0, nativeBuffer, buf.Length);
                return ida_netnode_setblob(this.Index, nativeBuffer, (ulong)buf.Length, start, tag);
            }
            finally { Marshal.FreeCoTaskMem(nativeBuffer); }
        }

        public byte[] GetBlob(byte[] buf, nodeidx_t start, byte tag)
        {
            IntPtr nativeBuffer = IntPtr.Zero;

            try
            {
                ulong bufsize = 0;
                nativeBuffer = ida_netnode_getblob(this.Index, nativeBuffer, ref bufsize, start, tag);
                if (null == buf) { buf = new byte[bufsize]; }
                Marshal.Copy(nativeBuffer, buf, 0, Math.Min(buf.Length, (int)bufsize));
                return buf;
            }
            finally { if (IntPtr.Zero != nativeBuffer) { Marshal.FreeCoTaskMem(nativeBuffer); } }
        }

        public int GetBlobSize(nodeidx_t start, byte tag)
        {
            return (int)ida_netnode_blobsize(this.Index, start, tag);
        }

        public bool AltdelAll(byte atag)
        {
            return ida_netnode_supdel_all(this.Index, atag);
        }

        public bool SupdelAll(byte atag)
        {
            return ida_netnode_supdel_all(this.Index, atag);
        }

        public nodeidx_t AltvalIdx8(byte alt, int tag)
        {
            return ida_netnode_altval_idx8(this.Index, alt, tag);
        }

        public unsafe bool AltsetIdx8(byte alt, nodeidx_t val, int tag)
        {
            return ida_netnode_supset_idx8(Index, alt, (IntPtr)(&val), sizeof(nodeidx_t), tag);
        }

        public void Dispose()
        {
            Dispose(true);
            return;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing) { GC.SuppressFinalize(this); }
            if (IntPtr.Zero != UnmanagedPtr)
            {
                Marshal.FreeCoTaskMem(UnmanagedPtr);
                UnmanagedPtr = IntPtr.Zero;
            }
            return;
        }
        #endregion
    }

    #region INNER CLASSES
    internal class HashedValuesEnumerator : IEnumerator<KeyValuePair<string, byte[]>>
    {
        internal class Factory : IEnumerable<KeyValuePair<string, byte[]>>
        {
            internal Factory(Netnode owner, byte tag)
            {
                _owner = owner;
                _tag = tag;
                return;
            }

            public IEnumerator<KeyValuePair<string, byte[]>> GetEnumerator()
            {
                return new HashedValuesEnumerator(_owner, _tag, true);
            }

            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            {
                return this.GetEnumerator();
            }

            #region FIELDS
            private Netnode _owner;
            private byte _tag;
            #endregion
        }

        #region CONSTRUCTORS
        internal HashedValuesEnumerator(Netnode owner, byte tag, bool forward)
        {
            _owner = owner;
            _tag = tag;
            Forward = forward;
            return;
        }

        ~HashedValuesEnumerator()
        {
            Dispose(false);
            return;
        }
        #endregion

        #region PROPERTIES
        internal bool Forward { get; set; }
        #endregion

        #region METHODS
        public KeyValuePair<string, byte[]> Current
        {
            get
            {
                if ((null == _currentKey) || _noMore) { throw new InvalidOperationException(); }
                return _currentValue;
            }
        }

        object System.Collections.IEnumerator.Current
        {
            get { return this.Current; }
        }

        public void Dispose()
        {
            Dispose(true);
            return;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing) { GC.SuppressFinalize(this); }
            return;
        }

        public bool MoveNext()
        {
            if (null == _currentKey)
            {
                _currentIndex = (Forward)
                    ? _owner.GetFirstHashedValue(_tag, out _currentKey)
                    : _owner.GetLastHashedValue(_tag, out _currentKey);
            }
            else
            {
                _currentIndex = (Forward)
                    ? _owner.GetNextHashedValue(_currentKey, _tag, out _currentKey)
                    : _owner.GetPreviousHashedValue(_currentKey, _tag, out _currentKey);
            }
            _noMore = (-1 == _currentIndex);
            if (!_noMore)
            {
                byte[] hashedValue;
                _owner.GetHashedValue(_currentKey, out hashedValue, _tag);
                _currentValue = new KeyValuePair<string, byte[]>(_currentKey, hashedValue);
            }
            return !_noMore;
        }

        public void Reset()
        {
            if (null != _currentKey) { _currentKey = null; }
            return;
        }
        #endregion

        #region FIELDS
        private string _currentKey;
        private KeyValuePair<string, byte[]> _currentValue;
        private int _currentIndex;
        private bool _noMore;
        private Netnode _owner;
        private byte _tag;
        #endregion
    }

    /// <summary>An enumerator suitable for retrieving A and S tagged values.</summary>
    internal class NodeValuesEnumerator : IEnumerator<byte[]>
    {
        internal class Factory : IEnumerable<byte[]>
        {
            internal Factory(Netnode owner, byte tag)
            {
                _owner = owner;
                _tag = tag;
                return;
            }

            public IEnumerator<byte[]> GetEnumerator()
            {
                return new NodeValuesEnumerator(_owner, _tag, true);
            }

            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            {
                return this.GetEnumerator();
            }

            #region FIELDS
            private Netnode _owner;
            private byte _tag;
            #endregion
        }

        #region CONSTRUCTORS
        internal NodeValuesEnumerator(Netnode owner, byte tag, bool forward)
        {
            _owner = owner;
            _tag = tag;
            Forward = forward;
            return;
        }

        ~NodeValuesEnumerator()
        {
            Dispose(false);
            return;
        }
        #endregion

        #region PROPERTIES
        internal bool Forward { get; set; }
        #endregion

        #region METHODS
        public byte[] Current
        {
            get
            {
                if ((null == _currentValue) || _noMore) { throw new InvalidOperationException(); }
                return _currentValue;
            }
        }

        object System.Collections.IEnumerator.Current
        {
            get { return this.Current; }
        }

        public void Dispose()
        {
            Dispose(true);
            return;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing) { GC.SuppressFinalize(this); }
            return;
        }

        public bool MoveNext()
        {
            if (null == _currentValue)
            {
                _currentIndex = (Forward)
                    ? _owner.GetFirstSupplementaryValue(_tag)
                    : _owner.GetLastSupplementaryValue(_tag);
            }
            else
            {
                _currentIndex = (Forward)
                    ? _owner.GetNextSupplementaryValue(_currentIndex, _tag)
                    : _owner.GetPreviousSupplementaryValue(_currentIndex, _tag);
            }
            _noMore = (nodeidx_t.MaxValue == _currentIndex);
            if (!_noMore) { _owner.GetSupplementaryValue(_currentIndex, _tag, out _currentValue); }
            return !_noMore;
        }

        public void Reset()
        {
            if (null != _currentValue) { _currentValue = null; }
            return;
        }
        #endregion

        #region FIELDS
        private byte[] _currentValue;
        private nodeidx_t _currentIndex;
        private bool _noMore;
        private Netnode _owner;
        private byte _tag;
        #endregion
    }

    internal class NetNodeEnumerator : IEnumerator<Netnode>
    {
        internal class Factory : IEnumerable<Netnode>
        {
            public IEnumerator<Netnode> GetEnumerator()
            {
                return new NetNodeEnumerator(true);
            }

            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            {
                return this.GetEnumerator();
            }
        }

        #region CONSTRUCTORS
        internal NetNodeEnumerator(bool forward)
        {
            Forward = forward;
            return;
        }

        ~NetNodeEnumerator()
        {
            Dispose(false);
            return;
        }
        #endregion

        #region PROPERTIES
        bool Forward { get; set; }
        #endregion

        #region METHODS
        public Netnode Current
        {
            get
            {
                if ((null == _currentNode) || _noMore) { throw new InvalidOperationException(); }
                return new Netnode(_currentNode.Index);
            }
        }

        public void Dispose()
        {
            Dispose(true);
            return;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing) { GC.SuppressFinalize(this); }
            return;
        }

        object System.Collections.IEnumerator.Current
        {
            get { return this.Current; }
        }

        public bool MoveNext()
        {
            if (null == _currentNode)
            {
                _currentNode = new Netnode(0x0);
                _noMore = (Forward)
                    ? (false == ida_netnode_start(_currentNode.UnmanagedPtr))
                    : (false == ida_netnode_end(_currentNode.UnmanagedPtr));
            }
            else
            {
                _noMore = (Forward)
                    ? (false == ida_netnode_next(_currentNode.UnmanagedPtr))
                    : (false == ida_netnode_prev(_currentNode.UnmanagedPtr));
            }
            return !_noMore;
        }

        public void Reset()
        {
            if (null != _currentNode)
            {
                _currentNode.Dispose();
                _currentNode = null;
            }
            return;
        }
        #endregion

        #region FIELDS
        private Netnode _currentNode;
        private bool _noMore = false;
        #endregion
    }
    #endregion

    public abstract class altadjust_visitor_t
    {
        public abstract bool should_skip(nodeidx_t ea);
    };
}
