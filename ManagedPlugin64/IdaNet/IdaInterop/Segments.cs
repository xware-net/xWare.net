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
    public class Segments
    {

        #region PROPERTIES

        /// <summary>Get number of segments</summary>
        /// 
        internal static int Count
        {
            get { return ida_get_segm_qty(); }
        }

        #endregion

        /// <summary>
        /// Enumerates the segments.
        /// </summary>
        /// <returns>An enumeration of segments with all their properties</returns>
        internal static IEnumerable<SegmentT> EnumerateSegments()
        {
            int upperBound = Count;
            for (int index = 0; index < upperBound; index++)
            {
                IntPtr nativeBuffer = IntPtr.Zero;
                SegmentT result = new SegmentT();
                result.UnmanagedPtr = ida_getnseg(index);

                // name
                try
                {
                    var requiredSize = ida_get_segm_name(IntPtr.Zero, index, 0);
                    if (-1 == requiredSize)
                    {
                        result.name = string.Empty;
                    }
                    else
                    {
                        nativeBuffer = Marshal.AllocCoTaskMem((int)requiredSize);
                        requiredSize = ida_get_segm_name(nativeBuffer, index, 0);
                        if (0 <= requiredSize)
                        {
                            result.name = Marshal.PtrToStringAnsi(nativeBuffer, (int)requiredSize);
                        }
                    }
                }
                catch (Exception ex)
                {
                    PluginBase.WriteDebugMessage("Exception {0}\n stack trace {1}", ex.Message, ex.StackTrace);
                    result.name = ex.Message;
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
                    var requiredSize = ida_get_segm_class(IntPtr.Zero, index);
                    if (-1 == requiredSize)
                    {
                        result.sclass = string.Empty;
                    }
                    else
                    {
                        nativeBuffer = Marshal.AllocCoTaskMem((int)requiredSize);
                        requiredSize = ida_get_segm_class(nativeBuffer, index);
                        if (0 <= requiredSize)
                        {
                            result.sclass = Marshal.PtrToStringAnsi(nativeBuffer, (int)requiredSize);
                        }
                    }
                }
                catch (Exception ex)
                {
                    PluginBase.WriteDebugMessage("Exception {0}\n stack trace {1}", ex.Message, ex.StackTrace);
                    result.sclass = ex.Message;
                }
                finally
                {
                    if (IntPtr.Zero != nativeBuffer)
                    {
                        Marshal.FreeCoTaskMem(nativeBuffer);
                        nativeBuffer = IntPtr.Zero;
                    }
                }

                result.start_ea = ida_get_segm_start_ea(index);
                result.end_ea = ida_get_segm_end_ea(index);
                result.align = (SegmentAlignement)ida_get_segm_align(index);
                result.comb = (SegmentCombination)ida_get_segm_comb(index);
                result.perm = (SegmentPermission)ida_get_segm_perm(index);
                result.bitness = (SegmentBitness)ida_get_segm_bitness(index);
                result.flags = (SegmentFlags)ida_get_segm_flags(index);
                result.type = (SegmentType)ida_get_segm_type(index);

                yield return result;
            }

            yield break;
        }

        internal static SegmentT GetSegmentContainingAddress(ea_t ea)
        {
            foreach (var segment in Segments.EnumerateSegments())
            {
                if (segment.Contains(ea))
                {
                    return segment;
                }
            }

            return new SegmentT();
        }
    }
}
