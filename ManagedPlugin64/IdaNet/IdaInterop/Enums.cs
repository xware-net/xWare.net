using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using static IdaPlusPlus.IdaInterop;

namespace IdaNet.IdaInterop
{
    public class Enums
    {
        #region PROPERTIES

        /// <summary>Get number of segments</summary>
        /// 
        internal static ulong Count
        {
            get { return ida_get_enum_qty(); }
        }

        #endregion
        internal static IEnumerable<Enumeration> EnumerateEnums()
        {
            for (ulong index = 0; index < Count; index++)
            {
                Enumeration result = new Enumeration();
                result.Index = index;

                yield return result;
            }

            yield break;
        }
    }
}
