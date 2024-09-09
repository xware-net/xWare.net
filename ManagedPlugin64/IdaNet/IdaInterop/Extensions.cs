using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Runtime.InteropServices;

namespace IdaNet.IdaInterop
{
    public static class Extensions
    {
        private static void Resize<T>(this List<T> list, int size) where T : struct
        {
            if (size > list.Count)
                while (size - list.Count > 0)
                    list.Add(default(T));
            else if (size < list.Count)
                while (list.Count - size > 0)
                    list.RemoveAt(list.Count - 1);
        }
        
        public static T CastToStruct<T>(this byte[] data) where T : struct
        {
            var pData = GCHandle.Alloc(data, GCHandleType.Pinned);
            var result = (T)Marshal.PtrToStructure(pData.AddrOfPinnedObject(), typeof(T));
            pData.Free();
            return result;
        }

        public static byte[] CastToArray<T>(this T data) where T : struct
        {
            var result = new byte[Marshal.SizeOf(typeof(T))];
            var pResult = GCHandle.Alloc(result, GCHandleType.Pinned);
            Marshal.StructureToPtr(data, pResult.AddrOfPinnedObject(), true);
            pResult.Free();
            return result;
        }
        
        internal static string Stringify(this InfoFlags flags)
        {
            string outstring = string.Empty;
            bool b = false;

            if ((flags & InfoFlags.INFFL_AUTO) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "INFFL_AUTO";
                b = true;
            }

            if ((flags & InfoFlags.INFFL_ALLASM) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "INFFL_ALLASM";
                b = true;
            }

            if ((flags & InfoFlags.INFFL_LOADIDC) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "INFFL_LOADIDC";
                b = true;
            }

            if ((flags & InfoFlags.INFFL_NOUSER) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "INFFL_NOUSER";
                b = true;
            }

            if ((flags & InfoFlags.INFFL_READONLY) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "INFFL_READONLY";
                b = true;
            }

            if ((flags & InfoFlags.INFFL_CHKOPS) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "INFFL_CHKOPS";
                b = true;
            }

            if ((flags & InfoFlags.INFFL_NMOPS) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "INFFL_NMOPS";
                b = true;
            }

            if ((flags & InfoFlags.INFFL_GRAPH_VIEW) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "INFFL_GRAPH_VIEW";
                b = true;
            }

            return outstring;
        }

        internal static string Stringify(this MiscDatabaseFlags flags)
        {
            string outstring = string.Empty;
            bool b = false;

            if ((flags & MiscDatabaseFlags.LFLG_PC_FPP) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "LFLG_PC_FPP";
                b = true;
            }

            if ((flags & MiscDatabaseFlags.LFLG_PC_FLAT) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "LFLG_PC_FLAT";
                b = true;
            }

            if ((flags & MiscDatabaseFlags.LFLG_64BIT) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "LFLG_64BIT";
                b = true;
            }

            if ((flags & MiscDatabaseFlags.LFLG_IS_DLL) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "LFLG_IS_DLL";
                b = true;
            }

            if ((flags & MiscDatabaseFlags.LFLG_FLAT_OFF32) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "LFLG_FLAT_OFF32";
                b = true;
            }

            if ((flags & MiscDatabaseFlags.LFLG_MSF) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "LFLG_MSF";
                b = true;
            }

            if ((flags & MiscDatabaseFlags.LFLG_WIDE_HBF) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "LFLG_WIDE_HBF";
                b = true;
            }

            if ((flags & MiscDatabaseFlags.LFLG_DBG_NOPATH) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "LFLG_DBG_NOPATH";
                b = true;
            }

            if ((flags & MiscDatabaseFlags.LFLG_SNAPSHOT) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "LFLG_SNAPSHOT";
                b = true;
            }

            if ((flags & MiscDatabaseFlags.LFLG_PACK) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "LFLG_PACK";
                b = true;
            }

            if ((flags & MiscDatabaseFlags.LFLG_COMPRESS) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "LFLG_COMPRESS";
                b = true;
            }

            if ((flags & MiscDatabaseFlags.LFLG_KERNMODE) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "LFLG_KERNMODE";
                b = true;
            }

            return outstring;
        }

        internal static string Stringify(this AnalysisFlags flags)
        {
            string outstring = string.Empty;
            bool b = false;

            if ((flags & AnalysisFlags.AF_CODE) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_CODE";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_MARKCODE) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_MARKCODE";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_JUMPTBL) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_JUMPTBL";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_PURDAT) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_PURDAT";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_USED) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_USED";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_UNK) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_UNK";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_PROCPTR) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_PROCPTR";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_PROC) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_PROC";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_FTAIL) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_FTAIL";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_LVAR) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_LVAR";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_STKARG) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_STKARG";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_REGARG) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_REGARG";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_TRACE) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_TRACE";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_VERSP) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_VERSP";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_ANORET) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_ANORET";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_MEMFUNC) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_MEMFUNC";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_TRFUNC) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_TRFUNC";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_STRLIT) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_STRLIT";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_CHKUNI) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_CHKUNI";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_FIXUP) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_FIXUP";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_DREFOFF) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_DREFOFF";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_IMMOFF) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_IMMOFF";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_DATOFF) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_DATOFF";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_FLIRT) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_FLIRT";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_SIGCMT) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_SIGCMT";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_SIGMLT) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_SIGMLT";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_HFLIRT) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_HFLIRT";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_JFUNC) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_JFUNC";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_NULLSUB) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_NULLSUB";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_DODATA) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_DODATA";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_DOCODE) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_DOCODE";
                b = true;
            }

            if ((flags & AnalysisFlags.AF_FINAL) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF_FINAL";
                b = true;
            }

            return outstring;
        }

        internal static string Stringify(this AnalysisFlagsEx flags)
        {
            string outstring = string.Empty;
            bool b = false;

            if ((flags & AnalysisFlagsEx.AF2_DOEH) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF2_DOEH";
                b = true;
            }

            if ((flags & AnalysisFlagsEx.AF2_DORTTI) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF2_DORTTI";
                b = true;
            }

            if ((flags & AnalysisFlagsEx.AF2_MACRO) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += "AF2_MACRO";
                b = true;
            }

            return outstring;
        }

        internal static string Stringify(this cm_t flags)
        {
            string outstring = string.Empty;
            bool b = false;

            if ((flags & cm_t.CM_MASK) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += Enum.GetName(typeof(cm_t), (flags & cm_t.CM_MASK));
                b = true;
            }

            if ((flags & cm_t.CM_M_MASK) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += Enum.GetName(typeof(cm_t), (flags & cm_t.CM_M_MASK));
                b = true;
            }

            if ((flags & cm_t.CM_CC_MASK) != 0)
            {
                if (b)
                {
                    outstring += " | ";
                }

                outstring += Enum.GetName(typeof(cm_t), (flags & cm_t.CM_CC_MASK)); 
                b = true;
            }

            return outstring;
        }
    }
}
