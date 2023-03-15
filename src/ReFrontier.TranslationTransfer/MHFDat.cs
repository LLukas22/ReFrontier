using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace ReFrontier.TranslationTransfer
{

    public enum Ranks
    {
        HR1 = 0,
        HR2 = 1,
        HR3 = 2,
        HR4 = 3,
        HR5 = 4,
        HR6 = 5,
        GR1= 6,
        GR2= 7,
        GR3 = 8,
        GR4 = 9,
        GR5 = 10,
        GR6 = 11,
        GR7 = 12,
        GR8 = 13,
        GR9 = 14,
        GR10 = 15
    }
    public static class MHFDat
    {
        //Length of the unpatched File
        public const int OriginalLength = 26454976;

        #region Quests
        public const int HRankStartAdress = 2712;
        public const int LowGRankStartAdress = 1736;
        public const int HighGRankStartAdress = 1856;

        public static int GetRankAddress(Ranks rank, byte[] data)
        {
            var rank_pointer_address = GetRankPointerAddress(rank);
            //Low and Highrank need to be offset at the actual rank pointer
            if (rank <= Ranks.HR6)
            {
                var offset_rank_pointer = BitConverter.ToInt32(data, rank_pointer_address) + ((int)rank * 4);
                return BitConverter.ToInt32(data, offset_rank_pointer);
            }
            else
            {
                var rank_pointer = BitConverter.ToInt32(data, rank_pointer_address);
                return BitConverter.ToInt32(data, rank_pointer);
            }
        }
        public static int GetRankPointerAddress(Ranks rank)
        {
            switch (rank)
            {
                case Ranks.HR1:
                case Ranks.HR2:
                case Ranks.HR3:
                case Ranks.HR4:
                case Ranks.HR5:
                case Ranks.HR6:
                    return HRankStartAdress;
                case Ranks.GR1:
                case Ranks.GR2:
                case Ranks.GR3:
                case Ranks.GR4:
                case Ranks.GR5:
                case Ranks.GR6:
                case Ranks.GR7:
                    var relative_g_rank_index = ((int)rank)-6;
                    return LowGRankStartAdress + relative_g_rank_index*4;
                case Ranks.GR8:
                case Ranks.GR9:
                case Ranks.GR10:
                    var relative_high_g_rank_index = ((int)rank)-13;
                    return HighGRankStartAdress + relative_high_g_rank_index*4;
                default: 
                    throw new ArgumentException("Unknown Rank");
            }
        } 
        #endregion

        #region Text
        public const int JapaneseTextStart = 3072;
        public const int JapaneseTextEnd = 3328538;
        #endregion

        #region Translations
        public const int TranslationPointersStart = 4428256;
        public static readonly (int start, int end)[] TranslationInvalidRegions = new (int start, int end)[] { (4705152, 9652320), (9743504, 12039636), (12245080, 13425300), (13670932, 23693140), (23779568, 26139300), (26151480, 26297040) };
        #endregion
    }
}
