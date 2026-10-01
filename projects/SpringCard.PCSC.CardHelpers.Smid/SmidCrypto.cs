using SpringCard.LibCs;
using System;
using System.Collections.Generic;
using System.Text;


namespace SpringCard.PCSC.CardHelpers
{
    public partial class Smid
    {
        const uint AES128_BLOCK_LENGTH = 16;
        static readonly byte[] SMID_RESP_DATA_PADDING = { 0xAA, 0x1A, 0xC8, 0xC6, 0x59, 0x13, 0x80, 0x1A, 0xA8, 0xA3 };
        static readonly byte[] SMID_CMDE_DATA_PADDING = { 0x82, 0x48, 0x6F, 0xA5, 0xB0, 0xF2, 0x1F, 0x7C, 0xA4, 0x4C };

    }
}
