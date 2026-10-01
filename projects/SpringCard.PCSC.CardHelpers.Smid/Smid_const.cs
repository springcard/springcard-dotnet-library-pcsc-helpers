/*
 * SpringCard Smid Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard Smid library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using System;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of Smid_const.
    /// </summary>
    public partial class Smid
    {
        public const byte ISO7816_CLA = 0x90;
        public const uint HCE_USI_LENGTH = 7;

        /*
         * DESFire status (codes returned by the PICC)
         * -------------------------------------------
         */

        public const long Success = 0x0000;

        /*
         * Smid commands (codes sent by the PCD)
         * ----------------------------------------
         */

        public enum SmidCommand : byte
        {
            AUTHENTICATE = 0xA1,
            GET_NB_CARD = 0x6C,
            GET_DATA = 0x6D,
            TRANSACTION_COMMIT = 0xC7,
            EXTENDED = 0xAF,
            NFC_ID = 0x5C,
            SELECT = 0xA4,
            EXTENDED_STID = 0xFF,
            RFU = 0x00
        }
        public enum SmidCardError : byte
        {
            NormalProcessing = 0x00,
            LengthError = 0x7E,
            TimeoutError = 0x06,
            IntegrityError = 0x1E,
            PermissionDenied = 0x6C,
            AuthenticateError = 0xAE,
            AdditionalFrame = 0xAF,
            NoCardWithSiteCode = 0x0C,
            Unknown = 0xFF,

        }

        public enum SmidLibraryError : byte
        {
            Unknown = 0,
            OperationUnsupported,
            EmptyAnswer,
            LibraryCall,
            InvalidParameter,
            OutOfMemory,
            KeyDiversification,
            AuthenticationFailed,
            SelectApplicationFailed,
            WrongUsiLength,
            CmacDiffer,

        }
        public enum SmidProtocolVersion : ushort
        {
            Smid_vNone = 0x0000,
            Smid_v110 = 0x0110,
            Smid_v201 = 0x0201,
            Smid_v211 = 0x0211,
            Smid_v212 = 0x0212,
        }
        
    }
}
