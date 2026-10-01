/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using System;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        /**
         * @brief Desfire ISO wrapping mode.
         *
         * This enum defines the different modes of ISO 7816-4 wrapping for DESFire commands.
         */
        public enum DesfireIsoWrapping
        {
            None = 0, //<- No Wrapping, DESFire Legacy protocol
            Card = 1, //<- Let the Library perform the ISO Wrapping (recommended)
            Reader = 2 //<- Let the Reader perform the ISO Wrapping (works with SpringCard PC/SC readers only)
        }

        DesfireIsoWrapping IsoWrapping;

        private bool BuildIsoApdu(byte[] native_buffer, int native_buflen, byte[] iso_buffer, ref int iso_buflen, bool use_reader_wrapping)
        {
            if ((native_buffer == null) || (iso_buffer == null))
                return false;

            /* We can't accept an empty command */
            if (native_buflen == 0)
                return false;

            if (use_reader_wrapping)
            {
                /* Send an encapsulated APDU to the CSB6's embedded interpreter */
                /* ------------------------------------------------------------ */

                /* Check target length */
                if (iso_buflen < (6 + native_buflen))
                    return false;

                /* Build the APDU */
                iso_buffer[0] = 0xFF;                                  /* CLA  : CSB6's embedded interpreter */
                iso_buffer[1] = 0xFE;                                  /* INS  : ENCAPSULATE                 */
                iso_buffer[2] = 0x00;                                  /* P1   : dummmy                      */
                iso_buffer[3] = 0x00;                                  /* P2   : dummy                       */
                iso_buffer[4] = (byte)native_buflen;                  /* LC   : size of native buffer       */
                Array.ConstrainedCopy(native_buffer, 0, iso_buffer, 5, native_buflen); /* Data : native buffer itself        */
                iso_buffer[5 + native_buflen] = 0;                       /* LE   : accept any length in return */

                iso_buflen = 6 + native_buflen;

            }
            else
            {
                /* Use the Desfire ISO wrapping */
                /* ---------------------------- */

                /* Check target length */
                if (iso_buflen < (5 + native_buflen))
                    return false;

                /* Build the APDU */
                iso_buffer[0] = 0x90;                                  /* CLA  : Desfire specifc class       */
                iso_buffer[1] = native_buffer[0];                      /* INS  : Desfire command code        */
                iso_buffer[2] = 0x00;                                  /* P1   : dummmy                      */
                iso_buffer[3] = 0x00;                                  /* P2   : dummy                       */

                if (native_buflen > 1)
                {
                    iso_buffer[4] = (byte) (native_buflen-1);            /* LC   : length of command params    */
                    if (native_buflen>1)                                 /* Data : Desfire command parameters  */ 
                        Array.ConstrainedCopy(native_buffer, 1, iso_buffer, 5,   (native_buflen - 1));
                    iso_buffer[5+native_buflen-1] = 0;                   /* LE   : accept any length in return */
                    iso_buflen = 5 + native_buflen;
                }
                else
                {
                    iso_buffer[4] = 0x00;                                /* LE   : accept any length in return */
                    iso_buflen = 5;
                }
            }
            return true;
        }
    }
}
