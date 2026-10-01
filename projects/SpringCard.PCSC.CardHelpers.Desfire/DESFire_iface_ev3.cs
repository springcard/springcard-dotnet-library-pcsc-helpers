/**
 *
 * @addtogroup Desfire
 *
 * @brief Desfire library (.NET only, no native depedency)
 *
 * @copyright
 *   Copyright (c) 2018 SpringCard - www.springcard.com
 *   All right reserved
 *
 * @author
 *   Johann.D et al. / SpringCard
 *
 */
/*
 * Read LICENSE.txt for license details and restrictions.
 */
using System;
using System.Reflection;
using System.Xml.Schema;
using SpringCard.LibCs;
using SpringCard.PCSC;
using SpringCard.PCSC.CardHelpers;

namespace SpringCard.PCSC.CardHelpers
{
    public interface DesfireEV3 : DesfireEV2
    {
        /* Card Configuration Commands */

        /**
         * @brief Enable the Random ID feature of the DESFire chip.
         *
         * @param Legacy If true, use UID0=0x80.
         * @return A status code indicating the result of the operation.
         */
        long EnableRandomID(bool Legacy);

        /**
         * @brief Configures the DESFire chip or the currently selected application with the specified Capability Data.
         *
         * @param PiccCap12 See Desfire datasheet.
         * @param PiccCap25 See Desfire datasheet.
         * @param PiccCap26 See Desfire datasheet.
         * @return A status code indicating the result of the operation.
         */
        long SetCapabilityData(byte VCTID, byte PiccCap12, byte PiccCap22, byte PiccCap25, byte PiccCap26);

        /**
         * @brief Configures the DESFire chip with the specified ATQA.
         *
         * @param AtqA See Desfire datasheet.
         * @return A status code indicating the result of the operation.
         */
        long SetUserATQA(byte[] AtqA);

    }
}
