/*
 * Created by SharpDevelop.
 * User: Jerome Izaac
 * Date: 15/09/2017
 * Time: 10:34
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using SpringCard.LibCs;
using System;
using System.Security.Cryptography;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of DESFire_keys.
    /// </summary>
    public partial class Desfire
    {
        /**
 * @file
 * @brief *   DesfireAPI :: Key management functions
 * @details *   Implementation of management functions to change keys or
 * @copyright *   (c) 2009 SpringCard - www.springcard.com
 */

        /**
 * @fn *   ChangeKeySettings
 * @brief *   Changes the key settings of the currently selected application
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : change succeeded
 */
        public long ChangeKeySettings(byte KeySettings)
        {
            logger.trace("ChangeKeySettings({0:X02})", KeySettings);

            xfer_length = 0;

            /* Create the info block containing the command code */
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.CHANGE_KEY_SETTINGS;
            xfer_buffer[xfer_length++] = KeySettings;

            if (SessionIsEV2OrGreater())
            {
                /* 'Encrypt' the buffer E(KSesAuth, NewKeyValue[|| KeyVer]) */
                Xfer_Padd_CipherSend(1);
                /* Append the CMAC */
                Xfer_AppendCmac();
            }
            else
            {
                /* Append the CRC value corresponding to the KeySettings byte */
                /* Then 'Encrypt' the bNewKeySettings byte and its CRC bytes.  */
                XferAppendCrc(1);
                Xfer_Padd_CipherSend(1);

                /* Communicate the info block to the card and check the operation's return status. */
            }

            return Command(0, DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
        }

        /**
 * @fn *   GetKeySettings
 * @brief *   Gets information on the DesFire card and application master key settings. In addition it returns
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : operation succeeded
 */
        public long GetKeySettings(out byte bKeySettings, out byte bKeyCount)
        {
            long status;
            bKeySettings = 0;
            bKeyCount = 0;

            /* Create the info block containing the command code */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.GET_KEY_SETTINGS;
            xfer_length = 1;

            /* EV2 secure mode */
            if (SessionIsEV2OrGreater())
            {
                /* size is 3 or 7 if AKS defined*/
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
                if (status != Success)
                    return status;
                if (xfer_length < 3)
                    return LibraryError(DesfireLibraryError.WrongLength);
            }
            else
            {
                /* Communicate the info block to the card and check the operation's return status. */
                /* GetKeySettings returns 3 bytes, the status and two bytes of information.        */
                status = Command(3, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
                if (status != Success)
                    return status;
            }

            /* Return the requested key settings bytes. */
            bKeySettings = xfer_buffer[INF + 1];
            bKeyCount = xfer_buffer[INF + 2];

            /* Success */
            return Success;
        }

        /**
 * @fn *   GetKeySettings
 * @brief *   Gets information on the DesFire card and application master key settings (used for AKS). In addition it returns
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : operation succeeded
 */
        public long GetKeySettings(out byte KeySettings, out byte KeyCount, out byte AKSVersion, out byte NoKeySets, out byte MaxKeySize, out byte AppKeySetSett)
        {
            long status;

            KeySettings = 0;
            KeyCount = 0;
            AKSVersion = 0;
            NoKeySets = 0;
            MaxKeySize = 0;
            AppKeySetSett = 0;

            /* Create the info block containing the command code */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.GET_KEY_SETTINGS;
            xfer_length = 1;

            /* EV2 secure mode */
            if (SessionIsEV2OrGreater())
            {
                /* size is 3 or 7 if AKS defined*/
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* Communicate the info block to the card and check the operation's return status. */
                /* GetKeySettings returns 3 bytes, the status and two bytes of information.        */
                status = Command(3, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            if (status != Success)
                return status;

            /* Return the requested key settings bytes. */
            KeySettings = xfer_buffer[INF + 1];
            KeyCount = xfer_buffer[INF + 2];
            AKSVersion = xfer_buffer[INF + 3];
            NoKeySets = xfer_buffer[INF + 4];
            MaxKeySize = xfer_buffer[INF + 5];
            AppKeySetSett = xfer_buffer[INF + 6];
            /* Success */
            return Success;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="key_set_number"></param>
        /// <param name="KeyNumber"></param>
        /// <param name="NewKeyValue"></param>
        /// <param name="OldKeyValue"></param>
        /// <returns></returns>

        /// <summary>
        /// 
        /// </summary>
        /// <param name="KeyNumber"></param>
        /// <param name="KeySetNumber"></param>
        /// <param name="pbKeyVersion"></param>
        /// <returns></returns>
        private long GetKeyVersion_Ex(ushort header_size, out byte[] pbKeyVersion)
        {
            long status;
            pbKeyVersion = null;

            /* EV2 secure mode */
            if (SessionIsEV2OrGreater())
            {
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                status = Command(header_size, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }

            if (status != Success)
                return status;

            /* Get the key version byte. */
            pbKeyVersion = BinUtils.Copy(xfer_buffer, INF + 1, xfer_length - 1);

            /* Success. */
            return Success;
        }

        /**
 * @fn *   GetKeyVersion
 * @brief *   Reads out the current key version of any key stored on the PICC
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : operation succeeded
 * @note *   This command can be issued without valid authentication.
 */
        public long GetKeyVersion(byte KeyNumber, out byte KeyVersion)
        {
            KeyVersion = 0;

            long status;

            /* Create the info block containing the command code and the key number argument. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.GET_KEY_VERSION;
            xfer_buffer[INF + 1] = KeyNumber;
            xfer_length = 2;

            status = GetKeyVersion_Ex(2, out byte[] localKeyVersion);

            if (status != Success)
                return status;

            /* Get the key version byte. */
            KeyVersion = localKeyVersion[0];

            /* Success. */
            return Success;
        }

        /**
 * @fn *   GetKeyVersionEv2
 * @brief *   Reads out the current key version of any key stored on the PICC
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : operation succeeded
 * @note *   This command can be issued without valid authentication.
 */
        public long GetKeyVersion(byte KeyNumber, byte KeySetNumber, out byte[] pbKeyVersion)
        {
            /* Create the info block containing the command code and the key number argument. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.GET_KEY_VERSION;
            xfer_buffer[INF + 1] = 0x40; // (byte) (KeyNumber | 0x40);
            xfer_buffer[INF + 2] = 0x80; // (byte) (KeySetNumber | 0x80);
            xfer_length = 3;

            return GetKeyVersion_Ex(3, out pbKeyVersion);
        }        
    }
}
