/*
 * Created by SharpDevelop.
 * User: Jerome Izaac
 * Date: 12/09/2017
 * Time: 14:22
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using SpringCard.LibCs;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of DESFire_mgmt.
    /// </summary>
    public partial class Desfire
    {
        /**
         * NAME
         *   DesfireAPI :: Card management functions
         *
         * COPYRIGHT
         *   (c) 2009 SpringCard - www.springcard.com
         *
         * DESCRIPTION
         *   Implementation of management functions to personalize or format the
         *   DESFIRE card.
         *
         **/

        public long ECP2EndSession()
        {
            logger.trace("ECP2EndSession");

            xfer_buffer[INF + 0] = (byte)DesfireCommand.ECP2_END_SESSION;
            xfer_length = 1;

            return Command(0, DesfireCommandFlag.WANTS_OPERATION_OK);
        }


        /**
 * @fn *   GetFreeMemory
 * @brief *   Reads out the number of available bytes on the PICC
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK : operation succeeded
 * @note *   This command can be issued without valid authentication.
 */
        public long GetFreeMemory(out uint FreeBytes)
        {
            long status;
            FreeBytes = 0;

            logger.trace("GetFreeMemory");

            /* Create the info block containing the command code and the key number argument. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.GET_FREE_MEMORY;
            xfer_length = 1;

            if (SessionIsEV2OrGreater())
            {
                /* Under active authentication, the command Cmd.GetFileSettings requires CommMode.MAC */
                status = Command(4, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* Communicate the info block to the card and check the operation's return status. */
                /* The returned info block must contain 4 bytes, the status code and the requested */
                /* information.                                                                    */
                status = Command(4, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            if (status != Success)
                return status;

            /* Get the actual value. */
            FreeBytes = 0;
            FreeBytes += xfer_buffer[INF + 3];
            FreeBytes <<= 8;
            FreeBytes += xfer_buffer[INF + 2];
            FreeBytes <<= 8;
            FreeBytes += xfer_buffer[INF + 1];

            logger.trace("GetFreeMemory->{0}B", FreeBytes);

            /* Success. */
            return Success;
        }

        /**
         * @brief Retrieves the UID of the DESFire chip.
         *
         * @param[out] CardUid A byte array containing the UID.
         * @return A status code indicating the result of the operation.
         */
        public long GetCardUID(out byte[] CardUid)
        {
            logger.trace("GetCardUID");
            CardUid = null;

            long status;

            /* Create the info block containing the command code and the key number argument. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.GET_CARD_UID;
            xfer_length = 1;

            if (SessionIsEV2OrGreater())
            {
                /* Communicate the info block to the card and check the operation's return status. */
                /* The returned info block must contain 4 bytes, the status code and the requested */
                /* information.                                                                    */
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
                if (status != Success)
                    return status;

                /* at first we have to decipher the recv_buffer */
                CardUid = BinUtils.Copy(xfer_buffer, 1, xfer_length - 1);
                SessionCryptoContext.CipherRecv(ref CardUid);

                /* Decipher and unpadd the buffer */
                status = DecipherAfterReadEV2(xfer_buffer, ref xfer_length);
                if (status != Success)
                    return status;
            }
            else if (SessionIsEV0OrGreater())
            {
                /* Communicate the info block to the card and check the operation's return status. */
                /* The returned info block must contain 4 bytes, the status code and the requested */
                /* information.                                                                    */
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
                if (status != Success)
                    return status;

                if (SessionIsEV1OrGreater())
                {
                    /* Decipher, unpad and check CRC32 */
                    status = DecipherAfterReadEV1(xfer_buffer, ref xfer_length, 1, 7);
                    if (status != Success)
                        return status;
                }
                else
                {
                    /* Decipher, unpad and check CRC32 */
                    status = DecipherAfterReadEV0(xfer_buffer, ref xfer_length, 1, 7);
                    if (status != Success)
                        return status;
                }
            }

            if ((xfer_buffer[1] == 0) && (xfer_length > 3))
            {
                byte uid_length = xfer_buffer[2];
                if (xfer_length != 3 + uid_length)
                    return LibraryError(DesfireLibraryError.WrongData);
                
                CardUid = BinUtils.Copy(xfer_buffer, 3, uid_length);
            }
            else
            {
                CardUid = BinUtils.Copy(xfer_buffer, 1, 7);
            }

            logger.trace("GetCardUID->{0}", BinConvert.ToHex(CardUid));

            /* Success. */
            return Success;

        }

        /**
 * @fn *   FormatDAM
 * @brief *   Releases the DesFire card user memory
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : format succeeded
 * @note *   Current DAM selected are deleted.
 */
        public long FormatDAM()
        {
            /* Communicate the info block to the card and check the operation's return status. */
            return FormatPICC();
        }

        /**
 * @fn *   FormatPICC
 * @brief *   Releases the DesFire card user memory
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : format succeeded
 * @note *   All applications are deleted and all files within those applications  are deleted.
 */
        public long FormatPICC()
        {
            logger.trace("FormatPICC");

            /* Create the info block containing the command code. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.FORMAT_PICC;
            xfer_length = 1;

            if (SessionIsEV2OrGreater())
            {
                /* Communicate the info block to the card and check the operation's return status. */
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            /* Communicate the info block to the card and check the operation's return status. */
            return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
        }

        /**
 * @struct *   DesfireCommand.VERSION_INFO
 * @brief *   Structure for returning the information supplied by the GetVersion command.
 */

        /**
 * @fn *   GetVersion
 * @brief *   Returns manufacturing related data of the DesFire card
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : operation succeeded
 */
        public long GetVersion(out byte[] VersionInfo)
        {
            logger.trace("GetVersion");

            int recv_length = 1;
            byte[] recv_buffer = new byte[256];
            long status;

            VersionInfo = null;

            /* create the info block containing the command code */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.GET_VERSION;

            for (; ; )
            {
                if (SessionIsEV2OrGreater())
                {
                    /* authentification CMAC is required */
                    status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME | DesfireCommandFlag.WANTS_OPERATION_OK);
                }
                else
                {
                    status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME | DesfireCommandFlag.WANTS_OPERATION_OK);
                }

                if (status != Success)
                    return status;

                if ((xfer_length - 1) > (256 - recv_length))
                {
                    Array.ConstrainedCopy(xfer_buffer, INF + 1, recv_buffer, recv_length, (256 - recv_length));
                    recv_length = 256;
                }
                else
                {
                    /* Remember the frame for later CMAC processing */
                    Array.ConstrainedCopy(xfer_buffer, INF + 1, recv_buffer, recv_length, (xfer_length - 1));
                    recv_length += (xfer_length - 1);
                }

                if (xfer_buffer[INF + 0] != (byte) DesfireCardError.AdditionalFrame)
                    break;

                xfer_length = 1;
            }

            recv_buffer[0] = (byte)Success;

            /* Check the CMAC */
            if (SessionIsEV1OrGreater())
            {
                if (!SessionCryptoContext.VerifyAndRemoveCmacRecv(recv_buffer, ref recv_length))
                    status = LibraryError(DesfireLibraryError.WrongCMAC);
            }

            if (status != Success)
                return status;

            VersionInfo = BinUtils.Copy(recv_buffer, 1, recv_length - 1);

            logger.trace("GetVersion->{0}", BinConvert.ToHex(VersionInfo));

            return Success;
        }

        public long GetVersion(out DesfireVersionInfo VersionInfo)
        {
            long status;

            VersionInfo = new DesfireVersionInfo();

            status = GetVersion(out byte[] buffer);
            if (status != Success)
                return status;

            if (buffer.Length < 28)
                return LibraryError(DesfireLibraryError.WrongLength);

            VersionInfo = new DesfireVersionInfo();
            VersionInfo.Uid = new byte[7];
            VersionInfo.BatchNo = new byte[5];


            VersionInfo.HwVendorID = buffer[0];
            VersionInfo.HwType = buffer[1];
            VersionInfo.HwSubType = buffer[2];
            VersionInfo.HwMajorVersion = buffer[3];
            VersionInfo.HwMinorVersion = buffer[4];
            VersionInfo.HwStorageSize = buffer[5];
            VersionInfo.HwProtocol = buffer[6];
            VersionInfo.SwVendorID = buffer[7];
            VersionInfo.SwType = buffer[8];
            VersionInfo.SwSubType = buffer[9];
            VersionInfo.SwMajorVersion = buffer[10];
            VersionInfo.SwMinorVersion = buffer[11];
            VersionInfo.SwStorageSize = buffer[12];
            VersionInfo.SwProtocol = buffer[13];
            VersionInfo.Uid = BinUtils.Copy(buffer, 14, 7);
            VersionInfo.BatchNo = BinUtils.Copy(buffer, 21, 5);
            VersionInfo.ProductionCW = buffer[26];
            VersionInfo.ProductionYear = buffer[27];

            return status;
        }
    }
}
