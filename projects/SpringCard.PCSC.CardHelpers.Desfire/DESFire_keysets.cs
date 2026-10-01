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
        public long RollKeySet(byte KeySetNumber)
        {
            long status;

            logger.trace("RollKeySet({0:X02})", KeySetNumber);

            /* Create the info block containing the command code and the key number argument. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.ROLL_KEY_SET;
            xfer_buffer[INF + 1] = KeySetNumber;
            xfer_length = 2;

            if (SessionIsEV2OrGreater())
            {
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            if (status != Success)
                return status;

            /* As the authentication is lost, the response is sent with CommMode.Plain. */
            /*status = VerifyCmacRecvEV2(xfer_buffer, ref xfer_length);
            if (status != DesfireCommand.OPERATION_OK)
              return status;*/

            /* Success. */
            return Success;
        }

        public long InitializeKeySet(byte KeySetNumber, byte KeySetType)
        {
            long status;

            logger.trace("InitializeKeySet({0:X02}, {1:X02})", KeySetNumber, KeySetType);

            /* If KeySetNo is 0x00, the command is rejected as it is forbidden to initialize the AKS. */
            if ((KeySetNumber & 0x7F) == 0x00)
            {
                return LibraryError(DesfireLibraryError.InvalidParameter);
            }
            /* only 00, 01 or 10 allowed */
            if ((KeySetType & 0x03) == 0x03)
            {
                return LibraryError(DesfireLibraryError.InvalidParameter);
            }
            /* Create the info block containing the command code and the key number argument. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.INITIALIZE_KEY_SET;
            xfer_buffer[INF + 1] = KeySetNumber;
            xfer_buffer[INF + 2] = KeySetType;
            xfer_length = 3;

            /* Communicate the info block to the card and check the operation's return status.   */
            /* The returned info block must contain two bytes, the status code and the requested */
            /* key version byte.                                                                 */
            if (SessionIsEV2OrGreater())
            {
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }

            if (status != Success)
                return status;


            /* Success. */
            return Success;
        }

        public long FinalizeKeySet(byte KeySetNumber, byte KeySetVersion)
        {
            long status;

            logger.trace("FinalizeKeySet({0:X02}, {1:X02})", KeySetNumber, KeySetVersion);

            /* If KeySetNo is 0x00, the command is rejected as it is forbidden to initialize the AKS. */
            if ((KeySetNumber & 0x7F) == 0x00)
            {
                return LibraryError(DesfireLibraryError.InvalidParameter);
            }
            /*The key set version of the key set targeted by Cmd.RollKeySet has
              to be strictly bigger than the key set version of the AKS. 0x00 is never possible*/
            if (KeySetVersion == 0x00)
            {
                return LibraryError(DesfireLibraryError.InvalidParameter);
            }
            /* Create the info block containing the command code and the key number argument. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.FINALIZE_KEY_SET;
            xfer_buffer[INF + 1] = KeySetNumber;
            xfer_buffer[INF + 2] = KeySetVersion;
            xfer_length = 3;

            /* Communicate the info block to the card and check the operation's return status.   */
            /* The returned info block must contain two bytes, the status code and the requested */
            /* key version byte.                                                                 */
            if (SessionIsEV2OrGreater())
            {
                status = Command(0, DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            if (status != Success)
                return status;

            /* Success. */
            return Success;
        }
    }

}
