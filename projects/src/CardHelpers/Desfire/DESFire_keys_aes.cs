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
 * @fn *   ChangeKeyAes
 * @brief *   Change an AES key in the selected Desfire application.
 * @details
 * *
 * @return *   DF_OPERATION_OK    : change succeeded
 */
        public long ChangeKey(byte KeyNumber, byte KeyVersion, byte[] NewKeyValue, byte[] OldKeyValue)
        {
            if (SessionIsEV2OrGreater())
            {
                return ChangeKeyExEV2(DF_CHANGE_KEY, false, 0, KeyNumber, true, KeyVersion, NewKeyValue, OldKeyValue);
            }
            else if (SessionIsEV1OrGreater())
            {
                return ChangeKeyExEV1(KeyNumber, true, KeyVersion, NewKeyValue, OldKeyValue);
            }
            else
            {
                return DFCARD_LIB_CALL_ERROR;
            }
        }

    }
}
