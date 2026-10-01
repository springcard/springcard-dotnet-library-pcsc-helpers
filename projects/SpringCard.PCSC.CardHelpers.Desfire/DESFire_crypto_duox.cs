/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using SpringCard.LibCs;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        public class DesfireCryptoContextDuoX : DesfireCryptoContextEV2
        {
            public DesfireCryptoContextDuoX(Desfire desfire) : base(desfire, EAuthType.AES128_EV2)
            {
                /* DS874411 page 44 : The TI is set to all zero bytes */
                TransactionIdentifier = new byte[4];
            }

            public void GenerateSessionKeysDuoX(byte[] PublicKeyA, byte[] PublicKeyB, byte[] SharedSecret)
            {
                byte[] IV = new byte[16];

                logger.debug("GenerateSessionKeysDuoX");

                /*            
                 * In the first step, a KDK(Key Derivation Key) is generated out of a concatenation of the 8 least significant bytes
                 * from both shared ephemeral public keys X-coordinates during the first step of Cmd.ISOGeneralAuthenticate
                 * used as an AES key and the shared secret(ShS) from the ECDH key agreement as message.
                 */

                byte[] cmacKey = BinUtils.Concat(BinUtils.Copy(PublicKeyA, 1 + 32 - 8, 8), BinUtils.Copy(PublicKeyB, 1 + 32 - 8, 8));

                logger.debug("Key: {0}", BinConvert.ToHex(cmacKey));
                logger.debug("ShS: {0}", BinConvert.ToHex(SharedSecret));

                SessionCmacKey = cmacKey;
                InitCmac();

                ComputeCmac(SharedSecret);
                byte[] KDK = BinUtils.Copy(InitVector);

                logger.debug("KDK: {0}", BinConvert.ToHex(KDK));

                SessionCmacKey = KDK;
                InitCmac();

                byte[] SV1 = new byte[16];
                SV1[0] = 0xB4; SV1[1] = 0x4B; SV1[3] = 0x01; SV1[5] = 0x80;
                logger.debug("SV1: {0}", BinConvert.ToHex(SV1));

                ResetInitVector();
                ComputeCmac(SV1);
                byte[] encKeyValue = BinUtils.Copy(InitVector);

                byte[] SV2 = new byte[16];
                SV2[0] = 0x4B; SV2[1] = 0xB4; SV2[3] = 0x01; SV2[5] = 0x80;
                logger.debug("SV2: {0}", BinConvert.ToHex(SV2));

                ResetInitVector();
                ComputeCmac(SV2);
                byte[] cmacKeyValue = BinUtils.Copy(InitVector);

                logger.debug("ENC: {0}", BinConvert.ToHex(encKeyValue));
                logger.debug("MAC: {0}", BinConvert.ToHex(cmacKeyValue));

                SessionEncKey = encKeyValue;
                SessionCmacKey = cmacKeyValue;
                InitCmac();
            }
        }
    }
}
