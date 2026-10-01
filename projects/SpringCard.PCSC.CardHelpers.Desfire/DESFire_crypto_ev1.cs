/*
 * Created by SharpDevelop.
 * User: Jerome Izaac
 * Date: 12/09/2017
 * Time: 14:22
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Ocsp;
using SpringCard.LibCs;
using SpringCard.LibCs.Crypto;
using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using static SpringCard.PCSC.CardHelpers.Desfire;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of DESFire_mgmt.
    /// </summary>
    public partial class Desfire
    {
        [Serializable]
        public abstract class DesfireCryptoContextEV1 : DesfireCryptoContext
        {
            protected byte RX_Xor_Value { get; private set; }
            [NonSerialized]
            protected byte[] AuthKeyValue;
            [NonSerialized]
            protected byte[] AuthRndPcd;
            [NonSerialized]
            protected byte[] AuthRndPicc;

            [NonSerialized]
            protected IBlockCipher cipherCore;

            /* Serialized data (explicit) */
            protected byte[] SessionKey;
            protected byte[] CmacSubKey1;
            protected byte[] CmacSubKey2;
            protected byte[] InitVector;

            /* Serialization */
            public override void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                base.GetObjectData(info, context);
                info.AddValue("AuthKVC", BinConvert.ToHex(AuthKVC));
                info.AddValue("SessionKey", BinConvert.ToHex(SessionKey));
                info.AddValue("CmacSubKey1", BinConvert.ToHex(CmacSubKey1));
                info.AddValue("CmacSubKey2", BinConvert.ToHex(CmacSubKey2));
                info.AddValue("InitVector", BinConvert.ToHex(InitVector));
            }

            /* Deserialization */
            protected DesfireCryptoContextEV1(SerializationInfo info, StreamingContext context) : base(info, context)
            {
                AuthKVC = BinConvert.HexToDword(info.GetString("AuthKVC"));
                SessionKey = BinConvert.HexToBytes(info.GetString("SessionKey"));
                CmacSubKey1 = BinConvert.HexToBytes(info.GetString("CmacSubKey1"));
                CmacSubKey2 = BinConvert.HexToBytes(info.GetString("CmacSubKey2"));
                InitVector = BinConvert.HexToBytes(info.GetString("InitVector"));
            }

            protected DesfireCryptoContextEV1(Desfire desfire, EAuthType AuthType, byte RB_Xor_Value, int BlockSize, int CmacSize) : base(desfire, AuthType, EPaddMode.Zeros, BlockSize, CmacSize)
            {
                this.RX_Xor_Value = RB_Xor_Value;
            }

            public uint AuthKVC { get; protected set; }
            public uint SessionKVC { get; protected set; }

            public void ExportSessionKey(out byte[] SessionKey)
            {
                SessionKey = BinUtils.Copy(this.SessionKey);
            }

            protected void ResetInitVector()
            {
                for (int i=0; i<InitVector.Length; i++)
                    InitVector[i] = 0;
            }

            protected void InitCmac()
            {
                byte bMSB;
                int t, i;

                if (desfire.logCrypto)
                    logger.trace("EV1.InitCmac");
                
                CmacSubKey1 = new byte[BlockSize];
                CmacSubKey2 = new byte[BlockSize];

                // Generate the padding bytes for O-MAC by enciphering a zero block
                // with the actual session key:
                for (i = 0; i < CmacSubKey1.Length; i++)
                    CmacSubKey1[i] = 0;

                if (desfire.logCrypto && desfire.logSecrets)
                    logger.debug("\tstep0. subkey1={0}", BinConvert.ToHex(CmacSubKey1));

                t = BlockSize;

                CipherSend(ref CmacSubKey1);

                if (desfire.logCrypto && desfire.logSecrets)
                    logger.debug("\tstep1. subkey1={0}", BinConvert.ToHex(CmacSubKey1));

                // If the MSBit of the generated cipher == 1 -> K1 = (cipher << 1) ^ Rb ...
                // store MSB:
                bMSB = CmacSubKey1[0];

                // Shift the complete cipher for 1 bit ==> K1:
                byte tmp;
                for (i = 0; i < BlockSize - 1; i++)
                {
                    tmp = (byte)((CmacSubKey1[i] << 1) & 0x00FE);
                    CmacSubKey1[i] = tmp;

                    // add the carry over bit:
                    CmacSubKey1[i] |= (byte)(((CmacSubKey1[i + 1] & 0x80) != 0) ? 0x01 : 0x00);
                }

                tmp = (byte)((CmacSubKey1[BlockSize - 1] << 1) & 0x00FE);
                CmacSubKey1[BlockSize - 1] = tmp;
                if ((bMSB & 0x80) != 0)
                {
                    // XOR with Rb:
                    CmacSubKey1[BlockSize - 1] ^= RX_Xor_Value;
                }

                if (desfire.logCrypto && desfire.logSecrets)
                    logger.debug("\tstep2. subkey1={0}", BinConvert.ToHex(CmacSubKey1));

                // store MSB:
                bMSB = CmacSubKey1[0];

                // Shift K1 ==> K2:
                for (i = 0; i < BlockSize - 1; i++)
                {
                    CmacSubKey2[i] = (byte)((CmacSubKey1[i] << 1) & 0x00FE);
                    CmacSubKey2[i] |= (byte)(((CmacSubKey1[i + 1] & 0x80) != 0) ? 0x01 : 0x00);
                }
                CmacSubKey2[BlockSize - 1] = (byte)((CmacSubKey1[BlockSize - 1] << 1) & 0x00FE);

                if ((bMSB & 0x80) == 0x80)
                {
                    // XOR with Rb:
                    CmacSubKey2[BlockSize - 1] ^= RX_Xor_Value;
                }

                if (desfire.logCrypto && desfire.logSecrets)
                    logger.debug("\tstep3. subkey2={0}", BinConvert.ToHex(CmacSubKey2));

                if (desfire.logCrypto && desfire.logSecrets)
                {
                    logger.debug("CMAC SubKey1={0}", BinConvert.ToHex(CmacSubKey1));
                    logger.debug("CMAC SubKey2={0}", BinConvert.ToHex(CmacSubKey2));
                }
            }

            public override byte[] ComputeCmacSend(byte[] data)
            {
                return ComputeCmac(data, false);
            }

            public override byte[] ComputeCmacRecv(byte[] data)
            {
                return ComputeCmac(data, true);
            }

            public override byte[] ComputeCmac(byte[] data)
            {
                return ComputeCmac(data, false);
            }

            private byte[] ComputeCmac(byte[] data, bool moveStatus)
            {
                if (desfire.logCrypto)
                {
                    logger.debug("  CalcCmac {0} [{1}]", BinConvert.ToHex(data), moveStatus.ToString());
                }

                // First we enlarge eNumOfBytes to a multiple of the cipher block size for allocating
                // memory of the intermediate buffer. Zero padding will be done by the DF8Encrypt function.
                // If we are ISO-authenticated, we have to do the spetial padding for the O-MAC:
                int length = data.Length;
                int actual_length = length;
                while ((actual_length % BlockSize) != 0)
                    actual_length++;

                byte[] buffer = new byte[actual_length];

                if (moveStatus)
                {
                    Array.ConstrainedCopy(data, 1, buffer, 0, (length - 1));
                    buffer[length - 1] = data[0];
                }
                else
                {
                    Array.ConstrainedCopy(data, 0, buffer, 0, (length));
                }

                /* Do the ISO padding and/or XORing */
                if ((length % BlockSize) != 0)
                {
                    /* Block incomplete -> padding + key 2 */
                    buffer[length++] = 0x80;

                    if (desfire.logCrypto)
                    {
                        logger.debug("      Key2 {0}", BinConvert.ToHex(CmacSubKey2));
                        logger.debug("      XOR  {0}", BinConvert.ToHex(buffer));
                    }

                    /* XOR the last eight bytes with CMAC_SubKey2 */
                    length = actual_length - BlockSize;
                    for (int i = 0; i < BlockSize; i++)
                    {
                        buffer[length + i] ^= (byte)(CmacSubKey2[i]);
                    }
                }
                else
                {
                    /* Block complete -> no padding + key 1 */

                    if (desfire.logCrypto)
                    {
                        logger.debug("      Key1 {0}", BinConvert.ToHex(CmacSubKey1));
                        logger.debug("      XOR  {0}", BinConvert.ToHex(buffer));
                    }

                    /* XOR the last eight bytes with CMAC_SubKey1 */
                    length = actual_length - BlockSize;
                    for (int i = 0; i < BlockSize; i++)
                    {
                        buffer[length + i] ^= (byte)(CmacSubKey1[i]);
                    }
                }

                CipherSend(ref buffer);

                // Save the current init vector, which is the last cipher block of the cryptogram:
                Array.ConstrainedCopy(buffer, (actual_length - BlockSize), InitVector, 0, BlockSize);

                byte[] cmac = new byte[CmacSize];

                // The mac is the first half of the init vector:
                Array.ConstrainedCopy(InitVector, 0, cmac, 0, CmacSize);

                if (desfire.logCrypto)
                {
                    logger.debug("      CMAC {0}", BinConvert.ToHex(cmac));
                }

                return cmac;
            }

            public override void CipherRecv(ref byte[] data)
            {
                if (desfire.logCrypto)
                {
                    logger.debug("CipherRecv {0}", BinConvert.ToHex(data));
                    logger.debug("       Key {0:X06}", cipherCore.GetKvcDw());
                    logger.debug("        IV {0}", BinConvert.ToHex(InitVector));
                }

                byte[] buffer = new byte[BlockSize];

                int block_count = data.Length / BlockSize;
                for (int i = 0; i < block_count; i++)
                {
                    //1.
                    Array.ConstrainedCopy(data, (BlockSize * i), buffer, 0, BlockSize);   // B  <- P


                    //2.
                    byte[] tmp = cipherCore.Decrypt(buffer);
                    Array.ConstrainedCopy(tmp, 0, data, (BlockSize * i), BlockSize);

                    //3. 
                    for (int j = 0; j < BlockSize; j++)
                        data[BlockSize * i + j] ^= (byte)(InitVector[j]);  // P  <- P XOR IV           

                    //4. 
                    Array.ConstrainedCopy(buffer, 0, InitVector, 0, BlockSize);// IV <- B  
                }

                if (desfire.logCrypto)
                {
                    logger.debug("           {0}", BinConvert.ToHex(data));
                    logger.debug("   Next IV {0}", BinConvert.ToHex(InitVector));
                }
            }

            public override void CipherSend(ref byte[] data)
            {
                if (desfire.logCrypto)
                {
                    logger.debug("CipherSend {0}", BinConvert.ToHex(data));
                    logger.debug("       Key {0:X06}", cipherCore.GetKvcDw());
                    logger.debug("        IV {0}", BinConvert.ToHex(InitVector));
                }

                int block_count = data.Length / BlockSize;

                for (int i = 0; i < block_count; i++)
                {
                    /* Keep last IV */

                    //1.
                    for (int j = 0; j < BlockSize; j++)
                        data[BlockSize * i + j] ^= (byte)(InitVector[j]);  // P  <- P XOR IV

                    //2.
                    byte[] tmp = new byte[BlockSize];
                    Array.ConstrainedCopy(data, (BlockSize * i), tmp, 0, BlockSize);
                    InitVector = cipherCore.Encrypt(tmp);

                    //3.
                    Array.ConstrainedCopy(InitVector, 0, data, (BlockSize * i), BlockSize);// P  <- IV
                }

                if (desfire.logCrypto)
                {
                    logger.debug("           {0}", BinConvert.ToHex(data));
                    logger.debug("   Next IV {0}", BinConvert.ToHex(InitVector));
                }
            }
        }

        [Serializable]
        public class DesfireCryptoContextEV1TDes : DesfireCryptoContextEV1, ISerializable
        {
            const byte RB_XOR_VALUE = 0x1B;

            int DesKeyCount;
            int RndSize;

            /* Upon deserialization, we need to reconstruct the cryptographic context */
            protected DesfireCryptoContextEV1TDes(SerializationInfo info, StreamingContext context) : base(info, context)
            {
                cipherCore = TDES.Create(SessionKey);
                SessionKVC = cipherCore.GetKvcDw();
            }

            private void SetAuthType(byte[] key)
            {
                bool k3_eq_k1 = true;
                bool k2_eq_k1 = true;

                if (key.Length == 24)
                    for (int i = 0; i < 8; i++)
                        if (key[i] != key[i + 16])
                            k3_eq_k1 = false;
                if ((key.Length == 16) || (key.Length == 24))
                    for (int i = 0; i < 8; i++)
                        if (key[i] != key[i + 8])
                            k2_eq_k1 = false;

                if (k3_eq_k1 && k2_eq_k1)
                {
                    DesKeyCount = 1;
                    RndSize = 8;
                    logger.debug("\tKey is simple DES");
                    AuthType = EAuthType.DES_EV1;
                }
                else if (k3_eq_k1)
                {
                    DesKeyCount = 2;
                    RndSize = 8;
                    logger.debug("\tKey is 3DES2K");
                    AuthType = EAuthType.TDES2K_EV1;
                }
                else
                {
                    DesKeyCount = 3;
                    RndSize = 16;
                    logger.debug("\tKey is 3DES3K");
                    AuthType = EAuthType.TDES3K_EV1;
                }
            }

            public DesfireCryptoContextEV1TDes(Desfire desfire, byte[] KeyValue) : base(desfire, EAuthType.NONE, RB_XOR_VALUE, 8, 8)
            {
                if (KeyValue == null)
                    throw new NullReferenceException(nameof(KeyValue));
                if ((KeyValue.Length != 8) && (KeyValue.Length != 16) && (KeyValue.Length != 24))
                    throw new ArgumentOutOfRangeException(nameof(KeyValue));

                KeySize = KeyValue.Length;
                SetAuthType(KeyValue);
                AuthKeyValue = BinUtils.Copy(KeyValue);
                SessionKey = BinUtils.Copy(KeyValue);
                InitVector = new byte[8];

                if (desfire.logSecrets)
                    logger.trace("Loading auth key {0}", BinConvert.ToHex(KeyValue));

                cipherCore = TDES.Create(KeyValue);
                AuthKVC = cipherCore.GetKvcDw();

                if (desfire.logCrypto)
                    logger.trace("Auth key: KVC={0:X06} Version={1:X02}", AuthKVC, (cipherCore as TDES).GetVersion());
            }

            public EAuthType ExportSessionType()
            {
                if (RndSize == 16)
                    return EAuthType.TDES3K_EV1;

                switch (DesKeyCount)
                {
                    case 1:
                        return EAuthType.DES_EV1;
                    case 2:
                        return EAuthType.TDES2K_EV1;
                    case 3:
                        return EAuthType.TDES3K_EV1;
                    default:
                        return EAuthType.NONE;
                }
            }

            public void ImportSessionKey(byte[] SessionKey)
            {
                this.SessionKey = BinUtils.Copy(SessionKey);
                SetAuthType(SessionKey);
                ResetInitVector();
                InitCmac();
                ResetInitVector();
            }

            public long ProcessAuth1(byte[] PiccChal1, out byte[] PcdChal1)
            {
                if (PiccChal1 == null)
                    throw new ArgumentNullException(nameof(PiccChal1));

                /* OK, we received the 8 bytes Ek( RndB ) from the PICC.
                   Decipher Ek( RndB ) to get RndB in ctx->xfer_buffer.
                   Note that the status code has already been extracted from the queue. */

                logger.debug("\tEk(RndPicc)={0}", BinConvert.ToHex(PiccChal1));

                if (PiccChal1.Length == 8)
                {
                    RndSize = 8;
                }
                else if (PiccChal1.Length == 16)
                {
                    RndSize = 16;
                }
                else
                {
                    PcdChal1 = null;
                    return LibraryError(DesfireLibraryError.WrongLength);
                }

                CipherRecv(ref PiccChal1);

                AuthRndPicc = PiccChal1;

                logger.debug("\tRndPicc={0}", BinConvert.ToHex(AuthRndPicc));

                AuthRndPcd = randomGenerator.Get(RndSize);
                logger.debug("\tRndPcd ={0}", BinConvert.ToHex(AuthRndPcd));

                PcdChal1 = new byte[2 * RndSize];

                /* Append RndA and RndB' ( RndB' is generated by rotating RndB one byte to the left )
                   after the status byte. */
                Array.ConstrainedCopy(AuthRndPcd, 0, PcdChal1, 0, RndSize);
                Array.ConstrainedCopy(AuthRndPicc, 1, PcdChal1, RndSize, RndSize - 1);
                Array.ConstrainedCopy(AuthRndPicc, 0, PcdChal1, 2 * RndSize - 1, 1);

                logger.debug("\tRndPcd || RndPicc'={0}", BinConvert.ToHex(PcdChal1));

                /* Apply the DES send operation to the 16 argument bytes before sending the second frame
                   to the PICC ( do not include the status byte in the DES operation ). */
                CipherSend(ref PcdChal1);
                logger.debug("\tEk(RndPcd || RndPicc')={0}", BinConvert.ToHex(PcdChal1));

                return Success;
            }

            public long ProcessAuth2(byte[] PiccChal2)
            {
                if (PiccChal2 == null)
                    throw new ArgumentNullException(nameof(PiccChal2));

                logger.debug("\tEk(RndPcd')={0}", BinConvert.ToHex(PiccChal2));

                if (PiccChal2.Length != RndSize)
                    return LibraryError(DesfireLibraryError.WrongLength);

                /* We should now have Ek( RndA' ) in our buffer.
                   RndA' was made from RndA by the PICC by rotating the string one byte to the left.
                   Decipher Ek( RndA' ) to get RndA' in ctx->xfer_buffer. */

                CipherRecv(ref PiccChal2);

                logger.debug("\tRndPcd'={0}", BinConvert.ToHex(PiccChal2));

                /* Now we have RndA' in our buffer.
                   We have to check whether it matches our local copy of RndA.
                   If one of the subsequent comparisons fails, we do not trust the PICC and therefore
                   abort the authentication procedure ( no session key is generated ). */

                /* First compare the bytes 1 to 7 of RndA with the first 7 bytes in the queue. */
                for (int i = 0; i < RndSize - 1; i++)
                    if (PiccChal2[i] != AuthRndPcd[1 + i])
                        return LibraryError(DesfireLibraryError.WrongResponseToChallenge);

                /* Then compare the leftmost byte of RndA with the last byte in the queue. */
                if (PiccChal2[RndSize - 1] != AuthRndPcd[0])
                    return LibraryError(DesfireLibraryError.WrongResponseToChallenge);

                /* The actual authentication has succeeded.
                   Finally we have to generate the session key from both random numbers RndA and RndB.
                   The first half of the session key is the concatenation of RndA[0-3] + RndB[0-3]. */
                /* If the original key passed through KeyValue is a TripleDES key, the session
                   key must also be a TripleDES key. */
                if (RndSize == 16)
                {
                    /* 3DES3K, for sure */
                    SessionKey = new byte[24];
                    Array.ConstrainedCopy(AuthRndPcd, 0, SessionKey, 0, 4);
                    Array.ConstrainedCopy(AuthRndPicc, 0, SessionKey, 4, 4);
                    Array.ConstrainedCopy(AuthRndPcd, 6, SessionKey, 8, 4);
                    Array.ConstrainedCopy(AuthRndPicc, 6, SessionKey, 12, 4);
                    Array.ConstrainedCopy(AuthRndPcd, 12, SessionKey, 16, 4);
                    Array.ConstrainedCopy(AuthRndPicc, 12, SessionKey, 20, 4);
                    logger.debug("Session key (3DES3K, ISO)={0}", BinConvert.ToHex(SessionKey));
                }
                else if (DesKeyCount == 1)
                {
                    /* DES */
                    SessionKey = new byte[16];
                    Array.ConstrainedCopy(AuthRndPcd, 0, SessionKey, 0, 4);
                    Array.ConstrainedCopy(AuthRndPicc, 0, SessionKey, 4, 4);
                    Array.ConstrainedCopy(SessionKey, 0, SessionKey, 8, 8);
                    logger.debug("Session key (DES, ISO)={0}", BinConvert.ToHex(SessionKey));
                }
                else
                {
                    /* 3DES2K */
                    SessionKey = new byte[16];
                    Array.ConstrainedCopy(AuthRndPcd, 0, SessionKey, 0, 4);
                    Array.ConstrainedCopy(AuthRndPicc, 0, SessionKey, 4, 4);
                    Array.ConstrainedCopy(AuthRndPcd, 4, SessionKey, 8, 4);
                    Array.ConstrainedCopy(AuthRndPicc, 4, SessionKey, 12, 4);
                    logger.debug("Session key (3DES, ISO)={0}", BinConvert.ToHex(SessionKey));
                }

                cipherCore = TDES.Create(SessionKey);
                SessionKVC = cipherCore.GetKvcDw();

                if (desfire.logCrypto)
                    logger.trace("Session key: KVC={0:X06}", SessionKVC);

                /* Cleanup init vector */
                ResetInitVector();

                /* Initialize the CMAC */
                InitCmac();

                /* Cleanup init vector, again */
                ResetInitVector();

                return Success;
            }
        }

        [Serializable]
        public class DesfireCryptoContextEV1Aes : DesfireCryptoContextEV1, ISerializable
        {
            const byte RB_XOR_VALUE = 0x87;

            /* Upon deserialization, we need to reconstruct the cryptographic context */
            protected DesfireCryptoContextEV1Aes(SerializationInfo info, StreamingContext context) : base(info, context)
            {
                cipherCore = AES.Create(SessionKey);
                SessionKVC = cipherCore.GetKvcDw();
            }

            public DesfireCryptoContextEV1Aes(Desfire desfire, byte[] KeyValue) : base(desfire, EAuthType.AES128_EV1, RB_XOR_VALUE, 16, 8)
            {
                if (KeyValue == null)
                    throw new NullReferenceException(nameof(KeyValue));
                if ((KeyValue.Length != 16))
                    throw new ArgumentOutOfRangeException(nameof(KeyValue));
                KeySize = KeyValue.Length;
                AuthKeyValue = BinUtils.Copy(KeyValue);
                SessionKey = BinUtils.Copy(KeyValue);
                InitVector = new byte[16];

                if (desfire.logSecrets)
                    logger.trace("Loading auth key {0}", BinConvert.ToHex(KeyValue));

                cipherCore = AES.Create(KeyValue);
                AuthKVC = cipherCore.GetKvcDw();

                if (desfire.logCrypto)
                    logger.trace("Auth key: KVC={0:X06}", AuthKVC);
            }

            public EAuthType ExportSessionType()
            {
                return EAuthType.AES128_EV1;
            }

            public void ImportSessionKey(byte[] SessionKey)
            {
                this.SessionKey = BinUtils.Copy(SessionKey);
                ResetInitVector();
                InitCmac();
                ResetInitVector();
            }

            public void ImportInitVector(byte[] InitVector)
            {
                this.InitVector = BinUtils.Copy(InitVector);
            }

            public long ProcessAuth1(byte[] PiccChal1, out byte[] PcdChal1)
            {
                if (PiccChal1 == null)
                    throw new ArgumentNullException(nameof(PiccChal1));

                /* OK, we received the 16 bytes Ek( RndB ) from the PICC.
                   Decipher Ek( RndB ) to get RndB in ctx->xfer_buffer.
                   Note that the status code has already been extracted from the queue. */

                logger.debug("\tEk(RndPicc)={0}", BinConvert.ToHex(PiccChal1));

                if (PiccChal1.Length != 16)
                {
                    PcdChal1 = null;
                    return LibraryError(DesfireLibraryError.WrongLength);
                }

                CipherRecv(ref PiccChal1);

                AuthRndPicc = PiccChal1;

                logger.debug("\tRndPicc={0}", BinConvert.ToHex(AuthRndPicc));

                AuthRndPcd = randomGenerator.Get(16);
                logger.debug("\tRndPcd ={0}", BinConvert.ToHex(AuthRndPcd));

                PcdChal1 = new byte[32];

                /* Append RndA and RndB' ( RndB' is generated by rotating RndB one byte to the left )
                   after the status byte. */
                Array.ConstrainedCopy(AuthRndPcd, 0, PcdChal1, 0, 16);
                Array.ConstrainedCopy(AuthRndPicc, 1, PcdChal1, 16, 16 - 1);
                Array.ConstrainedCopy(AuthRndPicc, 0, PcdChal1, 2 * 16 - 1, 1);

                logger.debug("\tRndPcd || RndPicc'={0}", BinConvert.ToHex(PcdChal1));

                /* Apply the AES send operation to the 16 argument bytes before sending the second frame
                   to the PICC ( do not include the status byte in the DES operation ). */
                CipherSend(ref PcdChal1);
                logger.debug("\tEk(RndPcd || RndPicc')={0}", BinConvert.ToHex(PcdChal1));

                return Success;
            }

            public long ProcessAuth2(byte[] PiccChal2)
            {
                if (PiccChal2 == null)
                    throw new ArgumentNullException(nameof(PiccChal2));

                logger.debug("\tEk(RndPcd')={0}", BinConvert.ToHex(PiccChal2));

                if (PiccChal2.Length != 16)
                    return LibraryError(DesfireLibraryError.WrongLength);

                /* We should now have Ek( RndA' ) in our buffer.
                   RndA' was made from RndA by the PICC by rotating the string one byte to the left.
                   Decipher Ek( RndA' ) to get RndA' in ctx->xfer_buffer. */

                CipherRecv(ref PiccChal2);

                logger.debug("\tRndPcd'={0}", BinConvert.ToHex(PiccChal2));

                /* Now we have RndA' in our buffer.
                   We have to check whether it matches our local copy of RndA.
                   If one of the subsequent comparisons fails, we do not trust the PICC and therefore
                   abort the authentication procedure ( no session key is generated ). */

                /* First compare the bytes 1 to 7 of RndA with the first 7 bytes in the queue. */
                for (int i = 0; i < 16 - 1; i++)
                    if (PiccChal2[i] != AuthRndPcd[1 + i])
                        return LibraryError(DesfireLibraryError.WrongResponseToChallenge);

                /* Then compare the leftmost byte of RndA with the last byte in the queue. */
                if (PiccChal2[16 - 1] != AuthRndPcd[0])
                    return LibraryError(DesfireLibraryError.WrongResponseToChallenge);

                /* The actual authentication has succeeded.
                   Finally we have to generate the session key from both random numbers RndA and RndB.
                   The first half of the session key is the concatenation of RndA[0-3] + RndB[0-3]. */
                /* If the original key passed through KeyValue is a TripleDES key, the session
                   key must also be a TripleDES key. */
                SessionKey = new byte[16];
                Array.ConstrainedCopy(AuthRndPcd, 0, SessionKey, 0, 4);
                Array.ConstrainedCopy(AuthRndPicc, 0, SessionKey, 4, 4);
                Array.ConstrainedCopy(AuthRndPcd, 12, SessionKey, 8, 4);
                Array.ConstrainedCopy(AuthRndPicc, 12, SessionKey, 12, 4);
                logger.debug("Session key (AES)={0}", BinConvert.ToHex(SessionKey));

                cipherCore = AES.Create(SessionKey);
                SessionKVC = cipherCore.GetKvcDw();

                if (desfire.logCrypto)
                    logger.trace("Session key: KVC={0:X06}", SessionKVC);

                /* Cleanup init vector */
                ResetInitVector();

                /* Initialize the CMAC */
                InitCmac();

                /* Cleanup init vector, again */
                ResetInitVector();

                return Success;
            }
        }
    }
}
