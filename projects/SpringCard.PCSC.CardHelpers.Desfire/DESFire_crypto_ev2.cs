/*
 * Created by SharpDevelop.
 * User: Jerome Izaac
 * Date: 12/09/2017
 * Time: 14:22
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using SpringCard.LibCs;
using SpringCard.LibCs.Crypto;
using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.Serialization;
using System.Security.Cryptography;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of DESFire_mgmt.
    /// </summary>
    public partial class Desfire
    {
        [Serializable]
        public class DesfireCryptoContextEV2 : DesfireCryptoContext, ISerializable
        {
            protected const byte RB_XOR_VALUE = 0x87;

            [NonSerialized]
            protected byte[] AuthKeyValue;
            [NonSerialized]
            public byte[] AuthRndPcd; // TODO
            [NonSerialized]
            public byte[] AuthRndPicc; // TODO

            [NonSerialized]
            AES aesEnc;

            private byte[] _SessionEncKey;
            protected byte[] SessionEncKey
            {
                get
                {
                    return _SessionEncKey;
                }
                set
                {
                    _SessionEncKey = value;
                    aesEnc = AES.Create(_SessionEncKey);
                    SessionEncKVC = aesEnc.GetKvcDw();
                }
            }

            [NonSerialized]
            AES aesCmac;

            private byte[] _SessionCmacKey;
            protected byte[] SessionCmacKey
            {
                get
                {
                    return _SessionCmacKey;
                }
                set
                {
                    _SessionCmacKey = value;
                    aesCmac = AES.Create(_SessionCmacKey);
                    SessionCmacKVC = aesCmac.GetKvcDw();
                }
            }

            protected byte[] CmacSubKey1;
            protected byte[] CmacSubKey2;
            protected byte[] InitVector = new byte[16];

            public uint AuthKVC { get; private set; }
            public uint SessionEncKVC { get; private set; }
            public uint SessionCmacKVC { get; private set; }

            public byte[] TransactionIdentifier { get; protected set; }
            public ushort TransactionCounter { get; protected set; }


            /* Serialization */
            public override void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                base.GetObjectData(info, context);
                info.AddValue("AuthKVC", BinConvert.ToHex(AuthKVC));
                info.AddValue("SessionEncKey", BinConvert.ToHex(SessionEncKey));
                info.AddValue("SessionCmacKey", BinConvert.ToHex(SessionCmacKey));
                info.AddValue("CmacSubKey1", BinConvert.ToHex(CmacSubKey1));
                info.AddValue("CmacSubKey2", BinConvert.ToHex(CmacSubKey2));
                info.AddValue("InitVector", BinConvert.ToHex(InitVector));
                info.AddValue("TransactionIdentifier", BinConvert.ToHex(TransactionIdentifier));
                info.AddValue("TransactionCounter", BinConvert.ToHex(TransactionCounter));
            }

            /* Deserialization */
            protected DesfireCryptoContextEV2(SerializationInfo info, StreamingContext context) : base(info, context)
            {
                SessionEncKey = BinConvert.HexToBytes(info.GetString("SessionEncKey")); /* Restore the context and the KVC automatically */
                SessionCmacKey = BinConvert.HexToBytes(info.GetString("SessionCmacKey")); /* Restore the context and the KVC automatically */
                CmacSubKey1 = BinConvert.HexToBytes(info.GetString("CmacSubKey1"));
                CmacSubKey2 = BinConvert.HexToBytes(info.GetString("CmacSubKey2"));
                InitVector = BinConvert.HexToBytes(info.GetString("InitVector"));
                TransactionIdentifier = BinConvert.HexToBytes(info.GetString("TransactionIdentifier"));
                TransactionCounter = BinConvert.HexToWord(info.GetString("TransactionCounter"));
            }

            protected void ResetInitVector()
            {
                for (int i = 0; i < 16; i++)
                    InitVector[i] = 0;
            }

            public DesfireCryptoContextEV2(Desfire desfire, byte[] KeyValue) : base(desfire, EAuthType.NONE, EPaddMode.Mark, 16, 8)
            {
                if (KeyValue == null)
                    throw new NullReferenceException(nameof(KeyValue));
                if ((KeyValue.Length != 16) && (KeyValue.Length != 32))
                    throw new ArgumentOutOfRangeException(nameof(KeyValue));
                KeySize = KeyValue.Length;

                if (KeySize == 16) AuthType = EAuthType.AES128_EV2; else
                if (KeySize == 32) AuthType = EAuthType.AES256_EV2;
                if (desfire.logCrypto && desfire.logSecrets)
                    logger.debug("EV2.AuthKey={0} ({1})", BinConvert.ToHex(KeyValue), KeySize);
                AuthKeyValue = KeyValue;
                SessionEncKey = KeyValue;
                AuthKVC = SessionEncKVC;
                SessionCmacKey = KeyValue;
                InitCmac();
            }

            public DesfireCryptoContextEV2(Desfire desfire, byte[] EncKeyValue, byte[] CmacKeyValue) : base(desfire, EAuthType.AES128_EV2, EPaddMode.Mark, 16, 8)
            {
                if (EncKeyValue == null)
                    throw new NullReferenceException(nameof(EncKeyValue));
                if ((EncKeyValue.Length != 16) && (EncKeyValue.Length != 32))
                    throw new ArgumentOutOfRangeException(nameof(EncKeyValue));
                if (CmacKeyValue == null)
                    throw new NullReferenceException(nameof(CmacKeyValue));
                if ((CmacKeyValue.Length != 16) && (CmacKeyValue.Length != 32))
                    throw new ArgumentOutOfRangeException(nameof(CmacKeyValue));
                KeySize = EncKeyValue.Length;
                SessionEncKey = EncKeyValue;
                SessionCmacKey = CmacKeyValue;
                InitCmac();
            }

            protected DesfireCryptoContextEV2(Desfire desfire, EAuthType AuthType) : base(desfire, AuthType, EPaddMode.Mark, 16, 8)
            {
                KeySize = 16;
            }

            public EAuthType ExportSessionType()
            {
                return EAuthType.AES128_EV2;
            }

            internal void ExportSessionKeys(out byte[] EncKeyValue, out byte[] CmacKeyValue)
            {
                EncKeyValue = this.SessionEncKey;
                CmacKeyValue = this.SessionCmacKey;
            }

            internal void ImportSessionKeys(byte[] EncKeyValue, byte[] CmacKeyValue)
            {
                if (EncKeyValue == null)
                    throw new NullReferenceException(nameof(EncKeyValue));
                if ((EncKeyValue.Length != 16) && (EncKeyValue.Length != 32))
                    throw new ArgumentOutOfRangeException(nameof(EncKeyValue));
                if (CmacKeyValue == null)
                    throw new NullReferenceException(nameof(CmacKeyValue));
                if ((CmacKeyValue.Length != 16) && (CmacKeyValue.Length != 32))
                    throw new ArgumentOutOfRangeException(nameof(CmacKeyValue));
                SessionEncKey = EncKeyValue;
                SessionCmacKey = CmacKeyValue;
                InitCmac();
            }

            public void ImportInitVector(byte[] InitVector)
            {
                this.InitVector = BinUtils.Copy(InitVector);
            }

            internal void ExportTransaction(out byte[] Identifier)
            {
                ExportTransaction(out Identifier, out ushort dummy);
            }

            internal void ExportTransaction(out byte[] Identifier, out ushort Counter)
            {
                Identifier = BinUtils.Copy(TransactionIdentifier);
                Counter = TransactionCounter;
            }

            internal void ImportTransaction(byte[] Identifier)
            {
                ImportTransaction(Identifier, 0);
            }

            internal void ImportTransaction(byte[] Identifier, ushort Counter)
            {
                TransactionIdentifier = BinUtils.Copy(Identifier);
                TransactionCounter = Counter;
            }

            internal void ImportTransaction(DesfireCryptoContextEV2 EarlierContext)
            {
                TransactionIdentifier = BinUtils.Copy(EarlierContext.TransactionIdentifier);
                TransactionCounter = EarlierContext.TransactionCounter;
            }

            public void IncrementTransactionCounter()
            {
                TransactionCounter++;
            }

            public void DecrementTransactionCounter()
            {
                TransactionCounter--;
            }

            protected void InitCmac()
            {
                byte bMSB;
                int t, i;

                ResetInitVector();

                if (desfire.logCrypto)
                    logger.debug("EV2.InitCmac ({0:X02}, {1})", RB_XOR_VALUE, BinConvert.ToHex(SessionCmacKey));

                CmacSubKey1 = new byte[BlockSize];
                CmacSubKey2 = new byte[BlockSize];

                // Generate the padding bytes for O-MAC by enciphering a zero block
                // with the actual session key:
                for (i = 0; i < CmacSubKey1.Length; i++)
                    CmacSubKey1[i] = 0;

                if (desfire.logCrypto)
                    logger.debug("InitCmac 0 {0}", BinConvert.ToHex(CmacSubKey1));

                t = BlockSize;

                CipherSendEx(aesCmac, true, ref CmacSubKey1);

                if (desfire.logCrypto)
                    logger.debug("InitCmac 1 {0}", BinConvert.ToHex(CmacSubKey1));

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
                    CmacSubKey1[BlockSize - 1] ^= RB_XOR_VALUE;
                }

                if (desfire.logCrypto)
                    logger.debug("   -> Key1 {0}", BinConvert.ToHex(CmacSubKey1));

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
                    CmacSubKey2[BlockSize - 1] ^= RB_XOR_VALUE;
                }

                if (desfire.logCrypto)
                    logger.debug("   -> Key2 {0}", BinConvert.ToHex(CmacSubKey2));

                ResetInitVector();
            }

            void GenerateSessionKeys128(byte[] RndA, byte[] RndB)
            {
                /*SV1 = 0xA5 || 0x5A || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15..14] || (RndA[13..8] XOR RndB[15..10])|| RndB[9..0] || RndA[7..0] */
                byte[] SV1 = new byte[32];
                byte[] SV2 = new byte[32];
                byte[] rnda = new byte[6];
                byte[] rndb = new byte[6];

                Array.ConstrainedCopy(RndA, 2, rnda, 0, 6);
                Array.ConstrainedCopy(RndB, 0, rndb, 0, 6);

                for (int j = 0; j < 6; j++)
                    rndb[j] ^= rnda[j];

                /* SV1 = 0xA5 || 0x5A || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15..14] || (RndA[13..8] XOR RndB[15..10])|| RndB[9..0] || RndA[7..0] */
                SV1[0] = 0xA5; SV1[1] = 0x5A; SV1[2] = 0x00; SV1[3] = 0x01; SV1[4] = 0x00; SV1[5] = 0x80;

                /* RndA[15..14] */
                Array.ConstrainedCopy(RndA, 0, SV1, 6, 2);
                /* (RndA[13..8] XOR RndB[15..10]) */
                Array.ConstrainedCopy(rndb, 0, SV1, 8, 6);
                /* RndB[9..0] */
                Array.ConstrainedCopy(RndB, 6, SV1, 14, 10);
                /* RndA[7..0] */
                Array.ConstrainedCopy(RndA, 8, SV1, 24, 8);

                /* SV2 = 0x5A || 0xA5 || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15..14] || (RndA[13..8] XOR RndB[15..10])|| RndB[9..0] || RndA[7..0] */
                SV2[0] = 0x5A; SV2[1] = 0xA5; SV2[2] = 0x00; SV2[3] = 0x01; SV2[4] = 0x00; SV2[5] = 0x80;
                Array.ConstrainedCopy(RndA, 0, SV2, 6, 2);
                Array.ConstrainedCopy(rndb, 0, SV2, 8, 6);
                Array.ConstrainedCopy(RndB, 6, SV2, 14, 10);
                Array.ConstrainedCopy(RndA, 8, SV2, 24, 8);

                /* Initialize the CMAC */
                InitCmac();

                /* Calculate the two session keys */
                ComputeCmac(SV2);
                byte[] cmacKey = BinUtils.Copy(InitVector);
                if (desfire.logCrypto && desfire.logSecrets)
                    logger.debug("Session CMAC key (AES128)={0}", BinConvert.ToHex(cmacKey));
                ComputeCmac(SV1);
                byte[] cipherKey = BinUtils.Copy(InitVector);
                if (desfire.logCrypto && desfire.logSecrets)
                    logger.debug("Session Cipher key (AES128)={0}", BinConvert.ToHex(cipherKey));

                /* Remember the keys */
                SessionCmacKey = cmacKey;
                SessionEncKey = cipherKey;

                /* Initialize the CMAC */
                InitCmac();
            }

            void GenerateSessionKeys256(byte[] RndA, byte[] RndB)
            {
                byte[] SV1a = new byte[32];
                byte[] SV1b = new byte[32];
                byte[] SV2a = new byte[32];
                byte[] SV2b = new byte[32];
                byte[] rnda = new byte[6];
                byte[] rndb = new byte[6];

                Array.ConstrainedCopy(RndA, 2, rnda, 0, 6);
                Array.ConstrainedCopy(RndB, 0, rndb, 0, 6);

                for (int j = 0; j < 6; j++)
                    rndb[j] ^= rnda[j];

                /* Build SV1a */
                /* ---------- */

                SV1a[0] = 0xA5; SV1a[1] = 0x5A; SV1a[2] = 0x00; SV1a[3] = 0x01; SV1a[4] = 0x01; SV1a[5] = 0x00;
                Array.ConstrainedCopy(RndA, 0, SV1a, 6, 2);
                Array.ConstrainedCopy(rndb, 0, SV1a, 8, 6);
                Array.ConstrainedCopy(RndB, 6, SV1a, 14, 10);
                Array.ConstrainedCopy(RndA, 8, SV1a, 24, 8);

                /* Build SV1b */
                /* ---------- */

                SV1b[0] = 0xA5; SV1b[1] = 0x5A; SV1b[2] = 0x00; SV1b[3] = 0x02; SV1b[4] = 0x01; SV1b[5] = 0x00;

                Array.ConstrainedCopy(RndA, 0, SV1b, 6, 2);
                Array.ConstrainedCopy(rndb, 0, SV1b, 8, 6);
                Array.ConstrainedCopy(RndB, 6, SV1b, 14, 10);
                Array.ConstrainedCopy(RndA, 8, SV1b, 24, 8);

                /* Build SV2a */
                /* ---------- */

                SV2a[0] = 0x5A; SV2a[1] = 0xA5; SV2a[2] = 0x00; SV2a[3] = 0x01; SV2a[4] = 0x01; SV2a[5] = 0x00;
                Array.ConstrainedCopy(RndA, 0, SV2a, 6, 2);
                Array.ConstrainedCopy(rndb, 0, SV2a, 8, 6);
                Array.ConstrainedCopy(RndB, 6, SV2a, 14, 10);
                Array.ConstrainedCopy(RndA, 8, SV2a, 24, 8);

                /* Build SV2b */
                /* ---------- */

                SV2b[0] = 0x5A; SV2b[1] = 0xA5; SV2b[2] = 0x00; SV2b[3] = 0x02; SV2b[4] = 0x01; SV2b[5] = 0x00;
                Array.ConstrainedCopy(RndA, 0, SV2b, 6, 2);
                Array.ConstrainedCopy(rndb, 0, SV2b, 8, 6);
                Array.ConstrainedCopy(RndB, 6, SV2b, 14, 10);
                Array.ConstrainedCopy(RndA, 8, SV2b, 24, 8);

                /* Calculate the two session keys */
                ComputeCmac(SV2a);
                byte[] cmacKey_a = BinUtils.Copy(InitVector);
                ComputeCmac(SV2b);
                byte[] cmacKey_b = BinUtils.Copy(InitVector);
                byte[] cmacKey = BinUtils.Concat(cmacKey_a, cmacKey_b);
                if (desfire.logCrypto && desfire.logSecrets)
                    logger.debug("Session CMAC key (AES256)={0}", BinConvert.ToHex(cmacKey));

                ComputeCmac(SV1a);
                byte[] cipherKey_a = BinUtils.Copy(InitVector);
                ComputeCmac(SV1b);
                byte[] cipherKey_b = BinUtils.Copy(InitVector);
                byte[] cipherKey = BinUtils.Concat(cipherKey_a, cipherKey_b);
                if (desfire.logCrypto && desfire.logSecrets)
                    logger.debug("Session Cipher key (AES256)={0}", BinConvert.ToHex(cipherKey));

                /* Remember the keys */
                SessionCmacKey = cmacKey;
                SessionEncKey = cipherKey;

                /* Initialize the CMAC */
                InitCmac();
            }

            public override byte[] ComputeCmacSend(byte[] data)
            {
                if (TransactionIdentifier == null)
                    throw new NullReferenceException($"ComputeCmacSend: {nameof(TransactionIdentifier)} not initialized");

                byte[] input = new byte[6 + data.Length];
                input[0] = data[0];
                input[1] = (byte)(TransactionCounter % 0x0100);
                input[2] = (byte)(TransactionCounter / 0x0100);
                Array.ConstrainedCopy(TransactionIdentifier, 0, input, 3, 4);
                Array.ConstrainedCopy(data, 1, input, 7, data.Length - 1);
                IncrementTransactionCounter();
                return ComputeCmac(input, (uint)(TransactionCounter - 1));
            }

            public override byte[] ComputeCmacRecv(byte[] data)
            {
                if (TransactionIdentifier == null)
                    throw new NullReferenceException($"ComputeCmacSend: {nameof(TransactionIdentifier)} not initialized");

                byte[] input = new byte[6 + data.Length];
                input[0] = data[0];
                input[1] = (byte)(TransactionCounter % 0x0100);
                input[2] = (byte)(TransactionCounter / 0x0100);
                Array.ConstrainedCopy(TransactionIdentifier, 0, input, 3, 4);
                Array.ConstrainedCopy(data, 1, input, 7, data.Length - 1);
                return ComputeCmac(input, TransactionCounter);
            }

            public override byte[] ComputeCmac(byte[] data)
            {
                return ComputeCmac(data, 0xFFFFFFFF);
            }

            private byte[] ComputeCmac(byte[] data, uint counterValue)
            {
                if (desfire.logCrypto)
                {
                    logger.debug("  CalcCmac {0}", BinConvert.ToHex(data));
                }

                // First we enlarge eNumOfBytes to a multiple of the cipher block size for allocating
                // memory of the intermediate buffer. Zero padding will be done by the DF8Encrypt function.
                // If we are ISO-authenticated, we have to do the spetial padding for the O-MAC:
                int data_length = data.Length;
                int actual_length = data_length;
                while ((actual_length % BlockSize) != 0)
                    actual_length++;

                byte[] buffer = new byte[actual_length];
                Array.ConstrainedCopy(data, 0, buffer, 0, (data_length));

                int offset = actual_length - BlockSize;

                /* Do the ISO padding and/or XORing */
                if ((data_length % BlockSize) != 0)
                {
                    /* Block incomplete -> padding + key 2 */
                    buffer[data_length++] = 0x80;

                    if (desfire.logCrypto)
                    {
                        logger.debug("           {0}", BinConvert.ToHex(buffer));
                        string s = "";
                        for (int i = 0; i < offset; i+= BlockSize)
                            s += "                                ";
                        logger.debug(" XOR Key 2 {0}{1}", s, BinConvert.ToHex(CmacSubKey2));
                    }

                    /* XOR the last bytes with CMAC_SubKey2 */
                    for (int i = 0; i < BlockSize; i++)
                    {
                        buffer[offset + i] ^= (byte)(CmacSubKey2[i]);
                    }
                }
                else
                {
                    /* Block complete -> no padding + key 1 */
                    if (desfire.logCrypto)
                    {
                        logger.debug("           {0}", BinConvert.ToHex(buffer));
                        string s = "";
                        for (int i = 0; i < offset; i += BlockSize)
                            s += "                                ";
                        logger.debug(" XOR Key 1 {0}{1}", s, BinConvert.ToHex(CmacSubKey1));
                    }

                    /* XOR the last bytes with CMAC_SubKey1 */
                    for (int i = 0; i < BlockSize; i++)
                    {
                        buffer[offset + i] ^= (byte)(CmacSubKey1[i]);
                    }
                }

                if (desfire.logCrypto)
                {
                    logger.debug("           {0}", BinConvert.ToHex(buffer));
                }

                CipherSendEx(aesCmac, true, ref buffer);

                // Save the current init vector, which is the last cipher block of the cryptogram:
                Array.ConstrainedCopy(buffer, (actual_length - BlockSize), InitVector, 0, BlockSize);

                logger.debug("   Next IV {0}", BinConvert.ToHex(InitVector));

                byte[] cmac = new byte[CmacSize];
                for (int i = 0; i < CmacSize; i++)
                    cmac[i] = InitVector[2 * i + 1];

                if (counterValue != 0xFFFFFFFF)
                    logger.debug("   CMAC <- {0} [{1}]", BinConvert.ToHex(cmac), counterValue);
                else
                    logger.debug("   CMAC <- {0}", BinConvert.ToHex(cmac));

                return cmac;
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

                CipherRecvEx(ref PiccChal1, true);

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
                CipherSendEx(ref PcdChal1, true);

                logger.debug("\tEk(RndPcd || RndPicc')={0}", BinConvert.ToHex(PcdChal1));

                return Success;
            }

            public long ProcessAuth2First(byte[] PiccChal2, out byte[] TransactionIdentifier, out byte[] PiccCaps2, out byte[] PcdCaps2_echo)
            {
                TransactionIdentifier = null;
                long status = ProcessAuth2First(PiccChal2, out PiccCaps2, out PcdCaps2_echo);
                if (status == Success)
                    TransactionIdentifier = this.TransactionIdentifier;
                return status;
            }

            public long ProcessAuth2First(byte[] PiccChal2, out byte[] PiccCaps2, out byte[] PcdCaps2_echo)
            {
                if (PiccChal2 == null)
                    throw new ArgumentNullException(nameof(PiccChal2));

                PiccCaps2 = null;
                PcdCaps2_echo = null;
                TransactionIdentifier = null;

                logger.debug("\tEk(TI || RndPcd' || PDcap2 || PCDcap2)={0}", BinConvert.ToHex(PiccChal2));

                if (PiccChal2.Length != 32)
                    return LibraryError(DesfireLibraryError.WrongLength);

                /* We should now have E(Kx, TI || RndA' || PDcap2 || PCDcap2) in our buffer.
                   RndA' was made from RndA by the PICC by rotating the string one byte to the left.
                   Decipher E(Kx, TI || RndA' || PDcap2 || PCDcap2) to get RndA' in xfer_buffer. */
                /* TI : 4 bytes,  RndA' 16 bytes, PDcap2 6 bytes, PCDcap2 6 bytes) */

                CipherRecvEx(ref PiccChal2, true);

                logger.debug("\tTI || RndPcd' || PDcap2 || PCDcap2={0}", BinConvert.ToHex(PiccChal2));

                /* Retrieve the TI */
                TransactionIdentifier = new byte[4];
                Array.ConstrainedCopy(PiccChal2, 0, TransactionIdentifier, 0, 4);
                
                logger.debug("\t\tTI={0}", BinConvert.ToHex(TransactionIdentifier));

                /* Now we have RndA' in our buffer.
                   We have to check whether it matches our local copy of RndA.
                   If one of the subsequent comparisons fails, we do not trust the PICC and therefore
                   abort the authentication procedure ( no session key is generated ). */
                logger.debug("\t\tRndPcd'={0}", BinConvert.ToHex(PiccChal2, 4, 16));
                /* First compare the bytes 1 to 7 of RndA with the first 7 bytes in the queue. */
                for (int i = 0; i < 16 - 1; i++)
                    if (PiccChal2[4 + i] != AuthRndPcd[1 + i])
                        goto wrong_response_to_challenge;

                /* Then compare the leftmost byte of RndA with the last byte in the queue. */
                if (PiccChal2[4 + 16 - 1] != AuthRndPcd[0])
                    goto wrong_response_to_challenge;

                /* Capabilities */
                PiccCaps2 = new byte[6];
                Array.ConstrainedCopy(PiccChal2, 20, PiccCaps2, 0, 6);
                logger.debug("\t\tPDcap2={0}", BinConvert.ToHex(PiccCaps2));
                PcdCaps2_echo = new byte[6];
                Array.ConstrainedCopy(PiccChal2, 26, PcdCaps2_echo, 0, 6);
                logger.debug("\t\tPcdCaps2={0}", BinConvert.ToHex(PcdCaps2_echo));

                /* The actual authentication has succeeded.
                   Finally we have to generate the session key from both random numbers RndA and RndB. */
                switch (KeySize)
                {
                    case 16:
                        GenerateSessionKeys128(AuthRndPcd, AuthRndPicc);
                        break;
                    case 32:
                        GenerateSessionKeys256(AuthRndPcd, AuthRndPicc);
                        break;
                }

                return Success;

            wrong_response_to_challenge:
                logger.trace("\t\tRndPcd'={0}", BinConvert.ToHex(PiccChal2, 4, 16));
                logger.trace("\t\tRndPcd ={0}", BinConvert.ToHex(AuthRndPcd));
                return LibraryError(DesfireLibraryError.WrongResponseToChallenge);
            }

            public long ProcessAuth2NonFirst(byte[] PiccChal2)
            {
                if (PiccChal2 == null)
                    throw new ArgumentNullException(nameof(PiccChal2));

                logger.debug("\tEk(RndPcd')={0}", BinConvert.ToHex(PiccChal2));

                if (PiccChal2.Length != 16)
                    return LibraryError(DesfireLibraryError.WrongLength);

                /* We should now have E(RndA') in our buffer.
                   RndA' was made from RndA by the PICC by rotating the string one byte to the left.
                   Decipher E(RndA') to get RndA' in xfer_buffer. */

                CipherRecvEx(ref PiccChal2, true);

                logger.debug("\tRndPcd'={0}", BinConvert.ToHex(PiccChal2));

                /* Now we have RndA' in our buffer.
                   We have to check whether it matches our local copy of RndA.
                   If one of the subsequent comparisons fails, we do not trust the PICC and therefore
                   abort the authentication procedure ( no session key is generated ). */

                /* First compare the bytes 1 to 7 of RndA with the first 7 bytes in the queue. */
                for (int i = 0; i < 16 - 1; i++)
                    if (PiccChal2[i] != AuthRndPcd[1 + i])
                        goto wrong_response_to_challenge;

                /* Then compare the leftmost byte of RndA with the last byte in the queue. */
                if (PiccChal2[16 - 1] != AuthRndPcd[0])
                    goto wrong_response_to_challenge;

                /* The actual authentication has succeeded.
                   Finally we have to generate the session key from both random numbers RndA and RndB. */
                switch (KeySize)
                {
                    case 16:
                        GenerateSessionKeys128(AuthRndPcd, AuthRndPicc);
                        break;
                    case 32:
                        GenerateSessionKeys256(AuthRndPcd, AuthRndPicc);
                        break;
                }

                return Success;

            wrong_response_to_challenge:
                logger.trace("\t\tRndPcd'={0}", BinConvert.ToHex(PiccChal2));
                logger.trace("\t\tRndPcd ={0}", BinConvert.ToHex(AuthRndPcd));
                return LibraryError(DesfireLibraryError.WrongResponseToChallenge);
            }

            private enum EInitVectorRefreshMode
            {
                Send,
                Recv
            }

            private byte[] MakeInitVector(EInitVectorRefreshMode mode)
            {
                byte[] buffer = new byte[16];

                switch (mode)
                {
                    case EInitVectorRefreshMode.Send:
                        buffer[0] = 0xA5;
                        buffer[1] = 0x5A;
                        break;
                    case EInitVectorRefreshMode.Recv:
                        buffer[0] = 0x5A;
                        buffer[1] = 0xA5;
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(mode));
                }

                for (int i = 2; i < 6; i++)
                    buffer[i] = TransactionIdentifier[i - 2];

                /* CmdCtr LSB first */
                buffer[6] = (byte)(TransactionCounter & 0x00FF);
                buffer[7] = (byte)((TransactionCounter >> 8) & 0x00FF);

                for (int i = 8; i < 16; i++)
                    buffer[i] = 0x00;

                if (desfire.logCrypto)
                {
                    logger.debug("   Make IV {0}", BinConvert.ToHex(buffer));
                    logger.debug("  With Key {0:X06}", aesEnc.GetKvcDw());
                }

                buffer = aesEnc.Encrypt(buffer);

                if (desfire.logCrypto)
                {
                    logger.debug("     IV <- {0}", BinConvert.ToHex(buffer));
                }

                return buffer;
            }


            public override void CipherRecv(ref byte[] data)
            {
                CipherRecvEx(ref data, false);
            }

            public void CipherRecvEx(ref byte[] data, bool blankIV)
            {
                if (desfire.logCrypto)
                {
                    logger.debug("CipherRecv {0}", BinConvert.ToHex(data));
                    logger.debug(" Using Key {0:X06}", aesEnc.GetKvcDw());
                }

                byte[] recv_iv = null;
                if (blankIV)
                {
                    recv_iv = new byte[16];
                }
                else
                {
                    recv_iv = MakeInitVector(EInitVectorRefreshMode.Recv);
                }

                if (desfire.logCrypto)
                {
                    logger.debug("  Using IV {0}", BinConvert.ToHex(recv_iv));
                }

                byte[] buffer = new byte[16];
                byte[] dummy_iv = new byte[16];

                int block_count = data.Length / 16;
                for (int i = 0; i < block_count; i++)
                {
                    //1.
                    Array.ConstrainedCopy(data, (16 * i), buffer, 0, 16);   // B  <- P

                    //2.
                    byte[] tmp = aesEnc.Decrypt(buffer);
                    Array.ConstrainedCopy(tmp, 0, data, (16 * i), 16);

                    //3. 
                    for (int j = 0; j < 16; j++)
                        data[16 * i + j] ^= (byte)(recv_iv[j]);  // P  <- P XOR IV           

                    //4. 
                    Array.ConstrainedCopy(buffer, 0, recv_iv, 0, 16);// IV <- B  
                }

                if (desfire.logCrypto)
                {
                    logger.debug("           {0}", BinConvert.ToHex(data));
                }
            }

            public override void CipherSend(ref byte[] data)
            {
                CipherSendEx(aesEnc, false, ref data);
            }

            public void CipherSendEx(ref byte[] data, bool blankIV)
            {
                CipherSendEx(aesEnc, blankIV, ref data);
            }

            private void CipherSendEx(AES aesCore, bool blankIV, ref byte[] data)
            {
                if (desfire.logCrypto)
                {
                    logger.debug("CipherSend {0}", BinConvert.ToHex(data));
                    logger.debug(" Using Key {0:X06}", aesCore.GetKvcDw());
                }

                byte[] send_iv = null;
                if (blankIV)
                {
                    send_iv = new byte[16];
                }
                else
                {
                    send_iv = MakeInitVector(EInitVectorRefreshMode.Send);
                }

                if (desfire.logCrypto)
                {
                    logger.debug("  Using IV {0}", BinConvert.ToHex(send_iv));
                }

                int block_count = data.Length / 16;
                byte[] dummy_iv = new byte[16];

                /* Keep last IV */
                for (int i = 0; i < block_count; i++)
                {
                    for (int j = 0; j < 16; j++)
                        data[16 * i + j] ^= (byte)(send_iv[j]);  /* P  <- P XOR IV  */

                    //2.
                    byte[] tmp = new byte[16];
                    Array.ConstrainedCopy(data, (16 * i), tmp, 0, 16);
                    send_iv = aesCore.Encrypt(tmp);

                    //3.
                    Array.ConstrainedCopy(send_iv, 0, data, (16 * i), 16);// P  <- IV
                }

                if (desfire.logCrypto)
                {
                    logger.debug("           {0}", BinConvert.ToHex(data));
                }
            }
        }
    }
}
