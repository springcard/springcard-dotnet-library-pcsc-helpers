using SpringCard.LibCs;
using SpringCard.LibCs.Crypto;
using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of DESFire_mgmt.
    /// </summary>
    public partial class Desfire
    {
        /**
         * @class DesfireCryptoContextEV0
         * @brief Implements the cryptographic context for DESFire EV0 cards.
         * 
         * This class provides methods for handling authentication and cryptographic
         * operations (DES/3DES) for DESFire EV0 cards. It supports both single DES
         * and 3DES keys, and manages session keys and cryptographic operations
         * during authentication.
         *
         * @author Johann Dantant et al.
         * \date 17/04/2025
         * @see Desfire
         */
        [Serializable]
        public class DesfireCryptoContextEV0 : DesfireCryptoContext, ISerializable
        {
            [NonSerialized]
            bool AuthSingleDes;
            [NonSerialized]
            byte[] AuthKeyValue;
            [NonSerialized]
            byte[] AuthRndPcd;
            [NonSerialized]
            byte[] AuthRndPicc;

            [NonSerialized]
            TDES cipherCore;

            byte[] SessionKey;

            /* Serialization */
            public override void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                base.GetObjectData(info, context);
                info.AddValue("AuthKVC", BinConvert.ToHex(AuthKVC));
                info.AddValue("SessionKVC", BinConvert.ToHex(SessionKVC));
                info.AddValue("SessionKey", SessionKey);
            }

            /* Deserialization */
            protected DesfireCryptoContextEV0(SerializationInfo info, StreamingContext context) : base(info, context)
            {
                AuthKVC = BinConvert.HexToDword(info.GetString("AuthKVC"));
                SessionKVC = BinConvert.HexToDword(info.GetString("SessionKVC"));
                SessionKey = BinConvert.HexToBytes(info.GetString("SessionKey"));
                cipherCore = TDES.Create(SessionKey);
            }

            /**
             * @brief Constructor for the DESFireCryptoContextEV0 class.
             *
             * Initializes the cryptographic context for DESFire EV0 cards using the
             * provided key. Determines whether the key is single DES or 3DES based
             * on its structure.
             *
             * @param desfire Reference to the parent Desfire object.
             * @param KeyNumber The key number to use for authentication.
             * @param KeyValue The key value (8 or 16 bytes).
             * \exception NullReferenceException Thrown if KeyValue is null.
             * \exception ArgumentOutOfRangeException Thrown if KeyValue length is not 8 or 16 bytes.
             */
            public DesfireCryptoContextEV0(Desfire desfire, byte[] KeyValue) : base(desfire, EAuthType.NONE, EPaddMode.Zeros, 8, 4)
            {
                if (KeyValue == null)
                    throw new NullReferenceException(nameof(KeyValue));
                if ((KeyValue.Length != 8) && (KeyValue.Length != 16))
                    throw new ArgumentOutOfRangeException(nameof(KeyValue));

                AuthSingleDes = true;
                for (int i = 0; i < 8; i++)
                    if ((KeyValue[i] & 0x7F) != (KeyValue[8 + i] & 0x7F))
                        AuthSingleDes = false;

                AuthKeyValue = BinUtils.Copy(KeyValue);
                SessionKey = BinUtils.Copy(KeyValue);

                if (desfire.logSecrets)
                    logger.trace("Loading auth key {0}", BinConvert.ToHex(KeyValue));

                cipherCore = TDES.Create(KeyValue);
                AuthKVC = cipherCore.GetKvcDw();

                if (desfire.logCrypto || desfire.logSecrets)
                    logger.trace("Auth key: KVC={0:X06} Version={1:X02}", AuthKVC, cipherCore.GetVersion());

                if (AuthSingleDes)
                {
                    if (desfire.logCrypto || desfire.logSecrets)
                        logger.trace("\tKey is simple DES");
                    AuthType = EAuthType.DES_EV0;
                    KeySize = 8;
                }
                else
                {
                    if (desfire.logCrypto || desfire.logSecrets)
                        logger.trace("\tKey is 3DES");
                    AuthType = EAuthType.TDES_EV0;
                    KeySize = 16;
                }                
            }

            /**
             * @brief Get the KVC of the authentication key
             */
            public uint AuthKVC { get; private set; }

            /**
             * @brief Get the KVC of the session key
             */
            public uint SessionKVC { get; private set; }

            /**
             * @brief Exports the session key.
             *
             * @param[out] SessionKey The session key (16 bytes).
             */
            public void ExportSessionKey(out byte[] SessionKey)
            {
                SessionKey = BinUtils.Copy(this.SessionKey);
            }

            /**
             * @brief Processes the first step of authentication.
             *
             * Handles the challenge-response mechanism for the first step of
             * authentication. Deciphers the challenge from the card and generates
             * a response.
             *
             * @param PiccChal1 The challenge received from the card (8 bytes).
             * @param[out] PcdChal1 The response to send to the card (16 bytes).
             * @return True if the operation succeeds, false otherwise.
             * \exception ArgumentNullException Thrown if PiccChal1 is null.
             */
            public long ProcessAuth1(byte[] PiccChal1, out byte[] PcdChal1)
            {
                if (PiccChal1 == null)
                    throw new ArgumentNullException(nameof(PiccChal1));

                /* OK, we received the 8 bytes Ek( RndB ) from the PICC.
                   Decipher Ek( RndB ) to get RndB in ctx->xfer_buffer.
                   Note that the status code has already been extracted from the queue. */

                if (desfire.logCrypto || desfire.logSecrets)
                    logger.debug("\tEk(RndPicc)={0}", BinConvert.ToHex(PiccChal1));

                if (PiccChal1.Length != 8)
                {
                    PcdChal1 = null;
                    return LibraryError(DesfireLibraryError.WrongLength);
                }

                CipherRecv(ref PiccChal1);

                AuthRndPicc = PiccChal1;

                if (desfire.logSecrets)
                    logger.debug("\tRndPicc={0}", BinConvert.ToHex(AuthRndPicc));

                AuthRndPcd = randomGenerator.Get(8);

                if (desfire.logSecrets)
                    logger.debug("\tRndPcd ={0}", BinConvert.ToHex(AuthRndPcd));

                PcdChal1 = new byte[16];

                /* Append RndA and RndB' ( RndB' is generated by rotating RndB one byte to the left )
                   after the status byte. */
                Array.ConstrainedCopy(AuthRndPcd, 0, PcdChal1, 0, 8);
                Array.ConstrainedCopy(AuthRndPicc, 1, PcdChal1, 8, 7);
                Array.ConstrainedCopy(AuthRndPicc, 0, PcdChal1, 8 + 7, 1);

                if (desfire.logSecrets)
                    logger.debug("\tRndPcd || RndPicc'={0}", BinConvert.ToHex(PcdChal1));

                /* Apply the DES send operation to the 16 argument bytes before sending the second frame
                   to the PICC ( do not include the status byte in the DES operation ). */
                CipherSend(ref PcdChal1);

                if (desfire.logCrypto || desfire.logSecrets)
                    logger.debug("\tEk(RndPcd || RndPicc')={0}", BinConvert.ToHex(PcdChal1));

                return Success;
            }

            /**
             * @brief Processes the second step of authentication.
             *
             * Handles the challenge-response mechanism for the second step of
             * authentication. Verifies the card's response and generates the
             * session key.
             *
             * @param PiccChal2 The challenge received from the card (8 bytes).
             * @return True if the operation succeeds, false otherwise.
             * \exception ArgumentNullException Thrown if PiccChal2 is null.
             */
            public long ProcessAuth2(byte[] PiccChal2)
            {
                if (PiccChal2 == null)
                    throw new ArgumentNullException(nameof(PiccChal2));

                if (desfire.logCrypto || desfire.logSecrets)
                    logger.debug("\tEk(RndPcd')={0}", BinConvert.ToHex(PiccChal2));

                if (PiccChal2.Length != 8)
                    return LibraryError(DesfireLibraryError.WrongLength);

                /* We should now have Ek( RndA' ) in our buffer.
                   RndA' was made from RndA by the PICC by rotating the string one byte to the left.
                   Decipher Ek( RndA' ) to get RndA' in ctx->xfer_buffer. */

                CipherRecv(ref PiccChal2);

                if (desfire.logSecrets)
                    logger.debug("\tRndPcd'={0}", BinConvert.ToHex(PiccChal2));

                /* Now we have RndA' in our buffer.
                   We have to check whether it matches our local copy of RndA.
                   If one of the subsequent comparisons fails, we do not trust the PICC and therefore
                   abort the authentication procedure ( no session key is generated ). */

                /* First compare the bytes 1 to 7 of RndA with the first 7 bytes in the queue. */
                for (int i = 0; i < 7; i++)
                    if (PiccChal2[i] != AuthRndPcd[1 + i])
                        return LibraryError(DesfireLibraryError.WrongResponseToChallenge);

                /* Then compare the leftmost byte of RndA with the last byte in the queue. */
                if (PiccChal2[7] != AuthRndPcd[0])
                    return LibraryError(DesfireLibraryError.WrongResponseToChallenge);

                /* The actual authentication has succeeded.
                   Finally we have to generate the session key from both random numbers RndA and RndB.
                   The first half of the session key is the concatenation of RndA[0-3] + RndB[0-3]. */
                /* If the original key passed through KeyValue is a TripleDES key, the session
                   key must also be a TripleDES key. */

                if (AuthSingleDes)
                {
                    SessionKey = new byte[16];
                    Array.ConstrainedCopy(AuthRndPcd, 0, SessionKey, 0, 4);
                    Array.ConstrainedCopy(AuthRndPicc, 0, SessionKey, 4, 4);
                    Array.ConstrainedCopy(SessionKey, 0, SessionKey, 8, 8);

                    if (desfire.logSecrets)
                        logger.debug("Session key (DES)={0}", BinConvert.ToHex(SessionKey));
                }
                else
                {
                    SessionKey = new byte[16];
                    Array.ConstrainedCopy(AuthRndPcd, 0, SessionKey, 0, 4);
                    Array.ConstrainedCopy(AuthRndPicc, 0, SessionKey, 4, 4);
                    Array.ConstrainedCopy(AuthRndPcd, 4, SessionKey, 8, 4);
                    Array.ConstrainedCopy(AuthRndPicc, 4, SessionKey, 12, 4);
                    if (desfire.logSecrets)
                        logger.debug("Session key (3DES)={0}", BinConvert.ToHex(SessionKey));
                }

                cipherCore = TDES.Create(SessionKey);
                SessionKVC = cipherCore.GetKvcDw();

                if (desfire.logCrypto || desfire.logSecrets)
                    logger.trace("Session key: KVC={0:X06}", cipherCore.GetKvcDw());

                return Success;
            }

            /**
             * @brief Deciphers data received from the card.
             *
             * Applies the decryption algorithm to the provided data using the
             * session key.
             * Note that for Desfire EV0, the PICC always encrypts and the PCD always decrypts.
             *
             * @param data The data to decipher.
             */
            public override void CipherRecv(ref byte[] data)
            {
                if (desfire.logCrypto)
                {
                    logger.debug("CipherRecv {0}", BinConvert.ToHex(data));
                    logger.debug(" Using key {0:X06}", cipherCore.GetKvcDw());
                }

                byte[] buffer = new byte[8];
                byte[] carry = new byte[8];
                byte[] dummy_iv = new byte[8];

                int block_count = data.Length / 8;
                for (int i = 0; i < block_count; i++)
                {
                    Array.ConstrainedCopy(buffer, 0, carry, 0, 8);      // IV <- B         
                    Array.ConstrainedCopy(data, (8 * i), buffer, 0, 8);   // B  <- P        

                    /* In EV0, the card always encrypt, the PCD always decrypts. */
                    byte[] tmp = cipherCore.Decrypt(buffer);
                    Array.ConstrainedCopy(tmp, 0, data, (8 * i), 8);// P  <- iDES(B)   

                    for (int j = 0; j < 8; j++)
                        data[8 * i + j] ^= (byte)(carry[j]);  // P  <- P XOR IV 
                }

                if (desfire.logCrypto)
                {
                    logger.debug("           {0}", BinConvert.ToHex(data));
                }
            }

            /**
             * @brief Enciphers data to send to the card.
             *
             * Applies the encryption algorithm to the provided data using the
             * session key.
             * Note that for Desfire EV0, the PICC always encrypts and the PCD always decrypts, therefore
             * this CipherSend method is actually an encrypt/encipher operation.
             *
             * @param data The data to encipher.
             */
            public override void CipherSend(ref byte[] data)
            {
                int block_count = data.Length / 8;
                byte[] dummy_iv = new byte[8];
                byte[] carry = new byte[8];

                if (desfire.logCrypto)
                {
                    logger.debug("CipherSend {0}", BinConvert.ToHex(data));
                    logger.debug(" Using key {0:X06}", cipherCore.GetKvcDw());
                }

                for (int i = 0; i < block_count; i++)
                {
                    for (int j = 0; j < 8; j++)
                        data[8 * i + j] ^= (byte)(carry[j]);  /* P  <- P XOR IV  */

                    /* Legacy mode : PICC always encrypts, PCD always decrypts */
                    byte[] tmp = new byte[8];
                    Array.ConstrainedCopy(data, (8 * i), tmp, 0, 8);

                    /* In EV0, the card always encrypt, the PCD always decrypts. */
                    carry = cipherCore.Decrypt(tmp);
                    Array.ConstrainedCopy(carry, 0, data, (8 * i), 8);// P  <- IV
                }

                if (desfire.logCrypto)
                {
                    logger.debug("           {0}", BinConvert.ToHex(data));
                }
            }

            /**
             * @brief Computes the CMAC for outgoing data.
             *
             * @param data The data for which to compute the CMAC.
             * @return A byte array containing the computed CMAC.
             */
            public override byte[] ComputeCmacSend(byte[] data)
            {
                return ComputeCmac(data);
            }

            /**
             * @brief Computes the CMAC for incoming data.
             *
             * @param data The data for which to compute the CMAC.
             * @return A byte array containing the computed CMAC.
             */
            public override byte[] ComputeCmacRecv(byte[] data)
            {
                data = BinUtils.Copy(data, 1, data.Length - 1);
                return ComputeCmac(data);
            }

            public override byte[] ComputeCmac(byte[] data)
            {
                int block_count = data.Length / BlockSize;

                if ((data.Length % BlockSize) != 0)
                {
                    block_count++;
                    data = BinUtils.EnsureSize(data, BlockSize * block_count, BlockSize * block_count, BinUtils.PaddMethod.After);
                }

                byte[] carry = new byte[8];
                byte[] dummy_iv = new byte[8];

                if (desfire.logCrypto)
                {
                    logger.debug("  CalcCmac {0}", BinConvert.ToHex(data));
                    logger.debug(" Using key {0:X06}", cipherCore.GetKvcDw());
                }

                for (int j = 0; j < 8; j++)
                    dummy_iv[j] = 0;

                for (int j = 0; j < 8; j++)/* IV <- 00...00   */
                    carry[j] = 0;

                for (int i = 0; i < block_count; i++)
                {
                    byte[] tmp = new byte[8];
                    Array.ConstrainedCopy(data, (8 * i), tmp, 0, 8);

                    for (int j = 0; j < 8; j++)
                        tmp[j] ^= carry[j];    /* P  <- P XOR IV  */
                    carry = cipherCore.Encrypt(tmp);  /* IV <- DES(P)    */
                }

                if (desfire.logCrypto)
                {
                    logger.debug("           {0}", BinConvert.ToHex(carry));
                }

                return BinUtils.Copy(carry, 0, 4);
            }
        }
    }
}
