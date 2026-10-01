/*
 * Crée par SharpDevelop.
 * Utilisateur: johann
 * Date: 05/01/2012
 * Heure: 12:02
 * 
 * Pour changer ce modèle utiliser Outils | Options | Codage | Editer les en-têtes standards.
 */
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using SpringCard.LibCs;
using SpringCard.LibCs.Crypto;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using Org.BouncyCastle.X509;
using System.Net.Security;

namespace SpringCard.PCSC.CardEmulation
{
    /// <summary>
    /// Description of CardEmulMifareDuoX.
    /// </summary>
    public partial class CardEmulMifareDuoX : CardEmulDesfireEV2
    {
        protected CardEmulMifareDuoX(string name, DesfireApplication rootApp) : base(name, rootApp) {  }
        public CardEmulMifareDuoX() : base("EV4", new DesfireApplication(DesfireApplication.EApplicationKeyType.AES128, 1))
        {
            RootApplication.ECCKeyPairs[0] = DesfireECCKeyPair.Generate(0x0C, 0, 0, 0);
            RootApplication.ECCKeyPairs[1] = DesfireECCKeyPair.Generate(0x0C, 0, 0, 0);
        }

        protected byte ManageKeyPair(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            byte OpCode = 0x46;

            if (CipherContext == null)
            {
                /* No in secure session */
                return AUTHENTICATION_ERROR;
            }

            if (DataIn.Length < 10)
            {
                /* Too short */
                return LENGTH_ERROR;
            }

            byte keyPairNo = DataIn.GetByte(0);
            byte option = DataIn.GetByte(1);
            byte curveId = DataIn.GetByte(2);
            ushort keyPolicy = (ushort) (DataIn.GetByte(3) | (DataIn.GetByte(4) << 8));
            byte writeAccess = DataIn.GetByte(5);
            uint kucLimit = (uint) (DataIn.GetByte(6) | (DataIn.GetByte(7) << 8) | (DataIn.GetByte(8) << 16) | (DataIn.GetByte(9) << 24));
            byte[] incomingData = DataIn.GetBytes(10, DataIn.Length - 10);

            if (CurrentApplication == null)
            {
                logger.debug("ManageKeyPair:No application");
                return PERMISSION_DENIED;
            }

            DesfireECCKeyPair privateKey = null;

            if (CurrentApplication.ECCKeyPairs.ContainsKey(keyPairNo))
            {
                logger.debug("ManageKeyPair:KeyPair {0:X02} already exists", keyPairNo);
                privateKey = CurrentApplication.ECCKeyPairs[keyPairNo];
            }

            byte[] publicKeyValue = null;
            byte commMode = COMM_MODE_CIPHER;

            if (privateKey != null)
                commMode = privateKey.CommMode;

            switch (commMode)
            {
                case COMM_MODE_PLAIN:
                    /* Increment the counter in EV2 */
                    logger.debug("ManageKeyPair:Plain");
                    CipherContext.IncrementCounter();
                    break;
                case COMM_MODE_MACED:
                    logger.debug("ManageKeyPair:Maced");
                    /* EV2 : CMAC on command + header + data */
                    if (!CipherContext.CheckCmac(BinUtils.Concat(OpCode, DataIn.GetBytes())))
                        return INTEGRITY_ERROR;
                    /* Increment the counter in EV2 */
                    CipherContext.IncrementCounter();
                    break;
                case COMM_MODE_CIPHER:
                    logger.debug("ManageKeyPair:Cipher");
                    if (CipherContext == null)
                        return AUTHENTICATION_ERROR;
                    /* EV2 : CMAC on command + header + data */
                    if (!CipherContext.CheckCmac(BinUtils.Concat(OpCode, DataIn.GetBytes())))
                        return INTEGRITY_ERROR;
                    incomingData = BinUtils.Copy(incomingData, 0, incomingData.Length - 8);
                    /* EV2 : Increment the counter before deciphering */
                    CipherContext.IncrementCounter();
                    if ((incomingData != null) && (incomingData.Length > 0))
                    {
                        /* EV2 : Decipher the data */
                        if (!CipherContext.CipherRecv(ref incomingData))
                            return INTEGRITY_ERROR;
                        if (!CipherContext.Unpadd(ref incomingData))
                            return INTEGRITY_ERROR;
                    }
                    break;
            }

            byte[] privateKeyValue = null;
            if ((incomingData != null) && (incomingData.Length > 0))
            {
                privateKeyValue = incomingData;
                logger.debug("ManageKeyPair:Private key {0}", BinConvert.ToHex(privateKeyValue));
            }

            switch (option)
            {
                case 0x00:
                    if (privateKeyValue != null)
                    {
                        logger.debug("ManageKeyPair:Generate:Private key shall not be present");
                        return PARAMETER_ERROR;
                    }
                    privateKey = DesfireECCKeyPair.Generate(curveId, keyPolicy, writeAccess, kucLimit);
                    if (privateKey == null)
                    {
                        logger.debug("ManageKeyPair:Generate:Failed");
                        return PARAMETER_ERROR;
                    }
                    publicKeyValue = privateKey.PublicKeyValue;
                    break;
                case 0x01:
                    if (privateKeyValue == null)
                    {
                        logger.debug("ManageKeyPair:Import:Private key shall be present");
                        return PARAMETER_ERROR;
                    }
                    privateKey = DesfireECCKeyPair.Import(curveId, keyPolicy, writeAccess, kucLimit, privateKeyValue);
                    if (privateKey == null)
                    {
                        logger.debug("ManageKeyPair:Import:Failed");
                        return PARAMETER_ERROR;
                    }
                    break;
                case 0x02:
                    if (privateKey == null)
                    {
                        logger.debug("ManageKeyPair:Update MetaData:No such key");
                        return NO_SUCH_KEY;
                    }
                    if (privateKeyValue != null)
                    {
                        logger.debug("ManageKeyPair:Update MetaData:Private key shall not be present");
                        return PARAMETER_ERROR;
                    }
                    if (!privateKey.UpdateMetaData(curveId, keyPolicy, writeAccess, kucLimit))
                    {
                        logger.debug("ManageKeyPair:Update MetaData:Failed");
                        return PARAMETER_ERROR;
                    }
                    break;
                default:
                    logger.debug("ManageKeyPair:Unsupported option {0:X02}", option);
                    return PARAMETER_ERROR;
            }

            logger.debug("ManageKeyPair:Saving Private Key {0:X02}", keyPairNo);
            if (CurrentApplication != null)
            {
                CurrentApplication.ECCKeyPairs[keyPairNo] = privateKey;
            }
            else
            {
                RootApplication.ECCKeyPairs[keyPairNo] = privateKey;
            }


            byte[] outgoingData;

            if (publicKeyValue != null)
                outgoingData = publicKeyValue;
            else
                outgoingData = new byte[0];

            switch (commMode)
            {
                case COMM_MODE_PLAIN:
                    break;
                case COMM_MODE_MACED:
                    CipherContext.AppendCmac(ref outgoingData);
                    break;
                case COMM_MODE_CIPHER:
                    if (!CipherContext.CipherSend(ref outgoingData))
                        return INTERNAL_ERROR;
                    /* Add a CMAC to the ciphered output */
                    CipherContext.AppendCmac(ref outgoingData);
                    break;
            }

            DataOut = new CardBuffer(outgoingData);

            return OPERATION_OK;
        }

        protected byte ManageCARootKey(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            byte OpCode = 0x48;

            if (CipherContext == null)
            {
                /* No in secure session */
                return AUTHENTICATION_ERROR;
            }

            if (DataIn.Length < 10)
            {
                /* Too short */
                return LENGTH_ERROR;
            }

            byte keyPairNo = DataIn.GetByte(0);
            byte curveId = DataIn.GetByte(1);
            ushort accessRights = (ushort)(DataIn.GetByte(2) | (DataIn.GetByte(3) << 8));
            byte writeAccess = DataIn.GetByte(4);
            byte readAccess = DataIn.GetByte(5);
            byte crlFileId = DataIn.GetByte(6);
            uint crlFileAid = (uint)(DataIn.GetByte(7) | (DataIn.GetByte(8) << 8) | (DataIn.GetByte(9) << 16));
            byte[] incomingData = DataIn.GetBytes(10, DataIn.Length - 10);

            byte[] publicKey = null;
            byte issuerLen = 0;
            byte[] issuer = null;

            if (CurrentApplication == null)
            {
                logger.debug("ManageCARootKey:No application");
                return PERMISSION_DENIED;
            }

            DesfireCARootKey caRootKey = null;
            byte commMode = COMM_MODE_CIPHER;

            switch (commMode)
            {
                case COMM_MODE_PLAIN:
                    /* Increment the counter in EV2 */
                    CipherContext.IncrementCounter();
                    break;
                case COMM_MODE_MACED:
                    /* EV2 : CMAC on command + header + data */
                    if (!CipherContext.CheckCmac(BinUtils.Concat(OpCode, DataIn.GetBytes())))
                        return INTEGRITY_ERROR;
                    /* Increment the counter in EV2 */
                    CipherContext.IncrementCounter();
                    break;
                case COMM_MODE_CIPHER:
                    if (CipherContext == null)
                        return AUTHENTICATION_ERROR;
                    /* EV2 : CMAC on command + header + data */
                    if (!CipherContext.CheckCmac(BinUtils.Concat(OpCode, DataIn.GetBytes())))
                        return INTEGRITY_ERROR;
                    /* EV2 : Increment the counter before deciphering */
                    CipherContext.IncrementCounter();
                    if ((incomingData != null) && (incomingData.Length > 8))
                    {
                        /* EV2 : Decipher the data */
                        incomingData = BinUtils.Copy(incomingData, 0, incomingData.Length - 8);
                        if (!CipherContext.CipherRecv(ref incomingData))
                            return INTEGRITY_ERROR;
                        if (!CipherContext.Unpadd(ref incomingData))
                            return INTEGRITY_ERROR;
                    }
                    break;
            }

            if (incomingData.Length == 65)
            {
                logger.debug("ManageCARootKey:Public key found");
                publicKey = incomingData;
            }
            else if (incomingData.Length > 65)
            {
                issuerLen = incomingData[65];

                if (incomingData.Length != 65 + 1 + issuerLen)
                {
                    /* Wrong length */
                    logger.debug("ManageCARootKey:Length error ({0})", BinConvert.ToHex(incomingData));
                    return LENGTH_ERROR;
                }

                publicKey = BinUtils.Copy(incomingData, 0, 65);
                if (issuerLen > 0)
                    issuer = BinUtils.Copy(incomingData, 65, issuerLen);
            }
            else
            {
                /* Too short */
                logger.debug("ManageCARootKey:Length error ({0})", BinConvert.ToHex(incomingData));
                return LENGTH_ERROR;
            }

            caRootKey = DesfireCARootKey.Create(curveId, accessRights, writeAccess, readAccess, crlFileId, crlFileAid, publicKey, issuer);

            logger.debug("ManageCARootKey:Saving CA Root Key {0:X02}", caRootKey);
            if (CurrentApplication != null)
            {
                CurrentApplication.CARootKeys[keyPairNo] = caRootKey;
            }
            else
            {
                RootApplication.CARootKeys[keyPairNo] = caRootKey;
            }

            byte[] outgoingData = new byte[0];

            switch (commMode)
            {
                case COMM_MODE_PLAIN:
                    break;
                case COMM_MODE_MACED:
                case COMM_MODE_CIPHER:
                    CipherContext.AppendCmac(ref outgoingData);
                    break;
            }

            DataOut = new CardBuffer(outgoingData);

            return OPERATION_OK;
        }

        protected class PendingIsoGeneralAuthenticate : PendingCommand
        {
            public byte SecCARootKeyNo;
            public byte CARootKeyNo;
            public DesfireCARootKey CARootKey = null;
            public DesfireECCKeyPair ECCKeyPair = null;
            public byte AuthMethod;
            public byte Version;
            public byte CertFileId;
            public byte PrivKeyNo;
            public byte[] OptsA;
            public ECPublicKeyParameters EPubA;
            public ECPublicKeyParameters EPubB;
            public ECPrivateKeyParameters EPriB;
            public DesfireFile CertFile;
        }

        protected ushort IsoGeneralAuthenticate(byte P1, byte P2, CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (pendingCommand == null)
                pendingCommand = new PendingIsoGeneralAuthenticate();
            if (!(pendingCommand is PendingIsoGeneralAuthenticate))
                return 0x6985;

            PendingIsoGeneralAuthenticate _pending = (PendingIsoGeneralAuthenticate)pendingCommand;

            switch (_pending.Iteration)
            {
                case 0:
                    {
                        /* First iteration */
                        ClearSession();

                        if (DataIn.Length < 49)
                        {
                            /* Too short */
                            logger.debug("IsoGeneralAuthenticate#1:Too short");
                            return 0x6700;
                        }
                        if (P1 != 0)
                        {
                            /* P1 must be 0 */
                            logger.debug("IsoGeneralAuthenticate#1:P1 must be 00");
                            return 0x6987;
                        }

                        _pending.SecCARootKeyNo = (byte)((P2 >> 4) & 0x07);
                        _pending.CARootKeyNo = (byte)(P2 & 0x07);

                        if (CurrentApplication != null)
                        {
                            if (CurrentApplication.CARootKeys.ContainsKey(_pending.CARootKeyNo))
                            {
                                _pending.CARootKey = CurrentApplication.CARootKeys[_pending.CARootKeyNo];
                            }
                            else if (CurrentApplication.CARootKeys.ContainsKey(_pending.SecCARootKeyNo))
                            {
                                _pending.CARootKey = CurrentApplication.CARootKeys[_pending.SecCARootKeyNo];
                            }
                        }
                        else
                        {
                            if (RootApplication.CARootKeys.ContainsKey(_pending.CARootKeyNo))
                            {
                                _pending.CARootKey = RootApplication.CARootKeys[_pending.CARootKeyNo];
                            }
                            else if (RootApplication.CARootKeys.ContainsKey(_pending.SecCARootKeyNo))
                            {
                                _pending.CARootKey = RootApplication.CARootKeys[_pending.SecCARootKeyNo];
                            }
                        }
                        if (_pending.CARootKey == null)
                        {
                            /* CA Root Key not found */
                            logger.debug("IsoGeneralAuthenticate#1:CA Root Key {0} (or {1}) not found", _pending.CARootKeyNo, _pending.SecCARootKeyNo);
                            return 0x6A88;
                        }

                        /* Generate EPriB */
                        /* -------------- */
                        string curveName = DesfireECCKeyPair.GetCurveName(_pending.CARootKey.CurveId);
                        if (string.IsNullOrEmpty(curveName))
                        {
                            /* Unsupported curve */
                            logger.debug("IsoGeneralAuthenticate#1:Unsupported curve {0:X02}", _pending.CARootKey.CurveId);
                            return 0x6984;
                        }
                        X9ECParameters curve = SecNamedCurves.GetByName(curveName);
                        if (curve == null)
                        {
                            /* Unsupported curve */
                            logger.debug("IsoGeneralAuthenticate#1:Unimplemented curve {0:X02} ({1})", _pending.CARootKey.CurveId, curveName);
                            return 0x6984;
                        }

                        ECDomainParameters curveSpec = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
                        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
                        keyPairGenerator.Init(new ECKeyGenerationParameters(curveSpec, new SecureRandom()));
                        AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
                        _pending.EPriB = (ECPrivateKeyParameters)keyPair.Private;

                        /* Extract the public key from the private key */
                        Org.BouncyCastle.Math.EC.ECPoint priPoint = curve.G.Multiply(_pending.EPriB.D);
                        _pending.EPubB = new ECPublicKeyParameters("ECDSA", priPoint, curveSpec);

                        /* Retrieve the parameters */
                        /* ----------------------- */

                        Asn1Tlv tlvOptsA = Asn1Tlv.Deserialize(DataIn.Bytes, out byte[] remaining);
                        if ((tlvOptsA == null) || !tlvOptsA.T_IsByte || (tlvOptsA.T_AsByte != 0x80))
                        {
                            /* First TLV must be OptsA */
                            logger.debug("IsoGeneralAuthenticate#1:OptA not found");
                            return 0x6987;
                        }
                        if (tlvOptsA.L == 2)
                        {
                            _pending.AuthMethod = tlvOptsA.V[0];
                            _pending.Version = tlvOptsA.V[1];
                        }
                        else if (tlvOptsA.L == 4)
                        {
                            _pending.AuthMethod = tlvOptsA.V[0];
                            _pending.Version = tlvOptsA.V[1];
                            _pending.CertFileId = tlvOptsA.V[2];
                            _pending.PrivKeyNo = tlvOptsA.V[3];

                            if (CurrentApplication != null)
                            {
                                if (CurrentApplication.ECCKeyPairs.ContainsKey(_pending.PrivKeyNo))
                                {
                                    _pending.ECCKeyPair = CurrentApplication.ECCKeyPairs[_pending.PrivKeyNo];
                                }
                            }
                            else
                            {
                                if (RootApplication.ECCKeyPairs.ContainsKey(_pending.PrivKeyNo))
                                {
                                    _pending.ECCKeyPair = RootApplication.ECCKeyPairs[_pending.PrivKeyNo];
                                }
                            }

                            if (_pending.ECCKeyPair == null)
                            {
                                /* CA Root Key not found */
                                logger.debug("IsoGeneralAuthenticate#1:Private Key {0} not found", _pending.PrivKeyNo);
                                return 0x6A84;
                            }

                            if (CurrentApplication != null)
                            {
                                if (CurrentApplication.Files.ContainsKey(_pending.CertFileId))
                                {
                                    _pending.CertFile = CurrentApplication.Files[_pending.CertFileId];
                                }
                            }
                            else
                            {
                                if (RootApplication.Files.ContainsKey(_pending.CertFileId))
                                {
                                    _pending.CertFile = RootApplication.Files[_pending.CertFileId];
                                }
                            }

                            if (_pending.CertFile == null)
                            {
                                /* CertB not found */
                                logger.debug("IsoGeneralAuthenticate#1:Certificate File {0:X02} not found", _pending.CertFileId);
                                return 0x6984;
                            }
                        }
                        else
                        {
                            /* OptsA must be 2 or 4 bytes long */
                            logger.debug("IsoGeneralAuthenticate#1:Unsupported length ({0}) for OptsA", tlvOptsA.L);
                            return 0x6988;
                        }
                        /* Remember OptsA, we'll need it to verify SigA */
                        _pending.OptsA = tlvOptsA.Serialize();

                        Asn1Tlv tlvAuthDOIn = Asn1Tlv.Deserialize(remaining, out remaining);
                        if ((tlvAuthDOIn == null) || !tlvAuthDOIn.T_IsByte || (tlvAuthDOIn.T_AsByte != 0x7C))
                        {
                            /* Second TLV must be AuthDOHdr */
                            logger.debug("IsoGeneralAuthenticate#1:AuthDO not found");
                            return 0x6987;
                        }

                        Asn1Tlv tlvEPubA = Asn1Tlv.Deserialize(tlvAuthDOIn.V);
                        if ((tlvEPubA == null) || !tlvEPubA.T_IsByte || (tlvEPubA.T_AsByte != 0x85))
                        {
                            /* EPubA not found */
                            logger.debug("IsoGeneralAuthenticate#1:AuthDO.EPubA not found");
                            return 0x6987;
                        }

                        /* Validate EPubA */
                        Org.BouncyCastle.Math.EC.ECPoint pubPoint = curve.Curve.DecodePoint(tlvEPubA.V);
                        _pending.EPubA = new ECPublicKeyParameters("ECDSA", pubPoint, curveSpec);

                        /* Show keys */
                        logger.debug("IsoGeneralAuthenticate#1:EPubA={0}", BinConvert.ToHex(_pending.EPubA.Q.GetEncoded(false)));
                        logger.debug("IsoGeneralAuthenticate#1:EPubB={0}", BinConvert.ToHex(_pending.EPubB.Q.GetEncoded(false)));

                        /* Prepare response TLV */
                        Asn1Tlv tlvEPubB = new Asn1Tlv(0x85, _pending.EPubB.Q.GetEncoded(false));
                        Asn1Tlv tlvAuthDOOut = new Asn1Tlv(0x7C, tlvEPubB);

                        DataOut = new CardBuffer(tlvAuthDOOut.Serialize());
                        return 0x9000;
                    }

                case 1:
                    {
                        /* Second iteration */
                        if (DataIn.Length < 6)
                        {
                            /* Too short */
                            logger.debug("IsoGeneralAuthenticate#2:Too short");
                            return 0x6700;
                        }
                        if ((P1 != 0) || (P2 != 0))
                        {
                            /* P1 must be 0 */
                            logger.debug("IsoGeneralAuthenticate#2:P1,P2 must be 00,00");
                            return 0x6987;
                        }

                        Asn1Tlv tlvAuthDOIn = Asn1Tlv.Deserialize(DataIn.Bytes, out byte[] remaining);
                        if ((tlvAuthDOIn == null) || !tlvAuthDOIn.T_IsByte || (tlvAuthDOIn.T_AsByte != 0x7C))
                        {
                            /* Second TLV must be AuthDOHdr */
                            logger.debug("IsoGeneralAuthenticate#2:AuthDO not found");
                            return 0x6987;
                        }

                        Asn1Tlv tlvMsgAEnc = Asn1Tlv.Deserialize(tlvAuthDOIn.V);
                        if ((tlvMsgAEnc == null) || !tlvMsgAEnc.T_IsByte || (tlvMsgAEnc.T_AsByte != 0x86))
                        {
                            /* EPubA not found */
                            logger.debug("IsoGeneralAuthenticate#2:AuthDO.MsgAEnc not found");
                            return 0x6987;
                        }

                        /* Initalize the cryptographic context */
                        CipherContext = new MifareDuoXCipher(this, _pending.EPubA, _pending.EPubB, _pending.EPriB);

                        /* Decipher MsgA */
                        byte[] MsgA = tlvMsgAEnc.V;
                        if ((MsgA.Length % 16) != 0)
                        {
                            /* MsgA must be a multiple of 16 bytes */
                            logger.debug("IsoGeneralAuthenticate#2:MsgAEnc length error ({0})", MsgA.Length);
                            return 0x6987;
                        }
                        if (!(CipherContext as MifareDuoXCipher).CipherRecvEx(ref MsgA, true))
                        {
                            logger.debug("IsoGeneralAuthenticate#2:Decipher MsgA failed");
                            return 0x6982;
                        }

                        /* Validate the padding */
                        if (!CipherContext.Unpadd(ref MsgA))
                        {
                            logger.debug("IsoGeneralAuthenticate#2:Unpadd MsgA failed");
                            return 0x6982;
                        }

                        /* Verify MsgA */
                        logger.debug("IsoGeneralAuthenticate#2:MsgA={0}", BinConvert.ToHex(MsgA));

                        if (MsgA.Length < 2 + 64)
                        {
                            logger.debug("IsoGeneralAuthenticate#2:MsgA is too short");
                            return 0x6982;
                        }

                        if ((MsgA[0] != 0xE0) || (MsgA[1] != 0xE0))
                        {
                            logger.debug("IsoGeneralAuthenticate#2:MsgA does not start with E0E0");
                            return 0x6982;
                        }

                        /* MsgA seems valid, extract CertA and SigA */
                        byte[] CertA = new byte[0];
                        if (MsgA.Length > 2 + 64)
                        {
                            CertA = BinUtils.Copy(MsgA, 2, MsgA.Length - 64 - 2);
                            logger.debug("IsoGeneralAuthenticate#2:CertA={0}", BinConvert.ToHex(CertA));
                        }

                        byte[] SigA = BinUtils.Copy(MsgA, MsgA.Length - 64, 64);

                        /* Ensure CertA is expected */
                        if ((_pending.AuthMethod & 0x20) != 0)
                        {
                            /* CertA NOT expected */
                            if (CertA.Length != 0)
                            {
                                logger.debug("IsoGeneralAuthenticate#2:CertA received, but not expected");
                                return 0x6980;
                            }
                        }
                        else
                        {
                            /* CertA expected */
                            if (CertA.Length == 0)
                            {
                                logger.debug("IsoGeneralAuthenticate#2:CertA expected, but not received");
                                return 0x6980;
                            }
                        }

                        /* Take Long Term public key from CA Root Key */
                        ECPublicKeyParameters LTPubA = _pending.CARootKey.PublicKey;

                        if (CertA.Length > 0)
                        {
                            Asn1Tlv tlvCertA0 = Asn1Tlv.Deserialize(CertA, out remaining);
                            if ((remaining != null) && (remaining.Length > 0))
                            {
                                /* We are likely to have 2 certificates */
                                Asn1Tlv tlvCertA1 = Asn1Tlv.Deserialize(remaining, out remaining);
                                if ((tlvCertA1 == null) || ((remaining != null) && (remaining.Length > 0)))
                                {
                                    logger.debug("IsoGeneralAuthenticate#2:CertA format is invalid (extra bytes?)");
                                    return 0x6988;
                                }
                                X509Certificate certA0;
                                try
                                {
                                    certA0 = new X509Certificate(tlvCertA0.Serialize());
                                }
                                catch
                                {
                                    logger.debug("IsoGeneralAuthenticate#2:CertA#0 is invalid (failed to parse X509 format)");
                                    return 0x6980;
                                }
                                X509Certificate certA1;
                                try
                                {
                                    certA1 = new X509Certificate(tlvCertA1.Serialize());
                                }
                                catch
                                {
                                    logger.debug("IsoGeneralAuthenticate#2:CertA#1 is invalid (failed to parse X509 format)");
                                    return 0x6980;
                                }
                                /* Verifying parent with CA */
                                try
                                {
                                    certA0.Verify(LTPubA);
                                }
                                catch
                                {
                                    logger.debug("IsoGeneralAuthenticate#2:CertA#0 is invalid (signature does not match CA Root Key)");
                                    return 0x6982;
                                }
                                logger.debug("CertA#0 verified OK with Root CA");
                                /* Verifying child with parent */
                                try
                                {
                                    certA1.Verify(certA0.GetPublicKey());
                                }
                                catch
                                {
                                    logger.debug("IsoGeneralAuthenticate#2:CertA#1 is invalid (signature does not match Public Key of CertA#0)");
                                    return 0x6982;
                                }
                                logger.debug("CertA#1 verified OK with Cert#0, using its LTPubA");
                                LTPubA = (ECPublicKeyParameters)certA1.GetPublicKey();
                                // TODO we should verify the Issuer/Subject relationship
                            }
                            else
                            {
                                /* Single certificate */
                                X509Certificate certA;
                                try
                                {
                                    certA = new X509Certificate(CertA);
                                }
                                catch
                                {
                                    logger.debug("IsoGeneralAuthenticate#2:CertA is invalid (failed to parse X509 format)");
                                    return 0x6980;
                                }
                                try
                                {
                                    certA.Verify(LTPubA);
                                }
                                catch
                                {
                                    logger.debug("IsoGeneralAuthenticate#2:CertA is invalid (signature does not match CA Root Key)");
                                    return 0x6982;
                                }
                                logger.debug("CertA verified OK against Root CA, using its LTPubA");
                                LTPubA = (ECPublicKeyParameters)certA.GetPublicKey();
                            }
                        }
                        else
                        {
                            /* No CertA, keep using LTPubA from CA */
                            logger.debug("Using LTPubA from Root CA");
                        }

                        /* Verify SigA */
                        byte[] SigAMsg = new byte[2] { 0xE0, 0xE0 };
                        SigAMsg = BinUtils.Concat(SigAMsg, _pending.OptsA);
                        SigAMsg = BinUtils.Concat(SigAMsg, _pending.EPubA.Q.GetEncoded(false));
                        SigAMsg = BinUtils.Concat(SigAMsg, _pending.EPubB.Q.GetEncoded(false));

                        logger.debug("IsoGeneralAuthenticate#2:SigA={0}", BinConvert.ToHex(SigA));
                        logger.debug("IsoGeneralAuthenticate#2:Verifying SigAMsg={0}", BinConvert.ToHex(SigAMsg));
                        logger.debug("IsoGeneralAuthenticate#2:LT.PubA={0}", BinConvert.ToHex(LTPubA.Q.GetEncoded(false)));

                        if (!MifareDuoXCipher.Verify(LTPubA, SigAMsg, SigA))
                        {
                            logger.debug("IsoGeneralAuthenticate#2:Wrong SigA");
                            return 0x6982;
                        }

                        /* Initialize MsgB */
                        byte[] MsgB = new byte[2] { 0xE1, 0xE1 };
                        /* No OptsB */
                        MsgB = BinUtils.Concat(MsgB, 0x00);

                        if (_pending.ECCKeyPair != null)
                        {
                            /* Compute SigB */
                            byte[] SigBMsg = new byte[2] { 0xE1, 0xE1 };
                            /* No OptsB */
                            SigBMsg = BinUtils.Concat(SigBMsg, 0x00);
                            SigBMsg = BinUtils.Concat(SigBMsg, _pending.EPubB.Q.GetEncoded(false));
                            SigBMsg = BinUtils.Concat(SigBMsg, _pending.EPubA.Q.GetEncoded(false));

                            logger.debug("IsoGeneralAuthenticate#2:Signing SigBMsg={0}", BinConvert.ToHex(SigBMsg));
                            logger.debug("IsoGeneralAuthenticate#2:LT.PubB={0}", BinConvert.ToHex(_pending.ECCKeyPair.PublicKeyValue));
                            byte[] SigB = MifareDuoXCipher.Sign(_pending.ECCKeyPair.PrivateKey, SigBMsg);
                            if (SigB == null)
                            {
                                logger.debug("IsoGeneralAuthenticate#2:Failed to compute SigB");
                                return 0x6F00;
                            }
                            logger.debug("IsoGeneralAuthenticate#2:SigB={0}", BinConvert.ToHex(SigB));
                            if (!MifareDuoXCipher.Verify(_pending.ECCKeyPair.PublicKey, SigBMsg, SigB))
                            {
                                logger.debug("IsoGeneralAuthenticate#2:Failed to verify my own SigB");
                                return 0x6F00;
                            }

                            /* Append CertB */
                            if (_pending.CertFile != null)
                            {
                                if (!(_pending.CertFile is DesfireStandardOrBackupDataFile))
                                {
                                    /* CertB not found */
                                    logger.debug("IsoGeneralAuthenticate#2:Certificate File {0:X02} is not a Standard or Backup data file", _pending.CertFileId);
                                    return 0x6984;
                                }
                                byte[] certData = (_pending.CertFile as DesfireStandardOrBackupDataFile).ReadData();
                                if (certData.Length < 3)
                                {
                                    logger.debug("IsoGeneralAuthenticate#2:Certificate File {0:X02} is too small", _pending.CertFileId);
                                    return 0x6984;
                                }
                                uint certLength = (uint)(certData[0] | (certData[1] << 8) | (certData[2] << 16));
                                if ((certData.Length - 3) < certLength)
                                {
                                    logger.debug("IsoGeneralAuthenticate#2:Certificate File {0:X02} has wrong length ({1} < {2})", _pending.CertFileId, certData.Length - 3, certLength);
                                    return 0x6984;
                                }
                                byte[] CertB = BinUtils.Copy(certData, 3, certLength);
                                logger.debug("IsoGeneralAuthenticate#2:CertB={0}", BinConvert.ToHex(CertB));
                                MsgB = BinUtils.Concat(MsgB, CertB);
                            }

                            /* Append SigB */
                            MsgB = BinUtils.Concat(MsgB, SigB);
                        }

                        /* Cipher MsgB */
                        logger.debug("IsoGeneralAuthenticate#2:MsgB={0}", BinConvert.ToHex(MsgB));
                        byte[] MsgBEnc = BinUtils.Copy(MsgB);
                        CipherContext.Padd(ref MsgBEnc);
                        (CipherContext as MifareDuoXCipher).CipherSendEx(ref MsgBEnc, true);

                        /* Prepare response TLV */
                        Asn1Tlv tlvMsgBEnc = new Asn1Tlv(0x82, MsgBEnc);
                        Asn1Tlv tlvAuthDOOut = new Asn1Tlv(0x7C, tlvMsgBEnc);

                        DataOut = new CardBuffer(tlvAuthDOOut.Serialize());

                        pendingCommand = null; /* Clear pending command */
                        /* Remember we are now in a secure session */
                        InitSession(ESessionType.EV2, 0, CipherContext);

                        return 0x9000;
                    }
            }

            return 0x6985;
        }

        protected ushort IsoInternalAuthenticate(byte P1, byte P2, CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (DataIn.Length < 20)
            {
                /* Too short */
                logger.debug("IsoInternalAuthenticate:Too short");
                return 0x6700;
            }
            if (P1 != 0)
            {
                /* P1 must be 0 */
                logger.debug("IsoInternalAuthenticate:P1 must be 00");
                return 0x6A86;
            }
            if ((P2 & 0x7C) != 0)
            {
                logger.debug("IsoInternalAuthenticate:RFU bit(s) set in P2");
                return 0x6A86;
            }
            byte PrivKeyNo = (byte)(P2 & 0x03);

            DesfireECCKeyPair ECCKeyPair = null;
            if (CurrentApplication != null)
            {
                if (CurrentApplication.ECCKeyPairs.ContainsKey(PrivKeyNo))
                {
                    ECCKeyPair = CurrentApplication.ECCKeyPairs[PrivKeyNo];
                }
            }
            else
            {
                if (RootApplication.ECCKeyPairs.ContainsKey(PrivKeyNo))
                {
                    ECCKeyPair = RootApplication.ECCKeyPairs[PrivKeyNo];
                }
            }

            if (ECCKeyPair == null)
            {
                logger.debug("IsoInternalAuthenticate:Private Key {0} not found", PrivKeyNo);
                return 0x6A88;
            }

            Asn1Tlv tlvOptsA = null;
            Asn1Tlv tlvAuthDOIn = null;

            byte[] remaining = DataIn.Bytes;

            while ((remaining != null) && (remaining.Length > 0))
            {
                Asn1Tlv tlv = Asn1Tlv.Deserialize(remaining, out remaining);
                if (tlv == null)
                    break;
                if (tlv.T_IsByte)
                {
                    switch (tlv.T_AsByte)
                    {
                        case 0x80:
                            /* OptsA TLV found */
                            tlvOptsA = tlv;
                            break;
                        case 0x7C:
                            /* AuthDOIn found */
                            tlvAuthDOIn = tlv;
                            break;
                    }
                }
            }

            if (tlvOptsA != null)
            {
                logger.debug("IsoInternalAuthenticate:OptA={0}", BinConvert.ToHex(tlvOptsA.V));
            }

            if (tlvAuthDOIn == null)
            {
                /* Second TLV must be AuthDOHdr */
                logger.debug("IsoInternalAuthenticate:AuthDO not found");
                return 0x6987;
            }

            Asn1Tlv tlvRndA = Asn1Tlv.Deserialize(tlvAuthDOIn.V);
            if ((tlvRndA == null) || !tlvRndA.T_IsByte || (tlvRndA.T_AsByte != 0x81))
            {
                /* EPubA not found */
                logger.debug("IsoInternalAuthenticate:AuthDO.RndA not found");
                return 0x6987;
            }
            if (tlvRndA.L != 16)
            {
                /* RndA must be 16 bytes long */
                logger.debug("IsoInternalAuthenticate:RndA length error ({0})", tlvRndA.L);
                return 0x6987;
            }
            byte[] RndA = tlvRndA.V;
            logger.debug("IsoInternalAuthenticate:RndA={0}", BinConvert.ToHex(RndA));

            byte[] RndB = RandomGenerator.Get(16);
            logger.debug("IsoInternalAuthenticate:RndB={0}", BinConvert.ToHex(RndB));

            /* Compute SigB */
            byte[] SigBMsg = new byte[2] { 0xF0, 0xF0 };
            if (tlvOptsA != null)
            {
                SigBMsg = BinUtils.Concat(SigBMsg, tlvOptsA.Serialize());
            }
            SigBMsg = BinUtils.Concat(SigBMsg, RndB);
            SigBMsg = BinUtils.Concat(SigBMsg, RndA);

            logger.debug("IsoInternalAuthenticate:Signing SigBMsg={0}", BinConvert.ToHex(SigBMsg));
            logger.debug("IsoInternalAuthenticate:LT.PubB={0}", BinConvert.ToHex(ECCKeyPair.PublicKeyValue));
            byte[] SigB = MifareDuoXCipher.Sign(ECCKeyPair.PrivateKey, SigBMsg);
            if (SigB == null)
            {
                logger.debug("IsoInternalAuthenticate:Failed to compute SigB");
                return 0x6F00;
            }
            logger.debug("IsoInternalAuthenticate:SigB={0}", BinConvert.ToHex(SigB));
            if (!MifareDuoXCipher.Verify(ECCKeyPair.PublicKey, SigBMsg, SigB))
            {
                logger.debug("IsoInternalAuthenticate:Failed to verify my own SigB");
                return 0x6F00;
            }

            /* Prepare response TLV */
            Asn1Tlv tlvRndB = new Asn1Tlv(0x81, RndB);
            Asn1Tlv tlvSigB = new Asn1Tlv(0x82, SigB);
            Asn1Tlv tlvAuthDOOut = new Asn1Tlv(0x7C, tlvRndB, tlvSigB);

            DataOut = new CardBuffer(tlvAuthDOOut.Serialize());
            return 0x9000;
        }

        protected override byte HandleDesfireCommand(byte Command, CardBuffer DataIn, ref CardBuffer DataOut)
        {
            switch (Command)
            {
                case 0x46: // ManageKeyPair
                    logger.trace("ManageKeyPair");
                    return ManageKeyPair(DataIn, ref DataOut);
                case 0x48: // ManageCARootKey
                    logger.trace("ManageCARootKey");
                    return ManageCARootKey(DataIn, ref DataOut);
                default:
                    return base.HandleDesfireCommand(Command, DataIn, ref DataOut);
            }
        }

        protected override ushort HandleIso7816Command(byte INS, byte P1, byte P2, CardBuffer DataIn, ref CardBuffer DataOut)
        {
            switch (INS)
            {
                case 0x87: // GeneralAuthenticate
                    logger.trace("GeneralAuthenticate");
                    return IsoGeneralAuthenticate(P1, P2, DataIn, ref DataOut);
                case 0x88: // InternalAuthenticate
                    logger.trace("InternalAuthenticate");
                    return IsoInternalAuthenticate(P1, P2, DataIn, ref DataOut);
                default:
                    return 0x6C00; // Command not supported by DuoX
            }
        }

    }
}
