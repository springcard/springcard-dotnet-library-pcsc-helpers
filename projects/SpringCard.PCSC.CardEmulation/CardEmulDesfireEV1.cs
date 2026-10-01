/*
 * Crée par SharpDevelop.
 * Utilisateur: johann
 * Date: 05/01/2012
 * Heure: 12:02
 * 
 * Pour changer ce modèle utiliser Outils | Options | Codage | Editer les en-têtes standards.
 */
using SpringCard.LibCs;
using System;
using System.Collections.Generic;

namespace SpringCard.PCSC.CardEmulation
{
    /// <summary>
    /// Description of PiccEmulDesfireEV1.
    /// </summary>
    public class CardEmulDesfireEV1 : CardEmulDesfireEV0
    {
        protected CardEmulDesfireEV1(string name, DesfireApplication rootApp) : base(name, rootApp) { }
        public CardEmulDesfireEV1() : base("EV1", new DesfireApplication(DesfireApplication.EApplicationKeyType.TDES3K, 1)) { }


        protected readonly List<byte> CommandsNotFeedingCmacInEV1 = new List<byte>()
        {
            0x0A, /* Authenticate */
            0x0C, /* Credit */
            0x1A, /* AuthenticateIso */
            0x1C, /* LimitedCredit */
            0x3B, /* WriteRecord */
            0x3D, /* WriteData */
            0x54, /* ChangeKeySettings */
            0x5F, /* ChangeFileSettings */
            0xAA, /* AuthenticateAES */
            0xC4, /* ChangeKey */
            0xDC, /* Debit */
        };

        protected readonly List<byte> CommandsNotAppendingCmacOutEV1 = new List<byte>()
        {
            0x0A, /* Authenticate */
            0x1A, /* AuthenticateIso */
            0x51, /* GetCardUID */
            0x6C, /* GetValue */
            0xAA, /* AuthenticateAES */
            0xBB, /* ReadRecords */
            0xBD, /* ReadData */
        };


        protected virtual byte ProcessIncoming(byte Command, CardBuffer DataIn)
        {
            if ((CipherContext != null) && ((SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES)))
                return ProcessIncomingEV1(Command, DataIn);
            return 0;
        }

        byte ProcessIncomingEV1(byte Command, CardBuffer DataIn)
        {
            /* Don't process again if we are in chaining */
            if ((pendingCommand != null) && (pendingCommand.Iteration != 0))
            {
                return 0;
            }

            /* Check if we must ignore the command */
            if (CommandsNotFeedingCmacInEV1.Contains(Command))
            {
                logger.trace("NOT feeding CMAC with command {0:X02}", Command);
                return 0;
            }

            /* Feed the command into the CMAC */
            logger.trace("Feeding CMAC (EV1) with command {0:X02}", Command);
            byte[] t = BinUtils.Concat(Command, DataIn.GetBytes());
            CipherContext.ComputeCmac(t);
            return 0;
        }

        protected virtual void ProcessOutgoing(bool LastOrSingle, byte Command, ref CardBuffer DataOut)
        {
            if ((CipherContext != null) && ((SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES)))
                ProcessOutgoingEV1(LastOrSingle, Command, ref DataOut);
        }

        void ProcessOutgoingEV1(bool LastOrSingle, byte Command, ref CardBuffer DataOut)
        {
            if (LastOrSingle)
            {
                /* Add the CMAC while respecting chaining */
                byte[] buffer;

                if (pendingResponse != null)
                {
                    /* We must use the pending command, not the current one */
                    Command = pendingResponse.Command;
                    pendingResponse.Append(DataOut.GetBytes());
                    buffer = pendingResponse.Buffer;
                }
                else
                {
                    buffer = DataOut.GetBytes();
                }

                /* No more pending response, whatever, since this is the last frame */
                pendingResponse = null;

                /* Check if the response already has a (explicit) CMAC */
                if (CommandsNotAppendingCmacOutEV1.Contains(Command))
                {
                    logger.trace("NOT adding CMAC in response to command {0:X02}", Command);
                    return;
                }

                /* Add the (implicit) CMAC */
                logger.trace("Adding CMAC (EV1) in response to command {0:X02}", Command);

                /* Add the CMAC at the end of the frame, including the status OPERATION_OK (0x00) __AFTER__ the data */
                buffer = BinUtils.Concat(buffer, OPERATION_OK);
                byte[] cmac = CipherContext.ComputeCmac(buffer);
                DataOut = new CardBuffer(BinUtils.Concat(DataOut.GetBytes(), cmac));
            }
            else
            {
                if (pendingResponse != null)
                {
                    /* Enqueue our bytes in the buffer */
                    pendingResponse.Append(DataOut.GetBytes());
                }
                else
                {
                    /* Create a new pending response */
                    pendingResponse = new PendingResponse(Command, DataOut.GetBytes());
                }
            }
        }

        protected override byte HandleDesfireCommand(byte Command, CardBuffer DataIn, ref CardBuffer DataOut)
        {
            byte Status;

            Status = ProcessIncoming(Command, DataIn);
            if (Status != 0)
                return Status;

            logger.trace("Handle Desfire Command {0:X02} (EV1)", Command);

            Status = HandleDesfireCommandEx(Command, DataIn, ref DataOut);

            switch (Status)
            {
                case OPERATION_OK:
                    ProcessOutgoing(true, Command, ref DataOut);
                    pendingResponse = null;
                    break;
                case ADDITIONAL_FRAME:
                    ProcessOutgoing(false, Command, ref DataOut);
                    break;
                default:
                    /* Upon error, clear everything */
                    CipherContext = null;
                    pendingCommand = null;
                    pendingResponse = null;
                    break;
            }

            return Status;
        }

        protected virtual byte HandleDesfireCommandEx(byte Command, CardBuffer DataIn, ref CardBuffer DataOut)
        {
            byte Status;

            switch (Command)
            {
                /*
                 * NOTES
                 * -----
                 * Since we are testing the Desfire library, it's a good idea to write down the Desfire opcodes as they are in the doc,
                 * instead of relying on Desfire's library constants that may be wrong!
                 * 
                 * Please keep the order to ease maintenance.
                 */
                case 0x1A:
                    logger.trace("AuthenticateIso");
                    Status = AuthenticateIso(DataIn, ref DataOut);
                    break;

                case 0x51:
                    logger.trace("GetCardUID");
                    Status = GetCardUID(DataIn, ref DataOut);
                    break;

                case 0x61:
                    logger.trace("GetISOFileIDs");
                    Status = GetISOFileIDs(DataIn, ref DataOut);
                    break;

                case 0x6D:
                    logger.trace("GetDFNames");
                    Status = GetDFNames(DataIn, ref DataOut);
                    break;

                case 0x6E:
                    logger.trace("FreeMem");
                    Status = FreeMem(DataIn, ref DataOut);
                    break;

                case 0xAA:
                    logger.trace("AuthenticateAes");
                    Status = AuthenticateAes(DataIn, ref DataOut);
                    break;

                default:
                    Status = base.HandleDesfireCommand(Command, DataIn, ref DataOut);
                    break;
            }

            return Status;
        }

        protected byte GetCardUID(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (CipherContext == null)
                return AUTHENTICATION_ERROR;

            logger.debug("Returning UID={0}", BinConvert.ToHex(CardUID));

            byte[] data = CardUID;

            if (SessionType == ESessionType.EV2)
            {
                if (!CipherContext.CipherSend(ref data))
                    return INTERNAL_ERROR;
                CipherContext.AppendCmac(ref data);
            }
            else if ((SessionType == ESessionType.EV0) || (SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES))
            {
                CipherContext.AppendCrc(ref data);
                if (!CipherContext.CipherSend(ref data))
                    return INTERNAL_ERROR;
            }

            DataOut = new CardBuffer(data);
            return OPERATION_OK;
        }


        protected byte FreeMem(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            int value = 8192;
            byte[] result = new byte[3];
            result[0] = (byte)(value & 0x0FF);
            result[1] = (byte)((value >> 8) & 0x0FF);
            result[2] = (byte)((value >> 16) & 0x0FF);
            DataOut = new CardBuffer(result);
            return OPERATION_OK;
        }

        protected byte AuthenticateIso(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            int i;
            byte[] t;

            if (pendingCommand == null)
                pendingCommand = new PendingAuthenticate();
            if (!(pendingCommand is PendingAuthenticate))
                return INTERNAL_ERROR;

            PendingAuthenticate _pending = (PendingAuthenticate)pendingCommand;

            switch (_pending.Iteration)
            {
                case 0:

                    ClearSession();

                    if (!CheckIn(DataIn, 1))
                        return LENGTH_ERROR;

                    _pending.KeyNumber = DataIn.GetByte(0);

                    bool tdes3k = false;

                    if (CurrentApplication == null)
                    {
                        if (_pending.KeyNumber != 0)
                            return NO_SUCH_KEY;
                        _pending.AuthKey = RootApplication.Keys[0];

                        if ((RootApplication.ApplicationKeyType == DesfireApplication.EApplicationKeyType.TDES3K) || (_pending.AuthKey.Is3DES3K()))
                            tdes3k = true;
                    }
                    else
                    {
                        if (_pending.KeyNumber >= CurrentApplication.Keys.Count)
                            return NO_SUCH_KEY;
                        _pending.AuthKey = CurrentApplication.Keys[_pending.KeyNumber];

                        if ((CurrentApplication.ApplicationKeyType == DesfireApplication.EApplicationKeyType.TDES3K) || (_pending.AuthKey.Is3DES3K()))
                            tdes3k = true;
                    }
                    
                    if (tdes3k)
                    {
                        _pending.RndPicc = RandomGenerator.Get(16);
                    }
                    else
                    {
                        _pending.RndPicc = RandomGenerator.Get(8);
                    }

                    CipherContext = new DesfireEV1TDesCipher(this, _pending.AuthKey.Value);

                    t = new byte[_pending.RndPicc.Length];

                    for (i = 0; i < _pending.RndPicc.Length; i++)
                        t[i] = _pending.RndPicc[i];
                    if (!CipherContext.CipherSend(ref t))
                        return INTERNAL_ERROR;

                    DataOut = new CardBuffer(t);
                    return ADDITIONAL_FRAME;

                case 1:

                    if (!CheckIn(DataIn, 2 * _pending.RndPicc.Length))
                        return LENGTH_ERROR;

                    t = DataIn.GetBytes();
                    if (!CipherContext.CipherRecv(ref t))
                        return INTEGRITY_ERROR;

                    _pending.RndPcd = new byte[_pending.RndPicc.Length];
                    for (i = 0; i < _pending.RndPicc.Length; i++)
                        _pending.RndPcd[i] = t[i];

                    logger.debug("RndPcd= {0}", BinConvert.ToHex(_pending.RndPcd));
                    logger.debug("RndPicc={0}", BinConvert.ToHex(_pending.RndPicc));

                    t = new byte[_pending.RndPicc.Length];

                    for (i = 0; i < _pending.RndPicc.Length - 1; i++)
                        t[i] = _pending.RndPcd[i + 1];
                    t[_pending.RndPicc.Length - 1] = _pending.RndPcd[0];

                    if (!CipherContext.CipherSend(ref t))
                        return INTERNAL_ERROR;

                    DataOut = new CardBuffer(t);

                    byte[] sessionKey;
                    
                    if (_pending.RndPicc.Length == 16)
                    {
                        /* 3DES3K, for sure */
                        sessionKey = new byte[24];
                        Array.ConstrainedCopy(_pending.RndPcd, 0, sessionKey, 0, 4);
                        Array.ConstrainedCopy(_pending.RndPicc, 0, sessionKey, 4, 4);
                        Array.ConstrainedCopy(_pending.RndPcd, 6, sessionKey, 8, 4);
                        Array.ConstrainedCopy(_pending.RndPicc, 6, sessionKey, 12, 4);
                        Array.ConstrainedCopy(_pending.RndPcd, 12, sessionKey, 16, 4);
                        Array.ConstrainedCopy(_pending.RndPicc, 12, sessionKey, 20, 4);
                    }
                    else if (_pending.AuthKey.IsDES())
                    {
                        sessionKey = new byte[16];
                        Array.ConstrainedCopy(_pending.RndPcd, 0, sessionKey, 0, 4);
                        Array.ConstrainedCopy(_pending.RndPicc, 0, sessionKey, 4, 4);
                        Array.ConstrainedCopy(sessionKey, 0, sessionKey, 8, 8);
                    }
                    else
                    {
                        sessionKey = new byte[16];
                        Array.ConstrainedCopy(_pending.RndPcd, 0, sessionKey, 0, 4);
                        Array.ConstrainedCopy(_pending.RndPicc, 0, sessionKey, 4, 4);
                        Array.ConstrainedCopy(_pending.RndPcd, 4, sessionKey, 8, 4);
                        Array.ConstrainedCopy(_pending.RndPicc, 4, sessionKey, 12, 4);
                    }

                    logger.debug("Session key (EV1 DES/3DES)={0}", BinConvert.ToHex(sessionKey));

                    InitSession(ESessionType.EV1_TDES, _pending.KeyNumber, new DesfireEV1TDesCipher(this, sessionKey));
                    return OPERATION_OK;
            }

            return INTERNAL_ERROR;
        }

        protected byte AuthenticateAes(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            int i;
            byte[] t;

            if (pendingCommand == null)
                pendingCommand = new PendingAuthenticate();
            if (!(pendingCommand is PendingAuthenticate))
                return INTERNAL_ERROR;

            PendingAuthenticate _pending = (PendingAuthenticate)pendingCommand;

            switch (_pending.Iteration)
            {
                case 0:

                    ClearSession();

                    if (!CheckIn(DataIn, 1))
                        return LENGTH_ERROR;

                    _pending.KeyNumber = DataIn.GetByte(0);

                    if (CurrentApplication == null)
                    {
                        if (_pending.KeyNumber != 0)
                            return NO_SUCH_KEY;
                        _pending.AuthKey = RootApplication.Keys[0];
                    }
                    else
                    {
                        if (_pending.KeyNumber >= CurrentApplication.Keys.Count)
                            return NO_SUCH_KEY;
                        _pending.AuthKey = CurrentApplication.Keys[_pending.KeyNumber];
                    }

                    _pending.RndPicc = RandomGenerator.Get(16);

                    CipherContext = new DesfireEV1AesCipher(this, _pending.AuthKey.Value);

                    t = new byte[16];

                    for (i = 0; i < 16; i++)
                        t[i] = _pending.RndPicc[i];
                    if (!CipherContext.CipherSend(ref t))
                        return INTERNAL_ERROR;

                    DataOut = new CardBuffer(t);
                    return ADDITIONAL_FRAME;

                case 1:

                    if (!CheckIn(DataIn, 32))
                        return LENGTH_ERROR;

                    t = DataIn.GetBytes();
                    if (!CipherContext.CipherRecv(ref t))
                        return INTEGRITY_ERROR;

                    _pending.RndPcd = new byte[16];
                    for (i = 0; i < 16; i++)
                        _pending.RndPcd[i] = t[i];

                    logger.debug("RndPCD= {0}", BinConvert.ToHex(_pending.RndPcd));
                    logger.debug("RndPICC={0}", BinConvert.ToHex(_pending.RndPicc));

                    t = new byte[16];

                    for (i = 0; i < 15; i++)
                        t[i] = _pending.RndPcd[i + 1];
                    t[15] = _pending.RndPcd[0];

                    if (!CipherContext.CipherSend(ref t))
                        return INTERNAL_ERROR;

                    DataOut = new CardBuffer(t);

                    byte[] sessionKey = new byte[16];
                    Array.ConstrainedCopy(_pending.RndPcd, 0, sessionKey, 0, 4);
                    Array.ConstrainedCopy(_pending.RndPicc, 0, sessionKey, 4, 4);
                    Array.ConstrainedCopy(_pending.RndPcd, 12, sessionKey, 8, 4);
                    Array.ConstrainedCopy(_pending.RndPicc, 12, sessionKey, 12, 4);

                    logger.debug("Session key (EV1 AES)={0}", BinConvert.ToHex(sessionKey));

                    InitSession(ESessionType.EV1_AES, _pending.KeyNumber, new DesfireEV1AesCipher(this, sessionKey));
                    return OPERATION_OK;
            }

            return INTERNAL_ERROR;
        }

        protected override byte ChangeKey(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if ((CipherContext != null) && ((SessionType == ESessionType.EV1_TDES || SessionType == ESessionType.EV1_AES)))
                return ChangeKeyEV1(DataIn, ref DataOut);

            return base.ChangeKey(DataIn, ref DataOut);
        }

        protected byte ChangeKeyEV1(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            bool IsAES = false;

            switch (CipherContext.GetBlockSize())
            {
                case 8:
                    break;
                case 16:
                    IsAES = true;
                    break;
                default:
                    return PERMISSION_DENIED;
            }

            byte KeyNumber = DataIn.GetByte(0);

            int KeyLength;
            switch (KeyNumber & 0xC0)
            {
                case 0x80:
                    /* This must be an AES key */
                    IsAES = true;
                    KeyLength = 16;
                    break;

                case 0x40:
                    /* This must be a 3DES3K key */
                    KeyLength = 24;
                    break;

                default:
                    /* This must be a 3DES2K key */
                    KeyLength = 16;
                    break;
            }

            byte ActualKeyNumber = (byte)(KeyNumber & 0x3F);

            DesfireKey OldKey = null;
            if (CurrentApplication == null)
            {
                if (ActualKeyNumber != 0)
                    return NO_SUCH_KEY;
                OldKey = RootApplication.Keys[0];

                logger.debug("ChangeKeyEV1({0:X02}) RootType={1} KeyLength={2} AES={3}", KeyNumber, RootApplication.ApplicationKeyType, KeyLength, IsAES);
            }
            else
            {
                switch (CurrentApplication.ApplicationKeyType)
                {
                    case DesfireApplication.EApplicationKeyType.AES128:
                        IsAES = true;
                        break;
                    case DesfireApplication.EApplicationKeyType.TDES3K:
                        KeyLength = 24;
                        break;
                }

                if (ActualKeyNumber >= CurrentApplication.Keys.Count)
                    return NO_SUCH_KEY;
                OldKey = CurrentApplication.Keys[ActualKeyNumber];

                logger.debug("ChangeKeyEV1({0:X02}) AppType={1} KeyLength={2} AES={3}", KeyNumber, CurrentApplication.ApplicationKeyType, KeyLength, IsAES);
            }            

            byte[] KeyMessage = DataIn.GetBytes(1, DataIn.Length - 1);

            logger.debug("Cipher KeyMessage={0} ({1})", BinConvert.ToHex(KeyMessage), KeyMessage.Length);

            if (!CipherContext.CipherRecv(ref KeyMessage))
                return INTEGRITY_ERROR;

            logger.debug("Plain  KeyMessage={0} ({1})", BinConvert.ToHex(KeyMessage), KeyMessage.Length);

            logger.debug("KeyNumber={0:X02}, KeyLength={1}, HasVersion={2}, MessageLength={3}", KeyNumber, KeyLength, IsAES, KeyMessage.Length);

            byte[] Crc32Input = new byte[] { 0xC4, KeyNumber };
            byte[] KeyValue;

            if (ActualKeyNumber != SessionKeyNumber)
            {
                /* Check that length is correct */
                int expectedLength = KeyLength + 2 * 4 + (IsAES ? 1 : 0); /* Key + 2 x CRC32 + Version */
                if (KeyMessage.Length < expectedLength)
                {
                    if (CurrentApplication.ApplicationKeyType == DesfireApplication.EApplicationKeyType.TDES3K)
                    {
                        /* Try again with shorter variant */
                        expectedLength = 16 + 2 * 4; /* Key + 2 x CRC32 */
                        if (KeyMessage.Length < expectedLength)
                            return LENGTH_ERROR;
                        /* Change key length */
                        KeyLength = 16;
                    }
                }

                if (OldKey == null)
                    return INTERNAL_ERROR;

                byte[] oldKeyValue = OldKey.Value;
                if (oldKeyValue.Length == 8) /* Transform a DES key into a 3DES2K key */
                    oldKeyValue = BinUtils.Concat(oldKeyValue, oldKeyValue);
                if (oldKeyValue.Length == 16) /* Transform a 3DES2K key into a 3DES3K key */
                    oldKeyValue = BinUtils.Concat(BinUtils.Copy(oldKeyValue, 0, 8), oldKeyValue);

                Crc32Input = BinUtils.Concat(Crc32Input, BinUtils.Copy(KeyMessage, 0, KeyLength));

                logger.debug("\tXOR Key={0}", BinConvert.ToHex(KeyMessage, 0, KeyLength));
                logger.debug("\tOld Key={0}", BinConvert.ToHex(oldKeyValue));

                KeyValue = new byte[KeyLength];
                for (int i = 0; i < KeyLength; i++)
                    KeyValue[i] = (byte)(KeyMessage[i] ^ oldKeyValue[i]);

                logger.debug("\tNew Key={0}", BinConvert.ToHex(KeyValue));

                byte[] Crc32OfKeyRcvd = BinUtils.Copy(KeyMessage, KeyLength + 4 + (IsAES ? 1 : 0), 4);

                logger.debug("\tCRC32 (NewKey)={0}", BinConvert.ToHex(Crc32OfKeyRcvd));
                byte[] Crc32OfKeyCalc = CipherContext.ComputeCrc(KeyValue);
                if (!BinUtils.Equals(Crc32OfKeyRcvd, Crc32OfKeyCalc))
                {
                    logger.debug("\tCRC32 (NewKey)={0}!={1}", BinConvert.ToHex(Crc32OfKeyRcvd), BinConvert.ToHex(Crc32OfKeyCalc));
                    return INTEGRITY_ERROR;
                }
            }
            else
            {
                /* Check that length is correct */
                int expectedLength = KeyLength + 1 * 4 + (IsAES ? 1 : 0); /* Key + 1 x CRC32 + Version */
                if (KeyMessage.Length < expectedLength)
                {
                    if (CurrentApplication.ApplicationKeyType == DesfireApplication.EApplicationKeyType.TDES3K)
                    {
                        /* Try again with shorter variant */
                        expectedLength = 16 + 1 * 4; /* Key + 1 x CRC32 */
                        if (KeyMessage.Length < expectedLength)
                            return LENGTH_ERROR;
                        /* Change key length */
                        KeyLength = 16;
                    }
                }

                KeyValue = new byte[KeyLength];
                for (int i = 0; i < KeyLength; i++)
                    KeyValue[i] = KeyMessage[i];

                logger.debug("\tKey={0}", BinConvert.ToHex(KeyValue));

                Crc32Input = BinUtils.Concat(Crc32Input, KeyValue);
            }

            byte[] Crc32Recv;
            byte KeyVersion = 0;

            if (IsAES)
            {
                /* Retrieve the key version */
                KeyVersion = KeyMessage[KeyLength];
                logger.debug("\tVersion={0:X02}", KeyVersion);
                Crc32Input = BinUtils.Concat(Crc32Input, KeyVersion);
                Crc32Recv = BinUtils.Copy(KeyMessage, KeyLength + 1, 4);
            }
            else
            {
                Crc32Recv = BinUtils.Copy(KeyMessage, KeyLength + 0, 4);
            }
            logger.debug("\tCrc32 received   {0}", BinConvert.ToHex(Crc32Recv));
            logger.debug("\tCrc32 input      {0}", BinConvert.ToHex(Crc32Input));
            byte[] Crc32Calc = CipherContext.ComputeCrc(Crc32Input);
            logger.debug("\tCrc32 calculated {0}", BinConvert.ToHex(Crc32Calc));

            if (!BinUtils.Equals(Crc32Recv, Crc32Calc))
            {
                logger.error("CRC32 error");
                return INTEGRITY_ERROR;
            }

            if (ActualKeyNumber == SessionKeyNumber)
            {
                /* Forget current authentication since we are changing the current key */
                ClearSession();
            }

            DesfireKey key = new DesfireKey(KeyValue, KeyVersion);

            if (CurrentApplication == null)
            {
                RootApplication.Keys[0] = key;
            }
            else
            {
                CurrentApplication.Keys[ActualKeyNumber] = key;
            }

            return OPERATION_OK;
        }

        protected override byte GetKeySettings(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if ((CipherContext != null) && ((SessionType == ESessionType.EV1_TDES || SessionType == ESessionType.EV1_AES)))
                return GetKeySettingsEV1(DataIn, ref DataOut);

            return base.GetKeySettings(DataIn, ref DataOut);
        }

        protected virtual byte GetKeySettingsEV1(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (!CheckIn(DataIn, 0))
                return LENGTH_ERROR;

            byte[] result = new byte[2];

            if (CurrentApplication != null)
            {
                result[0] = CurrentApplication.KeySettings;
                result[1] = (byte)CurrentApplication.Keys.Count;
            }
            else
            {
                result[0] = RootKeySettings;
                result[1] = 1;
            }

            DataOut = new CardBuffer(result);
            return OPERATION_OK;
        }

    }
}
