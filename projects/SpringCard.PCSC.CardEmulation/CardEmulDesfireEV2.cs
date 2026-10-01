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
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Xml;

namespace SpringCard.PCSC.CardEmulation
{
    /// <summary>
    /// Description of PiccEmulDesfireEV2.
    /// </summary>
    public class CardEmulDesfireEV2 : CardEmulDesfireEV1
    {
        protected CardEmulDesfireEV2(string name, DesfireApplication rootApp) : base(name, rootApp) { }
        public CardEmulDesfireEV2() : base("EV2", new DesfireApplication(DesfireApplication.EApplicationKeyType.TDES3K, 1)) { }

        protected readonly List<byte> CommandsWithoutCmacInEV2 = new List<byte>()
        {
            0x0C, /* Credit */
            0x1C, /* LimitedCredit */
            0x3B, /* WriteRecord */
            0x3D, /* WriteData */
            0x5A, /* SelectApplication */
            0x6C, /* GetValue */
            0x71, /* AuthenticateFirst */
            0x77, /* AuthenticateNonFirst */
            0x8B, /* WriteRecordISO */
            0x8D, /* WriteDataISO */
            0xAA, /* AuthenticateAES */
            0xAB, /* ReadRecordsISO */
            0xAD, /* ReadDataISO */
            0xBA, /* UpdateRecordISO */
            0xBB, /* ReadRecords */
            0xBD, /* ReadData */
            0xDB, /* UpdateRecord */
            0xDC, /* Debit */
        };

        protected readonly List<byte> CommandsNotAppendingCmacOutEV2 = new List<byte>()
        {
            0x0C, /* Credit */
            0x1C, /* LimitedCredit */
            0x3B, /* WriteRecord */
            0x3D, /* WriteData */
            0x51, /* GetCardUID */
            0x6C, /* GetValue */
            0x71, /* AuthenticateFirst */
            0x77, /* AuthenticateNonFirst */
            0x8B, /* WriteRecordISO */
            0x8D, /* WriteDataISO */
            0xAB, /* ReadRecordsISO */
            0xAD, /* ReadDataISO */
            0xBA, /* UpdateRecordISO */
            0xBB, /* ReadRecords */
            0xBD, /* ReadData */
            0xDB, /* UpdateRecord */
            0xDC, /* Debit */
        };

        protected override byte ProcessIncoming(byte Command, CardBuffer DataIn)
        {
            if ((CipherContext != null) && (SessionType == ESessionType.EV2))
                return ProcessIncomingEV2(Command, DataIn);
            return base.ProcessIncoming(Command, DataIn);
        }

        byte ProcessIncomingEV2(byte Command, CardBuffer DataIn)
        {
            /* Don't process again if we are in chaining */
            if ((pendingCommand != null) && (pendingCommand.Iteration != 0))
            {
                return 0;
            }

            /* Check if we must ignore the command */
            if (!CommandsWithoutCmacInEV2.Contains(Command))
            {
                /* Feed the command into the CMAC */
                logger.trace("Verifying CMAC (EV2) for command {0:X02} [{1}]", Command, (CipherContext as DesfireEV2Cipher).TransactionCounter);

                byte[] t = BinUtils.Concat(Command, DataIn.GetBytes());

                if (!CipherContext.CheckCmac(t))
                    return INTEGRITY_ERROR;

                DataIn.Bytes = DataIn.GetBytes(0, DataIn.Length - 8); /* Remove the CMAC from the buffer */

                /* Increment the transaction counter */
                (CipherContext as DesfireEV2Cipher).IncrementCounter();
            }

            return 0;
        }

        protected override void ProcessOutgoing(bool LastOrSingle, byte Command, ref CardBuffer DataOut)
        {
            if ((CipherContext != null) && (SessionType == ESessionType.EV2))
            {
                ProcessOutgoingEV2(LastOrSingle, Command, ref DataOut);
            }
            else
            {
                base.ProcessOutgoing(LastOrSingle, Command, ref DataOut);
            }
        }

        void ProcessOutgoingEV2(bool LastOrSingle, byte Command, ref CardBuffer DataOut)
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
                if (CommandsNotAppendingCmacOutEV2.Contains(Command))
                {
                    logger.trace("NOT adding CMAC in response to command {0:X02}", Command);
                    return;
                }

                /* Add the (implicit) CMAC */
                logger.trace("Adding CMAC (EV2) in response to command {0:X02}", Command);
                byte[] cmac = CipherContext.ComputeCmac(buffer);
                logger.trace("CMAC (EV2) {0} [{1}]", BinConvert.ToHex(cmac), (CipherContext as DesfireEV2Cipher).TransactionCounter);
                DataOut = new CardBuffer(BinUtils.Concat(DataOut.Bytes, cmac));
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

            logger.trace("Handle Desfire Command {0:X02} (EV2)", Command);

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
                case 0x71:
                    logger.trace("AuthenticateFirst");
                    Status = AuthenticateFirst(DataIn, ref DataOut);
                    break;

                case 0x77:
                    logger.trace("AuthenticateNonFirst");
                    Status = AuthenticateNonFirst(DataIn, ref DataOut);
                    break;

                case 0x8B:
                    logger.trace("WriteRecordISO");
                    Status = WriteRecord(DataIn, ref DataOut, true);
                    break;

                case 0x8D:
                    logger.trace("WriteDataISO");
                    Status = WriteData(DataIn, ref DataOut, true);
                    break;

                case 0xAB:
                    logger.trace("ReadRecordsISO");
                    Status = ReadRecords(DataIn, ref DataOut, true);
                    break;

                case 0xAD:
                    logger.trace("ReadDataISO");
                    Status = ReadData(DataIn, ref DataOut, true);
                    break;

                case 0xBA:
                    logger.trace("UpdateRecordISO");
                    Status = UpdateRecord(DataIn, ref DataOut, true);
                    break;

                case 0xDB:
                    logger.trace("UpdateRecord");
                    Status = UpdateRecord(DataIn, ref DataOut);
                    break;

                default:
                    Status = base.HandleDesfireCommandEx(Command, DataIn, ref DataOut);
                    break;
            }

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

        protected byte AuthenticateFirst(CardBuffer DataIn, ref CardBuffer DataOut)
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

                    if (!CheckIn(DataIn, 2, 8))
                        return LENGTH_ERROR;

                    _pending.KeyNumber = DataIn.GetByte(0);

                    int pcdCap2Len = DataIn.GetByte(1);
                    if (pcdCap2Len > 6)
                        return LENGTH_ERROR;

                    if (!CheckIn(DataIn, 2, 2 + pcdCap2Len))
                        return LENGTH_ERROR;

                    _pending.PcdCap2 = DataIn.GetBytes(2, pcdCap2Len);
                    _pending.PcdCap2 = BinUtils.EnsureSize(_pending.PcdCap2, 6, 6);

                    if (CurrentApplication == null)
                    {
                        if (_pending.KeyNumber >= RootApplication.Keys.Count)
                            return NO_SUCH_KEY;
                        _pending.AuthKey = RootApplication.Keys[_pending.KeyNumber];
                    }
                    else
                    {
                        if (_pending.KeyNumber >= CurrentApplication.Keys.Count)
                            return NO_SUCH_KEY;
                        _pending.AuthKey = CurrentApplication.Keys[_pending.KeyNumber];
                    }

                    logger.debug("Key=    {0}", BinConvert.ToHex(_pending.AuthKey.Value));

                    _pending.RndPicc = RandomGenerator.Get(16);

                    CipherContext = new DesfireEV2Cipher(this, _pending.AuthKey.Value);

                    t = new byte[16];

                    for (i = 0; i < 16; i++)
                        t[i] = _pending.RndPicc[i];
                    
                    if (!(CipherContext as DesfireEV2Cipher).CipherSendEx(ref t, true))
                        return INTERNAL_ERROR;

                    DataOut = new CardBuffer(t);
                    return ADDITIONAL_FRAME;

                case 1:

                    if (!CheckIn(DataIn, 32))
                        return LENGTH_ERROR;

                    t = DataIn.GetBytes();

                    if (!(CipherContext as DesfireEV2Cipher).CipherRecvEx(ref t, true))
                        return INTEGRITY_ERROR;

                    _pending.RndPcd = new byte[16];
                    for (i = 0; i < 16; i++)
                        _pending.RndPcd[i] = t[i];

                    logger.debug("RndPCD= {0}", BinConvert.ToHex(_pending.RndPcd));
                    logger.debug("RndPICC={0}", BinConvert.ToHex(_pending.RndPicc));

                    (CipherContext as DesfireEV2Cipher).SetTransactionIdentifier(RandomGenerator.Get(4));

                    t = new byte[16];
                    for (i = 0; i < 15; i++)
                        t[i] = _pending.RndPcd[i + 1];
                    t[15] = _pending.RndPcd[0];

                    t = BinUtils.Concat((CipherContext as DesfireEV2Cipher).TransactionIdentifier, t);
                    t = BinUtils.Concat(t, new byte[6]); /* PiccCap2 */
                    t = BinUtils.Concat(t, _pending.PcdCap2);
                    t = BinUtils.EnsureSize(t, 32, 32);

                    logger.trace("TI || RndPcd' || PiccCap2 || PcdCap2 = {0}", BinConvert.ToHex(t));

                    if (!(CipherContext as DesfireEV2Cipher).CipherSendEx(ref t, true))
                        return INTERNAL_ERROR;

                    DataOut = new CardBuffer(t);

                    if (_pending.AuthKey.IsAES256())
                    {
                        (CipherContext as DesfireEV2Cipher).GenerateSessionKeys256(_pending.RndPcd, _pending.RndPicc);
                    }
                    else
                    {
                        (CipherContext as DesfireEV2Cipher).GenerateSessionKeys128(_pending.RndPcd, _pending.RndPicc);
                    }

                    logger.debug("Session keys (EV2 AES) Encrypt={0}", BinConvert.ToHex((CipherContext as DesfireEV2Cipher).SessionEncKey));
                    logger.debug("                          CMAC={0}", BinConvert.ToHex((CipherContext as DesfireEV2Cipher).SessionCmacKey));

                    InitSession(ESessionType.EV2, _pending.KeyNumber, CipherContext);
                    return OPERATION_OK;
            }

            return INTERNAL_ERROR;
        }

        protected byte AuthenticateNonFirst(CardBuffer DataIn, ref CardBuffer DataOut)
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

                    if (CipherContext == null)
                        return AUTHENTICATION_ERROR;

                    if (!CheckIn(DataIn, 1, 1))
                        return LENGTH_ERROR;

                    _pending.KeyNumber = DataIn.GetByte(0);

                    if (CurrentApplication == null)
                    {
                        if (_pending.KeyNumber >= RootApplication.Keys.Count)
                            return NO_SUCH_KEY;
                        _pending.AuthKey = RootApplication.Keys[_pending.KeyNumber];
                    }
                    else
                    {
                        if (_pending.KeyNumber >= CurrentApplication.Keys.Count)
                            return NO_SUCH_KEY;
                        _pending.AuthKey = CurrentApplication.Keys[_pending.KeyNumber];
                    }

                    logger.debug("Key=    {0}", BinConvert.ToHex(_pending.AuthKey.Value));

                    _pending.RndPicc = RandomGenerator.Get(16);

                    /* "Clone" the current context to keep the same transaction identifier and counter */
                    CipherContext = new DesfireEV2Cipher(CipherContext as DesfireEV2Cipher, _pending.AuthKey.Value);

                    t = new byte[16];

                    for (i = 0; i < 16; i++)
                        t[i] = _pending.RndPicc[i];

                    if (!(CipherContext as DesfireEV2Cipher).CipherSendEx(ref t, true))
                        return INTERNAL_ERROR;

                    DataOut = new CardBuffer(t);
                    return ADDITIONAL_FRAME;

                case 1:

                    if (!CheckIn(DataIn, 32))
                        return LENGTH_ERROR;

                    t = DataIn.GetBytes();

                    if (!(CipherContext as DesfireEV2Cipher).CipherRecvEx(ref t, true))
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

                    logger.trace("RndPcd' = {0}", BinConvert.ToHex(t));

                    if (!(CipherContext as DesfireEV2Cipher).CipherSendEx(ref t, true))
                        return INTERNAL_ERROR;

                    DataOut = new CardBuffer(t);

                    if (_pending.AuthKey.IsAES256())
                    {
                        (CipherContext as DesfireEV2Cipher).GenerateSessionKeys256(_pending.RndPcd, _pending.RndPicc);
                    }
                    else
                    {
                        (CipherContext as DesfireEV2Cipher).GenerateSessionKeys128(_pending.RndPcd, _pending.RndPicc);
                    }

                    logger.debug("Session keys (EV2 AES) Encrypt={0}", BinConvert.ToHex((CipherContext as DesfireEV2Cipher).SessionEncKey));
                    logger.debug("                          CMAC={0}", BinConvert.ToHex((CipherContext as DesfireEV2Cipher).SessionCmacKey));

                    InitSession(ESessionType.EV2, _pending.KeyNumber, CipherContext);
                    return OPERATION_OK;
            }

            return INTERNAL_ERROR;
        }

        protected override byte ChangeKey(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if ((CipherContext != null) && (SessionType == ESessionType.EV2))
                return ChangeKeyEV2(DataIn, ref DataOut);

            return base.ChangeKey(DataIn, ref DataOut);
        }

        protected byte ChangeKeyEV2(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if ((CipherContext == null) || (SessionType != ESessionType.EV2))
                return AUTHENTICATION_ERROR;

            /*****************************************************/
            /* NB: CMAC has already been validated by the caller */
            /*****************************************************/

            byte KeyNumber = DataIn.GetByte(0);
            byte ActualKeyNumber = (byte)(KeyNumber & 0x3F);

            bool IsTDES = false;
            int KeyLength;
            switch (KeyNumber & 0xC0)
            {
                case 0xC0:
                    /* This must be an AES256 key */
                    KeyLength = 32;
                    break;
                case 0x80:
                    /* This must be an AES128 key */
                    KeyLength = 16;
                    break;
                case 0x40:
                    /* This must be a 3DES3K key */
                    KeyLength = 24;
                    IsTDES = true;
                    break;
                case 0x00:
                    /* This must be a 3DES2K key */
                    KeyLength = 16;
                    IsTDES = true;
                    break;

                default:
                    return PARAMETER_ERROR;
            }

            DesfireKey OldKey = null;
            if (CurrentApplication == null)
            {
                if (ActualKeyNumber >= CurrentApplication.Keys.Count)
                    return NO_SUCH_KEY;
                OldKey = RootApplication.Keys[ActualKeyNumber];
            }
            else
            {
                switch (CurrentApplication.ApplicationKeyType)
                {
                    case DesfireApplication.EApplicationKeyType.AES256:
                        KeyLength = 32;
                        IsTDES = false;
                        break;
                    case DesfireApplication.EApplicationKeyType.AES128:
                        KeyLength = 16;
                        IsTDES = false;
                        break;
                    case DesfireApplication.EApplicationKeyType.TDES2K:
                        KeyLength = 16;
                        IsTDES = true;
                        break;
                    case DesfireApplication.EApplicationKeyType.TDES3K:
                        KeyLength = 24;
                        IsTDES = true;
                        break;
                }

                if (ActualKeyNumber >= CurrentApplication.Keys.Count)
                    return NO_SUCH_KEY;
                OldKey = CurrentApplication.Keys[ActualKeyNumber];
            }

            logger.debug("ChangeKeyEV2({0:X02}) Size={1}", KeyNumber, KeyLength);

            byte[] KeyMessage = DataIn.GetBytes(1, DataIn.Length - 1);

            logger.debug("Cipher KeyMessage={0} ({1})", BinConvert.ToHex(KeyMessage), KeyMessage.Length);

            if (!CipherContext.CipherRecv(ref KeyMessage))
                return INTEGRITY_ERROR;

            logger.debug("Plain  KeyMessage={0} ({1})", BinConvert.ToHex(KeyMessage), KeyMessage.Length);

            logger.debug("KeyNumber={0:X02}, KeyLength={1}, HasVersion={2}, MessageLength={3}", KeyNumber, KeyLength, !IsTDES, KeyMessage.Length);

            byte[] KeyValue = new byte[KeyLength];

            if (ActualKeyNumber != SessionKeyNumber)
            {
                /* Check that length is correct */
                int expectedLength = KeyLength + 4 + (IsTDES ? 0 : 1); /* Key + CRC32 + Version */
                if (KeyMessage.Length < expectedLength)
                    return LENGTH_ERROR;

                if (OldKey == null)
                    return INTERNAL_ERROR;

                byte[] oldKeyValue = OldKey.Value;
                if (oldKeyValue.Length == 8) /* Transform a DES key into a 3DES2K key */
                    oldKeyValue = BinUtils.Concat(oldKeyValue, oldKeyValue);
                if (oldKeyValue.Length == 16) /* Transform a 3DES2K key into a 3DES3K key */
                    oldKeyValue = BinUtils.Concat(BinUtils.Copy(oldKeyValue, 0, 8), oldKeyValue);

                logger.debug("\tXOR Key={0}", BinConvert.ToHex(KeyMessage, 0, KeyLength));

                logger.debug("\tOld Key={0}", BinConvert.ToHex(oldKeyValue));

                for (int i = 0; i < KeyLength; i++)
                    KeyValue[i] = (byte)(KeyMessage[i] ^ oldKeyValue[i]);

                logger.debug("\tNew Key={0}", BinConvert.ToHex(KeyValue));

                byte[] Crc32OfKeyRcvd = BinUtils.Copy(KeyMessage, KeyLength + (IsTDES ? 0 : 1), 4);

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
                int expectedLength = KeyLength + (IsTDES ? 0 : 1); /* Key + 1 x CRC32 + Version */
                if (KeyMessage.Length < expectedLength)
                    return LENGTH_ERROR;

                for (int i = 0; i < KeyLength; i++)
                    KeyValue[i] = KeyMessage[i];

                logger.debug("\tKey={0}", BinConvert.ToHex(KeyValue));
            }

            DesfireKey key;

            if (!IsTDES)
            {
                /* Retrieve the key version */
                byte KeyVersion = KeyMessage[KeyLength];
                logger.debug("\tVersion={0:X02}", KeyVersion);
                key = new DesfireKey(KeyValue, KeyVersion);
            }
            else
            {
                key = new DesfireKey(KeyValue);
            }

            if (ActualKeyNumber == SessionKeyNumber)
            {
                /* Forget current authentication since we are changing the current key */
                ClearSession();
            }

            if (CurrentApplication == null)
            {
                RootApplication.Keys[ActualKeyNumber] = key;
            }
            else
            {
                CurrentApplication.Keys[ActualKeyNumber] = key;
            }

            return OPERATION_OK;
        }
    }
}
