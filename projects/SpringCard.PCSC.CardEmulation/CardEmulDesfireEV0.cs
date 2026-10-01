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
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace SpringCard.PCSC.CardEmulation
{
    /// <summary>
    /// Description of PiccEmulDesfireEV0.
    /// </summary>
    public class CardEmulDesfireEV0 : CardEmulDesfire
    {
        protected CardEmulDesfireEV0(string name, DesfireApplication rootApp) : base(name, rootApp) { }
        public CardEmulDesfireEV0() : base("EV0", new DesfireApplication(DesfireApplication.EApplicationKeyType.TDES2K, 1)) { }

        protected override ushort HandleIso7816Command(byte INS, byte P1, byte P2, CardBuffer DataIn, ref CardBuffer DataOut)
        {
            return 0x6C00; // Command not supported by EV0
        }

        protected override byte HandleDesfireCommand(byte Command, CardBuffer DataIn, ref CardBuffer DataOut)
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
                case 0x0A:
                    logger.trace("Authenticate");
                    Status = Authenticate(DataIn, ref DataOut);
                    break;
                case 0x0C:
                    logger.trace("Credit");
                    Status = Credit(DataIn, ref DataOut);
                    break;
                case 0x1C:
                    logger.trace("LimitedCredit");
                    Status = LimitedCredit(DataIn, ref DataOut);
                    break;
                case 0x3B:
                    logger.trace("WriteRecord");
                    Status = WriteRecord(DataIn, ref DataOut);
                    break;
                case 0x3D:
                    logger.trace("WriteData");
                    Status = WriteData(DataIn, ref DataOut);
                    break;
                case 0x45:
                    logger.trace("GetKeySettings");
                    Status = GetKeySettings(DataIn, ref DataOut);
                    break;
                case 0x54:
                    logger.trace("ChangeKeySettings");
                    Status = ChangeKeySettings(DataIn, ref DataOut);
                    break;
                case 0x5A:
                    logger.trace("SelectApplication");
                    Status = SelectApplication(DataIn, ref DataOut);
                    break;
                case 0x5F:
                    logger.trace("ChangeFileSettings");
                    Status = ChangeFileSettings(DataIn, ref DataOut);
                    break;
                case 0x60:
                    logger.trace("GetVersion");
                    Status = GetVersion(DataIn, ref DataOut);
                    break;
                case 0x64:
                    logger.trace("GetKeyVersion");
                    Status = GetKeyVersion(DataIn, ref DataOut);
                    break;
                case 0x6A:
                    logger.trace("GetApplicationIDs");
                    Status = GetApplicationIDs(DataIn, ref DataOut);
                    break;
                case 0x6C:
                    logger.trace("GetValue");
                    Status = GetValue(DataIn, ref DataOut);
                    break;
                case 0x6F:
                    logger.trace("GetFileIDs");
                    Status = GetFileIDs(DataIn, ref DataOut);
                    break;
                case 0xA7:
                    logger.trace("AbortTransaction");
                    Status = AbortTransaction(DataIn, ref DataOut);
                    break;
                case 0xBB:
                    logger.trace("ReadRecords");
                    Status = ReadRecords(DataIn, ref DataOut);
                    break;
                case 0xBD:
                    logger.trace("ReadData");
                    Status = ReadData(DataIn, ref DataOut);
                    break;
                case 0xC0:
                    logger.trace("CreateCyclicRecordFile");
                    Status = CreateRecordFile(true, DataIn, ref DataOut);
                    break;
                case 0xC1:
                    logger.trace("CreateLinearRecordFile");
                    Status = CreateRecordFile(false, DataIn, ref DataOut);
                    break;
                case 0xC4:
                    logger.trace("ChangeKey");
                    Status = ChangeKey(DataIn, ref DataOut);
                    break;
                case 0xC7:
                    logger.trace("CommitTransaction");
                    Status = CommitTransaction(DataIn, ref DataOut);
                    break;
                case 0xCA:
                    logger.trace("CreateApplication");
                    Status = CreateApplication(DataIn, ref DataOut);
                    break;
                case 0xCB:
                    logger.trace("CreateBackupDataFile");
                    Status = CreateDataFile(true, DataIn, ref DataOut);
                    break;
                case 0xCC:
                    logger.trace("CreateValueFile");
                    Status = CreateValueFile(DataIn, ref DataOut);
                    break;
                case 0xCD:
                    logger.trace("CreateStandardDataFile");
                    Status = CreateDataFile(false, DataIn, ref DataOut);
                    break;
                case 0xDA:
                    logger.trace("DeleteApplication");
                    Status = DeleteApplication(DataIn, ref DataOut);
                    break;
                case 0xDC:
                    logger.trace("Debit");
                    Status = Debit(DataIn, ref DataOut);
                    break;
                case 0xDF:
                    logger.trace("DeleteFile");
                    Status = DeleteFile(DataIn, ref DataOut);
                    break;
                case 0xEB:
                    logger.trace("ClearRecordFile");
                    Status = ClearRecordFile(DataIn, ref DataOut);
                    break;
                case 0xF5:
                    logger.trace("GetFileSettings");
                    Status = GetFileSettings(DataIn, ref DataOut);
                    break;
                case 0xFC:
                    logger.trace("FormatPICC");
                    Status = FormatPICC(DataIn, ref DataOut);
                    break;

                default:
                    logger.debug("{0}:Unsupported command {1:X02}", MethodBase.GetCurrentMethod().DeclaringType, Command);
                    Status = ILLEGAL_COMMAND_CODE;
                    break;
            }

            return Status;
        }

        public byte Authenticate(CardBuffer DataIn, ref CardBuffer DataOut)
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

                    logger.debug("\tKey={0}", BinConvert.ToHex(_pending.AuthKey.Value));

                    _pending.RndPicc = RandomGenerator.Get(8);
                    logger.debug("\tRndPicc={0}", BinConvert.ToHex(_pending.RndPicc));

                    CipherContext = new DesfireEV0Cipher(this, _pending.AuthKey.Value);

                    t = new byte[8];

                    for (i = 0; i < 8; i++)
                        t[i] = _pending.RndPicc[i];
                    if (!CipherContext.CipherSend(ref t))
                        return INTERNAL_ERROR;

                    DataOut = new CardBuffer(t);
                    return ADDITIONAL_FRAME;

                case 1:

                    if (!CheckIn(DataIn, 16))
                        return LENGTH_ERROR;

                    t = DataIn.GetBytes();
                    if (!CipherContext.CipherRecv(ref t))
                        return INTEGRITY_ERROR;

                    _pending.RndPcd = new byte[8];
                    for (i = 0; i < 8; i++)
                        _pending.RndPcd[i] = t[i];

                    logger.debug("\tRndPcd ={0}", BinConvert.ToHex(_pending.RndPcd));

                    t = new byte[8];

                    for (i = 0; i < 7; i++)
                        t[i] = _pending.RndPcd[i + 1];
                    t[7] = _pending.RndPcd[0];

                    if (!CipherContext.CipherSend(ref t))
                        return INTERNAL_ERROR;

                    DataOut = new CardBuffer(t);

                    byte[] sessionKey = new byte[16];

                    if (_pending.AuthKey.IsDES())
                    {
                        for (i = 0; i < 4; i++)
                            sessionKey[0 + i] = _pending.RndPcd[0 + i];
                        for (i = 0; i < 4; i++)
                            sessionKey[4 + i] = _pending.RndPicc[0 + i];
                        for (i = 0; i < 4; i++)
                            sessionKey[8 + i] = _pending.RndPcd[0 + i];
                        for (i = 0; i < 4; i++)
                            sessionKey[12 + i] = _pending.RndPicc[0 + i];
                    }
                    else
                    {
                        for (i = 0; i < 4; i++)
                            sessionKey[0 + i] = _pending.RndPcd[0 + i];
                        for (i = 0; i < 4; i++)
                            sessionKey[4 + i] = _pending.RndPicc[0 + i];
                        for (i = 0; i < 4; i++)
                            sessionKey[8 + i] = _pending.RndPcd[4 + i];
                        for (i = 0; i < 4; i++)
                            sessionKey[12 + i] = _pending.RndPicc[4 + i];
                    }

                    logger.debug("Session key (EV0 DES/3DES)={0}", BinConvert.ToHex(sessionKey));
                    InitSession(ESessionType.EV0, _pending.KeyNumber, new DesfireEV0Cipher(this, sessionKey));
                    return OPERATION_OK;
            }

            return INTERNAL_ERROR;
        }

        protected virtual byte ChangeKey(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            return ChangeKeyEV0(DataIn, ref DataOut);
        }

        protected byte ChangeKeyEV0(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (CipherContext == null)
                return PERMISSION_DENIED;

            if (!CheckIn(DataIn, 17, 25))
                return LENGTH_ERROR;

            byte KeyNumber = DataIn.GetByte(0);
            DesfireKey OldKey = null;

            if (CurrentApplication == null)
            {
                if (KeyNumber != 0)
                    return NO_SUCH_KEY;
                OldKey = RootApplication.Keys[0];
            }
            else
            {
                if (KeyNumber >= CurrentApplication.Keys.Count)
                    return NO_SUCH_KEY;
                OldKey = CurrentApplication.Keys[KeyNumber];
            }

            byte[] buffer = DataIn.GetBytes(1, DataIn.Length - 1);

            if (!CipherContext.CipherRecv(ref buffer))
            {
                logger.debug("ChangeKeyEV0: CipherRecv failed");
                return AUTHENTICATION_ERROR;
            }

            logger.debug("ChangeKeyEV0({0:X02})", KeyNumber);

            if (KeyNumber != SessionKeyNumber)
            {
                if (OldKey == null)
                    return INTERNAL_ERROR;

                byte[] oldKeyValue = OldKey.Value;
                if (oldKeyValue.Length == 8)
                    oldKeyValue = BinUtils.Concat(oldKeyValue, oldKeyValue);

                for (int i = 0; i < 16; i++)
                    buffer[i] ^= oldKeyValue[i];
            }
            else
            {
                /* Forget current authentication since we are changing the current key */
                ClearSession();
            }

            logger.debug("\tKey={0}", BinConvert.ToHex(buffer, 0, 16));

            DesfireKey key = new DesfireKey(BinUtils.Copy(buffer, 0, 16));

            if (CurrentApplication == null)
            {
                RootApplication.Keys[0] = key;
            }
            else
            {
                CurrentApplication.Keys[KeyNumber] = key;
            }

            return OPERATION_OK;
        }

        protected virtual byte GetKeySettings(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (!RootFreeCreateDelete)
                if (CipherContext == null)
                    return PERMISSION_DENIED;

            if (!CheckIn(DataIn, 0))
                return LENGTH_ERROR;

            byte[] Result = new byte[2];

            if (CurrentApplication != null)
            {
                Result[0] = CurrentApplication.KeySettings;
                Result[1] = (byte)CurrentApplication.Keys.Count;
            }
            else
            {
                Result[0] = RootKeySettings;
                Result[1] = 0;
            }

            DataOut = new CardBuffer(Result);
            return OPERATION_OK;
        }

    }
}
