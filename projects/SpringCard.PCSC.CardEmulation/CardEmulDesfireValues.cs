/*
 * Crée par SharpDevelop.
 * Utilisateur: johann
 * Date: 05/01/2012
 * Heure: 12:02
 * 
 * Pour changer ce modèle utiliser Outils | Options | Codage | Editer les en-têtes standards.
 */
using Newtonsoft.Json.Linq;
using SpringCard.LibCs;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace SpringCard.PCSC.CardEmulation
{
    public partial class CardEmulDesfire
    {
        protected byte CreateValueFile(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (!CheckIn(DataIn, 17))
                return LENGTH_ERROR;

            if (CurrentApplication == null)
            {
                logger.debug("CreateValueFile:No application");
                return PERMISSION_DENIED;
            }

            byte fileId = DataIn.GetByte(0);
            byte commSettings = DataIn.GetByte(1);
            ushort accessRights = Get2(DataIn.GetBytes(2, 2));

            long lowerLimit = Get4(DataIn.GetBytes(4, 4));
            long upperLimit = Get4(DataIn.GetBytes(8, 4));
            long value = Get4(DataIn.GetBytes(12, 4));
            byte moreSettings = DataIn.GetByte(16);

            if (CurrentApplication.FileExists(fileId))
                return DUPLICATE_ERROR;

            DesfireFile file = new DesfireValueFile(commSettings, accessRights, lowerLimit, upperLimit, value, ((moreSettings & 0x01) != 0), ((moreSettings & 0x01) != 0));
            file.SetMetaData(this, CurrentApplication.Aid, fileId);

            if (CurrentApplication.InsertFile(fileId, file))
                return OPERATION_OK;
            return APPL_INTEGRITY_ERROR;
        }

        public byte GetValue(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            const byte OpCode = 0x6C;
            DesfireValueFile file;

            if (CurrentApplication == null)
            {
                logger.debug("GetValue:No application");
                return PERMISSION_DENIED;
            }

            byte file_id = DataIn.GetByte(0);

            if (!CurrentApplication.SelectFile(file_id))
                return FILE_NOT_FOUND;

            if (!(CurrentApplication.CurrentFile is DesfireValueFile))
            {
                logger.debug("GetValue:Not a Value file");
                return PERMISSION_DENIED;
            }

            file = (DesfireValueFile)CurrentApplication.CurrentFile;

            if (!file.Readable(SessionKeyNumber))
            {
                logger.debug("GetValue:Access denied");
                return PERMISSION_DENIED;
            }

            if ((file.CommMode != COMM_MODE_PLAIN) && (CipherContext == null))
            {
                /* No in secure session */
                logger.debug("GetValue:Not in secure session");
                return PERMISSION_DENIED;
            }

            byte[] data = new byte[4];
            Set4(ref data, 0, file.Value);

            logger.debug("GetValue(file={0:X02}, commMode={1}) -> {2} ({3})", file.FileId, file.CommMode, file.Value, BinConvert.ToHex(data));

            switch (file.CommMode)
            {
                case COMM_MODE_PLAIN:
                    if ((CipherContext != null) && ((SessionType == ESessionType.EV2)))
                    {
                        /* Increment the counter in EV2 */
                        logger.debug("GetValue:Plain (EV2) [{0}]", (CipherContext as DesfireEV2Cipher).TransactionCounter);
                        CipherContext.IncrementCounter();
                    }
                    else if ((CipherContext != null) && ((SessionType == ESessionType.EV1_TDES || SessionType == ESessionType.EV1_AES)))
                    {
                        /* Always add a CMAC in EV1 */
                        logger.debug("GetValue:Plain (EV1)");
                        CipherContext.AppendCmac(ref data);
                    }
                    else
                    {
                        logger.debug("GetValue:Plain");
                    }
                    break;
                case COMM_MODE_MACED:
                    logger.debug("GetValue:CMAC");
                    if (CipherContext == null)
                        return AUTHENTICATION_ERROR;
                    CipherContext.IncrementCounter();
                    CipherContext.AppendCmac(ref data);
                    break;
                case COMM_MODE_CIPHER:
                    logger.debug("GetValue:Cipher");
                    if (CipherContext == null)
                        return AUTHENTICATION_ERROR;
                    if (SessionType == ESessionType.EV2)
                    {
                        byte[] t = BinUtils.Concat(OpCode, DataIn.GetBytes());
                        if (!CipherContext.CheckCmac(t))
                            return INTEGRITY_ERROR;
                        /* Increment the counter before answering */
                        CipherContext.IncrementCounter();
                        /* Cipher the output */
                        if (!CipherContext.CipherSend(ref data))
                            return INTERNAL_ERROR;
                        /* Add a CMAC to the ciphered output */
                        CipherContext.AppendCmac(ref data);
                    }
                    else if ((SessionType == ESessionType.EV0) || (SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES))
                    {
                        CipherContext.AppendCrc(ref data);
                        if (!CipherContext.CipherSend(ref data))
                            return INTERNAL_ERROR;
                    }
                    break;
            }

            DataOut = new CardBuffer(data);

            return OPERATION_OK;
        }

        public byte Credit(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            return ModifyValue(DataIn, ref DataOut, 0x0C, "Credit");
        }

        public byte LimitedCredit(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            return ModifyValue(DataIn, ref DataOut, 0x1C, "LimitedCredit");
        }

        public byte Debit(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            return ModifyValue(DataIn, ref DataOut, 0xDC, "Debit");
        }

        public byte ModifyValue(CardBuffer DataIn, ref CardBuffer DataOut, byte OpCode, string FuncName)
        {
            DesfireValueFile file;

            if (CurrentApplication == null)
            {
                logger.debug("{0}:No application", FuncName);
                return PERMISSION_DENIED;
            }

            byte file_id = DataIn.GetByte(0);

            if (!CurrentApplication.SelectFile(file_id))
                return FILE_NOT_FOUND;

            if (!(CurrentApplication.CurrentFile is DesfireValueFile))
            {
                logger.debug("{0}:Not a Value file", FuncName);
                return PERMISSION_DENIED;
            }

            file = (DesfireValueFile)CurrentApplication.CurrentFile;

            switch (OpCode)
            {
                case 0x0C:
                    if (!file.Creditable(SessionKeyNumber))
                    {
                        logger.debug("{0}[0C]:Access denied for key {1:X}", FuncName, SessionKeyNumber);
                        return PERMISSION_DENIED;
                    }
                    break;
                case 0x1C:
                    if (!file.LimitedCreditable(SessionKeyNumber))
                    {
                        logger.debug("{0}[1D]:Access denied for key {1:X}", FuncName, SessionKeyNumber);
                        return PERMISSION_DENIED;
                    }
                    break;
                case 0xDC:
                    if (!file.Debitable(SessionKeyNumber))
                    {
                        logger.debug("{0}[DC]:Access denied for key {1:X}", FuncName, SessionKeyNumber);
                        return PERMISSION_DENIED;
                    }
                    break;
                default:
                    return INTERNAL_ERROR;
            }

            if (file.CommMode == COMM_MODE_PLAIN)
            {
                /* No in secure session */
                logger.debug("{0}:commMode is {1}, not in secure session (key #{1:X})", FuncName, file.CommMode, SessionKeyNumber);
            }
            else if (CipherContext == null)
            {
                /* No in secure session */
                logger.debug("{0}:commMode is {1}, but not in secure session (key #{1:X})", FuncName, file.CommMode, SessionKeyNumber);
                return PERMISSION_DENIED;
            }

            byte[] data = DataIn.GetBytes(1, DataIn.Length - 1);

            logger.debug("{0}(file={1:X02}, commMode={2}, data={3})", FuncName, file.FileId, file.CommMode, BinConvert.ToHex(data));

            switch (file.CommMode)
            {
                case COMM_MODE_PLAIN:
                    if ((CipherContext != null) && ((SessionType == ESessionType.EV2)))
                    {
                        /* Increment the counter in EV2 */
                        logger.debug("{0}:Plain (EV2) [{1}]", FuncName, (CipherContext as DesfireEV2Cipher).TransactionCounter);
                        CipherContext.IncrementCounter();
                    }
                    else if ((CipherContext != null) && ((SessionType == ESessionType.EV1_TDES || SessionType == ESessionType.EV1_AES)))
                    {
                        /* Always compute a CMAC in EV1 */
                        logger.debug("{0}:Plain (EV1)", FuncName);
                        CipherContext.ComputeCmac(BinUtils.Concat(OpCode, DataIn.GetBytes()));
                    }
                    break;
                case COMM_MODE_MACED:
                    logger.debug("{0}:MACed", FuncName);
                    if (CipherContext == null)
                        return AUTHENTICATION_ERROR;
                    if (SessionType == ESessionType.EV2)
                    {
                        /* EV2 : CMAC on command + header + data */
                        if (!CipherContext.CheckCmac(BinUtils.Concat(OpCode, DataIn.GetBytes())))
                            return INTEGRITY_ERROR;
                        /* Increment the counter in EV2 */
                        CipherContext.IncrementCounter();
                    }
                    else if ((SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES))
                    {
                        /* EV1 : CMAC on command + data */
                        if (!CipherContext.CheckCmac(BinUtils.Concat(OpCode, DataIn.GetBytes())))
                            return INTEGRITY_ERROR;
                    }
                    else if (SessionType == ESessionType.EV0)
                    {
                        /* EV0 : CMAC on data only */
                        if (!CipherContext.CheckCmac(data))
                            return INTEGRITY_ERROR;
                    }
                    else
                    {
                        /* Not implemented */
                        return AUTHENTICATION_ERROR;
                    }
                    break;
                case COMM_MODE_CIPHER:
                    logger.debug("{0}:Cipher", FuncName);
                    if (CipherContext == null)
                        return AUTHENTICATION_ERROR;
                    if (SessionType == ESessionType.EV2)
                    {
                        /* EV2 : CMAC on command + header + data */
                        if (!CipherContext.CheckCmac(BinUtils.Concat(OpCode, DataIn.GetBytes())))
                            return INTEGRITY_ERROR;
                        /* EV2 : Increment the counter before deciphering */
                        CipherContext.IncrementCounter();
                        /* EV2 : Decipher the data */
                        if (!CipherContext.CipherRecv(ref data))
                            return INTEGRITY_ERROR;
                    }
                    else if ((SessionType == ESessionType.EV0) || (SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES))
                    {
                        if (!CipherContext.CipherRecv(ref data))
                            return INTEGRITY_ERROR;
                        // TODO : verify the CRC */
                    }
                    else
                    {
                        /* Not implemented */
                        return AUTHENTICATION_ERROR;
                    }
                    break;
            }

            long amount = Get4(data);

            if (amount < 0)
                return PARAMETER_ERROR;

            switch (OpCode)
            {
                case 0x0C:
                    if (!file.Credit(amount))
                        return BOUNDARY_ERROR;
                    break;

                case 0x1C:
                    if (!file.LimitedCredit(amount))
                        return BOUNDARY_ERROR;
                    break;

                case 0xDC:
                    if (!file.Debit(amount))
                        return BOUNDARY_ERROR;
                    break;

                default:
                    return INTERNAL_ERROR;
            }

            if ((CipherContext != null) && (SessionType == ESessionType.EV2))
            {
                switch (file.CommMode)
                {
                    case COMM_MODE_MACED:
                    case COMM_MODE_CIPHER:
                        if (SessionType == ESessionType.EV2)
                        {
                            /* EV2 : Add the (explicit) CMAC */
                            logger.debug("{0}:Adding CMAC EV2", FuncName);
                            byte[] cmac = CipherContext.ComputeCmac(null);
                            DataOut = new CardBuffer(cmac);
                        }
                        break;
                }
            }

            return OPERATION_OK;
        }
    }
}