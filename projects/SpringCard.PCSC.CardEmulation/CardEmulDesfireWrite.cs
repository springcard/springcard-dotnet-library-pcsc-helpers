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
using System.Text;
using System.Xml;

namespace SpringCard.PCSC.CardEmulation
{
    /// <summary>
    /// Description of PiccEmulDesfire.
    /// </summary>
    public partial class CardEmulDesfire
    {
        private class PendingWriteData : PendingCommand
        {
            public byte[] Header = null;
            public byte[] Buffer = null;
            public int Offset = 0;

            public DesfireStandardOrBackupDataFile TargetFile;
            public int TargetOffset = 0;
            public int TargetLength = 0;
        }

        public byte WriteData(CardBuffer DataIn, ref CardBuffer DataOut, bool Iso = false)
        {
            const byte OpCode = 0x3D;

            if (pendingCommand == null)
                pendingCommand = new PendingWriteData();
            if (!(pendingCommand is PendingWriteData))
                return INTERNAL_ERROR;

            PendingWriteData _pending = (PendingWriteData)pendingCommand;

            if (_pending.Iteration == 0)
            {
                if (CurrentApplication == null)
                    return PERMISSION_DENIED;

                if (!CheckIn(DataIn, 7, 64))
                    return LENGTH_ERROR;

                /* Remember the header, we'll need it for the CMAC */
                _pending.Header = BinUtils.Concat(OpCode, DataIn.GetBytes(0, 7));

                byte fileId = DataIn.GetByte(0);
                _pending.TargetOffset = (int)Get3(DataIn.GetBytes(1, 3));
                _pending.TargetLength = (int)Get3(DataIn.GetBytes(4, 3));

                if (!CurrentApplication.SelectFile(fileId))
                {
                    logger.debug("WriteData:File {0:X02} not found", fileId);
                    return FILE_NOT_FOUND;
                }

                if (!(CurrentApplication.CurrentFile is DesfireStandardOrBackupDataFile))
                {
                    logger.debug("WriteData:File {0:X02} is not a Standard or Backup data file", fileId);
                    return PERMISSION_DENIED;
                }

                if (!CurrentApplication.CurrentFile.Writable(SessionKeyNumber))
                {
                    logger.debug("WriteData:File {0:X02} is not writable", fileId);
                    return PERMISSION_DENIED;
                }

                _pending.TargetFile = (DesfireStandardOrBackupDataFile)CurrentApplication.CurrentFile;

                if (!_pending.TargetFile.MayWriteData(_pending.TargetOffset, _pending.TargetLength))
                {
                    logger.debug("WriteData:Can't write Offset={0}, Length={1} into File {0:X02}", fileId, _pending.TargetOffset, _pending.TargetLength);
                    return BOUNDARY_ERROR;
                }

                if ((_pending.TargetFile.CommMode != COMM_MODE_PLAIN) && (CipherContext == null))
                {
                    /* No in secure session */
                    logger.debug("WriteData:Not in secure session");
                    return PERMISSION_DENIED;
                }

                logger.debug("WriteData(file={0:X02}, commMode={1}, offset={2}, length={3})", _pending.TargetFile.FileId, _pending.TargetFile.CommMode, _pending.TargetOffset, _pending.TargetLength);

                long in_length = _pending.TargetLength;
                switch (_pending.TargetFile.CommMode)
                {
                    case COMM_MODE_PLAIN:
                        break;
                    case COMM_MODE_MACED:
                        in_length += CipherContext.GetCmacSize();
                        break;
                    case COMM_MODE_CIPHER:
                        if (SessionType == ESessionType.EV2)
                        {
                            in_length += 1; /* Padding is mandatory */
                            while ((in_length % CipherContext.GetBlockSize()) != 0)
                                in_length++;
                            in_length += CipherContext.GetCmacSize();
                        }
                        else if ((SessionType == ESessionType.EV0) || (SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES))
                        {
                            in_length += CipherContext.GetCrcSize();
                            while ((in_length % CipherContext.GetBlockSize()) != 0)
                                in_length++;
                        }
                        break;
                    default:
                        break;
                }

                logger.debug("WriteData: allocating {0}B for data ({1}B) and overhead", in_length, _pending.TargetLength);
                _pending.Buffer = new byte[in_length];

                for (long i = 7; i < DataIn.Length; i++)
                {
                    if (_pending.Offset >= _pending.Buffer.Length)
                    {
                        logger.debug("WriteData: buffer overflow after {0}B", _pending.Buffer.Length);
                        return LENGTH_ERROR;
                    }
                    _pending.Buffer[_pending.Offset++] = DataIn.GetByte(i);
                }
            }
            else
            {
                if (!CheckIn(DataIn, 0, 64))
                    return LENGTH_ERROR;

                logger.debug("WriteData(next)");

                for (long i = 0; i < DataIn.Length; i++)
                {
                    if (_pending.Offset >= _pending.Buffer.Length)
                    {
                        logger.debug("WriteData: buffer overflow after {0}B", _pending.Buffer.Length);
                        return LENGTH_ERROR;
                    }
                    _pending.Buffer[_pending.Offset++] = DataIn.GetByte(i);
                }
            }

            logger.debug("WriteData: {0}", BinConvert.ToHex(_pending.Buffer, 0, _pending.Offset));

            if (_pending.Buffer.Length > _pending.Offset)
            {
                logger.debug("WriteData(continue) ({0}<{1})", _pending.Offset, _pending.Buffer.Length);
                return ADDITIONAL_FRAME;
            }

            switch (_pending.TargetFile.CommMode)
            {
                case COMM_MODE_PLAIN:
                    if ((CipherContext != null) && (SessionType == ESessionType.EV2))
                    {
                        /* Increment the counter in EV2 */
                        logger.debug("WriteData:Plain (EV2) [{0}]", (CipherContext as DesfireEV2Cipher).TransactionCounter);
                        CipherContext.IncrementCounter();
                    }
                    if ((CipherContext != null) && ((SessionType == ESessionType.EV1_TDES || SessionType == ESessionType.EV1_AES)))
                    {
                        /* In EV1 mode, we must manage the CMAC, even in plain mode */
                        logger.trace("WriteData:Plain (EV1)");
                        CipherContext.ComputeCmac(BinUtils.Concat(_pending.Header, _pending.Buffer));
                    }
                    else
                    {
                        logger.trace("WriteData:Plain");
                    }
                    break;
                case COMM_MODE_MACED:
                    logger.trace("WriteData:MACed");
                    if (CipherContext == null)
                        return AUTHENTICATION_ERROR;
                    if (SessionType == ESessionType.EV2)
                    {
                        /* EV2 : CMAC on command + header + data */
                        if (!CipherContext.CheckCmac(BinUtils.Concat(_pending.Header, _pending.Buffer)))
                            return INTEGRITY_ERROR;
                        /* EV2 : Increment the counter */
                        CipherContext.IncrementCounter();
                    }
                    else if ((SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES))
                    {
                        /* EV1 : CMAC on header + data */
                        if (!CipherContext.CheckCmac(BinUtils.Concat(_pending.Header, _pending.Buffer)))
                            return INTEGRITY_ERROR;
                    }
                    else if (SessionType == ESessionType.EV0)
                    {
                        /* EV0 : CMAC on data only */
                        if (!CipherContext.CheckCmac(_pending.Buffer))
                            return INTEGRITY_ERROR;
                    }
                    else
                    {
                        return AUTHENTICATION_ERROR;
                    }
                    break;
                case COMM_MODE_CIPHER:
                    logger.debug("WriteData:Cipher");
                    if (CipherContext == null)
                        return AUTHENTICATION_ERROR;
                    if (SessionType == ESessionType.EV2)
                    {
                        /* EV2 : CMAC on command + header + data */
                        if (!CipherContext.CheckCmac(BinUtils.Concat(_pending.Header, _pending.Buffer)))
                            return INTEGRITY_ERROR;
                        /* EV2 : Increment the counter before deciphering */
                        CipherContext.IncrementCounter();
                        /* EV2 : Decipher the data */
                        if (!CipherContext.CipherRecv(ref _pending.Buffer))
                            return INTEGRITY_ERROR;
                    }
                    else if ((SessionType == ESessionType.EV0) || (SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES))
                    {
                        if (!CipherContext.CipherRecv(ref _pending.Buffer))
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

            _pending.TargetFile.WriteData(_pending.TargetOffset, _pending.Buffer, _pending.TargetLength);

            if ((CipherContext != null) && (SessionType == ESessionType.EV2))
            {
                switch (_pending.TargetFile.CommMode)
                {
                    case COMM_MODE_MACED:
                    case COMM_MODE_CIPHER:
                        if (SessionType == ESessionType.EV2)
                        {
                            /* EV2 : Add the (explicit) CMAC */
                            logger.trace("Adding CMAC (EV2) after WriteData");
                            byte[] cmac = CipherContext.ComputeCmac(null);
                            logger.trace("CMAC (EV2) {0} [{1}]", BinConvert.ToHex(cmac), (CipherContext as DesfireEV2Cipher).TransactionCounter);
                            DataOut = new CardBuffer(cmac);
                        }
                        break;
                }
            }

            return OPERATION_OK;
        }

        private class PendingWriteRecord : PendingCommand
        {
            public byte[] Header = null;
            public byte[] Buffer = null;
            public int Offset = 0;

            public LinearOrCyclicRecordFile TargetFile;
            public int TargetOffset = 0;
            public int TargetLength = 0;
        }

        public byte WriteRecord(CardBuffer DataIn, ref CardBuffer DataOut, bool Iso = false)
        {
            const byte OpCode = 0x3B;

            if (pendingCommand == null)
                pendingCommand = new PendingWriteRecord();
            if (!(pendingCommand is PendingWriteRecord))
                return INTERNAL_ERROR;

            PendingWriteRecord _pending = (PendingWriteRecord)pendingCommand;

            if (_pending.Iteration == 0)
            {
                if (CurrentApplication == null)
                    return PERMISSION_DENIED;
                if (!CheckIn(DataIn, 7, 64))
                    return LENGTH_ERROR;

                /* Remember the header, we'll need it for the CMAC */
                _pending.Header = BinUtils.Concat(OpCode, DataIn.GetBytes(0, 7));

                byte fileId = DataIn.GetByte(0);
                _pending.TargetOffset = (int)Get3(DataIn.GetBytes(1, 3));
                _pending.TargetLength = (int)Get3(DataIn.GetBytes(4, 3));

                if (!CurrentApplication.SelectFile(fileId))
                {
                    logger.debug("WriteRecord:File {0:X02} not found", fileId);
                    return FILE_NOT_FOUND;
                }

                if (!(CurrentApplication.CurrentFile is LinearOrCyclicRecordFile))
                {
                    logger.debug("WriteRecord:File {0:X02} is not a Linear or Cyclic record file", fileId);
                    return PERMISSION_DENIED;
                }

                _pending.TargetFile = (LinearOrCyclicRecordFile)CurrentApplication.CurrentFile;

                if (_pending.TargetFile.ClearPending)
                {
                    logger.debug("WriteRecord:File {0:X02} has a not commited clear operation", fileId);
                    return PERMISSION_DENIED;
                }

                if (!_pending.TargetFile.MayWriteRecord(_pending.TargetOffset, _pending.TargetLength))
                {
                    logger.debug("WriteRecord:Can't write Offset={0}, Length={1} into File {0:X02}", fileId, _pending.TargetOffset, _pending.TargetLength);
                    return BOUNDARY_ERROR;
                }

                if ((_pending.TargetFile.CommMode != COMM_MODE_PLAIN) && (CipherContext == null))
                {
                    /* No in secure session */
                    logger.debug("WriteRecord:Not in secure session");
                    return PERMISSION_DENIED;
                }

                logger.debug("WriteRecord(file={0:X02}, commMode={1}, offset={2}, length={3})", _pending.TargetFile.FileId, _pending.TargetFile.CommMode, _pending.TargetOffset, _pending.TargetLength);

                long in_length = _pending.TargetLength;
                switch (_pending.TargetFile.CommMode)
                {
                    case COMM_MODE_PLAIN:
                        break;
                    case COMM_MODE_MACED:
                        in_length += CipherContext.GetCmacSize();
                        break;
                    case COMM_MODE_CIPHER:
                        if (SessionType == ESessionType.EV2)
                        {
                            in_length += 1; /* Padding is mandatory */
                            while ((in_length % CipherContext.GetBlockSize()) != 0)
                                in_length++;
                            in_length += CipherContext.GetCmacSize();
                        }
                        else if ((SessionType == ESessionType.EV0) || (SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES))
                        {
                            in_length += CipherContext.GetCrcSize();
                            while ((in_length % CipherContext.GetBlockSize()) != 0)
                                in_length++;
                        }
                        break;
                    default:
                        break;
                }

                logger.debug("WriteRecord: allocating {0}B for data ({1}B) and overhead", in_length, _pending.TargetLength);
                _pending.Buffer = new byte[in_length];

                for (long i = 7; i < DataIn.Length; i++)
                {
                    if (_pending.Offset >= _pending.Buffer.Length)
                    {
                        logger.debug("WriteRecord: buffer overflow after {0}B", _pending.Buffer.Length);
                        return LENGTH_ERROR;
                    }
                    _pending.Buffer[_pending.Offset++] = DataIn.GetByte(i);
                }

            }
            else
            {
                if (!CheckIn(DataIn, 0, 64))
                    return LENGTH_ERROR;

                logger.debug("WriteRecord(next)");

                for (long i = 0; i < DataIn.Length; i++)
                {
                    if (_pending.Offset >= _pending.Buffer.Length)
                    {
                        logger.debug("WriteRecord: buffer overflow after {0}B", _pending.Buffer.Length);
                        return LENGTH_ERROR;
                    }
                    _pending.Buffer[_pending.Offset++] = DataIn.GetByte(i);
                }
            }

            logger.debug("WriteRecord: {0}", BinConvert.ToHex(_pending.Buffer, 0, _pending.Offset));

            if (_pending.Buffer.Length > _pending.Offset)
            {
                logger.debug("WriteRecord(continue) ({0}<{1})", _pending.Offset, _pending.Buffer.Length);
                return ADDITIONAL_FRAME;
            }

            switch (_pending.TargetFile.CommMode)
            {
                case COMM_MODE_PLAIN:
                    if ((CipherContext != null) && ((SessionType == ESessionType.EV2)))
                    {
                        /* Increment the counter in EV2 */
                        logger.debug("WriteRecord:Plain (EV2) [{0}]", (CipherContext as DesfireEV2Cipher).TransactionCounter);
                        CipherContext.IncrementCounter();
                    }
                    if ((CipherContext != null) && ((SessionType == ESessionType.EV1_TDES || SessionType == ESessionType.EV1_AES)))
                    {
                        /* In EV1 mode, we must manage the CMAC, even in plain mode */
                        logger.trace("WriteRecord:Plain (EV1)");
                        CipherContext.ComputeCmac(BinUtils.Concat(_pending.Header, _pending.Buffer));
                    }
                    else
                    {
                        logger.trace("WriteRecord:Plain");
                    }
                    break;
                case COMM_MODE_MACED:
                    logger.trace("WriteRecord:MACed");
                    if (CipherContext == null)
                        return AUTHENTICATION_ERROR;
                    if (SessionType == ESessionType.EV2)
                    {
                        /* EV2 : CMAC on command + header + data */
                        if (!CipherContext.CheckCmac(BinUtils.Concat(_pending.Header, _pending.Buffer)))
                            return INTEGRITY_ERROR;
                        /* EV2 : Increment the counter */
                        CipherContext.IncrementCounter();
                    }
                    else if ((SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES))
                    {
                        /* EV1 : CMAC on header + data */
                        if (!CipherContext.CheckCmac(BinUtils.Concat(_pending.Header, _pending.Buffer)))
                            return INTEGRITY_ERROR;
                    }
                    else if (SessionType == ESessionType.EV0)
                    {
                        /* EV0 : CMAC on data only */
                        if (!CipherContext.CheckCmac(_pending.Buffer))
                            return INTEGRITY_ERROR;
                    }
                    else
                    {
                        return AUTHENTICATION_ERROR;
                    }
                    break;
                case COMM_MODE_CIPHER:
                    logger.debug("WriteRecord:Cipher");
                    if (CipherContext == null)
                        return AUTHENTICATION_ERROR;
                    if (SessionType == ESessionType.EV2)
                    {
                        /* EV2 : CMAC on command + header + data */
                        if (!CipherContext.CheckCmac(BinUtils.Concat(_pending.Header, _pending.Buffer)))
                            return INTEGRITY_ERROR;
                        /* EV2 : Increment the counter before deciphering */
                        CipherContext.IncrementCounter();
                        /* EV2 : Decipher the data */
                        if (!CipherContext.CipherRecv(ref _pending.Buffer))
                            return INTEGRITY_ERROR;
                    }
                    else if ((SessionType == ESessionType.EV0) || (SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES))
                    {
                        if (!CipherContext.CipherRecv(ref _pending.Buffer))
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

            _pending.TargetFile.WriteRecord(_pending.TargetOffset, _pending.Buffer, _pending.TargetLength);

            if ((CipherContext != null) && (SessionType == ESessionType.EV2))
            {
                switch (_pending.TargetFile.CommMode)
                {
                    case COMM_MODE_MACED:
                    case COMM_MODE_CIPHER:
                        if (SessionType == ESessionType.EV2)
                        {
                            /* EV2 : Add the (explicit) CMAC */
                            logger.trace("Adding CMAC (EV2) after WriteRecord");
                            byte[] cmac = CipherContext.ComputeCmac(null);
                            logger.trace("CMAC (EV2) {0} [{1}]", BinConvert.ToHex(cmac), (CipherContext as DesfireEV2Cipher).TransactionCounter);
                            DataOut = new CardBuffer(cmac);
                        }
                        break;
                }
            }

            return OPERATION_OK;
        }

        public byte UpdateRecord(CardBuffer DataIn, ref CardBuffer DataOut, bool Iso = false)
        {
            logger.error("UpdateRecord not implemented, using WriteRecord instead");
            return WriteRecord(DataIn, ref DataOut, Iso);
        }
    }
}
