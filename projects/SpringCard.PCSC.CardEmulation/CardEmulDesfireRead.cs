/*
 * Crée par SharpDevelop.
 * Utilisateur: johann
 * Date: 05/01/2012
 * Heure: 12:02
 * 
 * Pour changer ce modèle utiliser Outils | Options | Codage | Editer les en-têtes standards.
 */
using SpringCard.LibCs;

namespace SpringCard.PCSC.CardEmulation
{
    public partial class CardEmulDesfire
    {
        private class PendingReadData : PendingCommand
        {
            public byte FileId;
            public int ReadOffset;
            public int ReadLength;
            public byte[] Buffer = null;
            public long Offset = 0;
        }

        public byte ReadData(CardBuffer DataIn, ref CardBuffer DataOut, bool Iso = false)
        {
            byte OpCode = Iso ? (byte)0xAD : (byte)0xBD;

            if (pendingCommand == null)
                pendingCommand = new PendingReadData();
            if (!(pendingCommand is PendingReadData))
                return INTERNAL_ERROR;

            PendingReadData _pending = (PendingReadData)pendingCommand;

            if (_pending.Iteration == 0)
            {
                if (!CheckIn(DataIn, 7, 7 + 8))
                    return LENGTH_ERROR;

                if (CurrentApplication == null)
                {
                    logger.debug("ReadData:No application");
                    return PERMISSION_DENIED;
                }

                _pending.FileId = DataIn.GetByte(0);
                _pending.ReadOffset = (int)Get3(DataIn.GetBytes(1, 3));
                _pending.ReadLength = (int)Get3(DataIn.GetBytes(4, 3));
                bool padd80 = false;

                if (!CurrentApplication.SelectFile(_pending.FileId))
                    return FILE_NOT_FOUND;

                if (!(CurrentApplication.CurrentFile is DesfireStandardOrBackupDataFile))
                {
                    logger.debug("ReadData:File is not Standard or Backup");
                    return PERMISSION_DENIED;
                }

                DesfireStandardOrBackupDataFile file = (DesfireStandardOrBackupDataFile)CurrentApplication.CurrentFile;

                if (_pending.ReadLength == 0)
                {
                    padd80 = true;
                    if (_pending.ReadOffset >= file.Size)
                        return BOUNDARY_ERROR;
                    _pending.ReadLength = file.Size - _pending.ReadOffset;
                }

                if (_pending.ReadOffset + _pending.ReadLength > file.Size)
                    return BOUNDARY_ERROR;

                _pending.Buffer = file.ReadData(_pending.ReadOffset, _pending.ReadLength);

                logger.debug("ReadData:Plain content is {0}", BinConvert.ToHex(_pending.Buffer));

                if ((file.CommMode != COMM_MODE_PLAIN) && (CipherContext == null))
                {
                    /* No in secure session */
                    logger.debug("ReadData:Not in secure session");
                    return PERMISSION_DENIED;
                }

                switch (file.CommMode)
                {
                    case COMM_MODE_PLAIN:
                        if ((CipherContext != null) && ((SessionType == ESessionType.EV2)))
                        {
                            /* Increment the counter in EV2 */
                            logger.debug("ReadData:Plain (EV2) [{0}]", (CipherContext as DesfireEV2Cipher).TransactionCounter);
                            CipherContext.IncrementCounter();
                        }
                        else if ((CipherContext != null) && ((SessionType == ESessionType.EV1_TDES || SessionType == ESessionType.EV1_AES)))
                        {
                            /* Always add a CMAC in EV1 */
                            logger.debug("ReadData:Plain (EV1)");
                            if (CipherContext == null)
                                return INTERNAL_ERROR;
                            CipherContext.AppendCmac(ref _pending.Buffer);
                        }
                        else
                        {
                            logger.debug("ReadData:Plain");
                        }
                        break;
                    case COMM_MODE_MACED:
                        logger.debug("ReadData:MACed");
                        if (CipherContext == null)
                            return AUTHENTICATION_ERROR;
                        if (SessionType == ESessionType.EV2)
                        {
                            /* Check the CMAC on input */
                            byte[] t = BinUtils.Concat(OpCode, DataIn.GetBytes());
                            if (!CipherContext.CheckCmac(t))
                                return INTEGRITY_ERROR;
                        }
                        /* Increment the counter before answering */
                        CipherContext.IncrementCounter();
                        /* Add a CMAC to the output */
                        CipherContext.AppendCmac(ref _pending.Buffer);
                        break;
                    case COMM_MODE_CIPHER:
                        logger.debug("ReadData:Cipher");
                        if (CipherContext == null)
                            return AUTHENTICATION_ERROR;
                        if (SessionType == ESessionType.EV2)
                        {
                            /* Check the CMAC on input */
                            byte[] t = BinUtils.Concat(OpCode, DataIn.GetBytes());
                            if (!CipherContext.CheckCmac(t))
                                return INTEGRITY_ERROR;
                            /* Increment the counter before answering */
                            CipherContext.IncrementCounter();
                            /* Cipher the output */
                            if (!CipherContext.CipherSend(ref _pending.Buffer))
                                return INTERNAL_ERROR;
                            /* Add a CMAC to the ciphered output */
                            CipherContext.AppendCmac(ref _pending.Buffer);
                        }
                        else if ((SessionType == ESessionType.EV0) || (SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES))
                        {
                            CipherContext.AppendCrc(ref _pending.Buffer);
                            if (padd80)
                            {
                                if (!CipherContext.Padd(ref _pending.Buffer)) // JDA TODO: Check if this is correct
                                    return INTERNAL_ERROR;
                            }
                            if (!CipherContext.CipherSend(ref _pending.Buffer))
                                return INTERNAL_ERROR;
                        }
                        break;
                }
            }

            bool chaining = false;
            long length = _pending.Buffer.Length - _pending.Offset;
            if (length > SendMaxSize())
            {
                chaining = true;
                length = SendMaxSize();
            }

            logger.debug("ReadData({0:X02},{1},{2})->{3}/{4} [{5}]", _pending.FileId, _pending.ReadOffset, _pending.ReadLength, _pending.Buffer.Length, length, _pending.Iteration);

            DataOut = new CardBuffer(_pending.Buffer, _pending.Offset, length);

            _pending.Offset += length;

            if (chaining)
                return ADDITIONAL_FRAME;
            return OPERATION_OK;
        }

        private class PendingReadRecords : PendingCommand
        {
            public byte FileId;
            public int FirstRecord;
            public int MaxCount;
            public byte[] Buffer = null;
            public long Offset = 0;
        }

        public byte ReadRecords(CardBuffer DataIn, ref CardBuffer DataOut, bool Iso = false)
        {
            byte OpCode = Iso ? (byte)0xAB : (byte)0xBB;

            if (pendingCommand == null)
                pendingCommand = new PendingReadRecords();
            if (!(pendingCommand is PendingReadRecords))
                return INTERNAL_ERROR;

            PendingReadRecords _pending = (PendingReadRecords)pendingCommand;

            if (_pending.Iteration == 0)
            {
                if (!CheckIn(DataIn, 7, 7 + 8))
                    return LENGTH_ERROR;

                if (CurrentApplication == null)
                {
                    logger.debug("ReadRecords:No application");
                    return PERMISSION_DENIED;
                }

                _pending.FileId = DataIn.GetByte(0);
                _pending.FirstRecord = (int)Get3(DataIn.GetBytes(1, 3));
                _pending.MaxCount = (int)Get3(DataIn.GetBytes(4, 3));
                bool padd80 = false;

                if (!CurrentApplication.SelectFile(_pending.FileId))
                    return FILE_NOT_FOUND;

                if (!(CurrentApplication.CurrentFile is LinearOrCyclicRecordFile))
                {
                    logger.debug("ReadRecords:File is not Linear or Cyclic");
                    return PERMISSION_DENIED;
                }

                LinearOrCyclicRecordFile file = (LinearOrCyclicRecordFile)CurrentApplication.CurrentFile;

                if (_pending.MaxCount == 0)
                    padd80 = true;

                byte r = file.ReadRecords(_pending.FirstRecord, _pending.MaxCount, out _pending.Buffer);
                if (r != OPERATION_OK)
                    return r;

                if ((file.CommMode != COMM_MODE_PLAIN) && (CipherContext == null))
                {
                    /* No in secure session */
                    logger.debug("ReadRecords:Not in secure session");
                    return PERMISSION_DENIED;
                }

                switch (file.CommMode)
                {
                    case COMM_MODE_PLAIN:
                        if ((CipherContext != null) && ((SessionType == ESessionType.EV2)))
                        {
                            /* Increment the counter in EV2 */
                            logger.debug("ReadRecords:Plain (EV2) [{0}]", (CipherContext as DesfireEV2Cipher).TransactionCounter);
                            CipherContext.IncrementCounter();
                        }
                        else if ((CipherContext != null) && ((SessionType == ESessionType.EV1_TDES || SessionType == ESessionType.EV1_AES)))
                        {
                            /* Always add a CMAC in EV1 */
                            logger.debug("ReadRecords:Plain (EV1)");
                            if (CipherContext == null)
                                return INTERNAL_ERROR;
                            CipherContext.AppendCmac(ref _pending.Buffer);
                        }
                        else
                        {
                            logger.debug("ReadRecords:Plain");
                        }
                        break;
                    case COMM_MODE_MACED:
                        logger.debug("ReadRecords:CMAC");
                        if (CipherContext == null)
                            return INTERNAL_ERROR;
                        if (SessionType == ESessionType.EV2)
                        {
                            /* Check the CMAC on input */
                            byte[] t = BinUtils.Concat(OpCode, DataIn.GetBytes());
                            if (!CipherContext.CheckCmac(t))
                                return INTEGRITY_ERROR;
                        }
                        /* Increment the counter before answering */
                        CipherContext.IncrementCounter();
                        /* Add a CMAC to the output */
                        CipherContext.AppendCmac(ref _pending.Buffer);
                        break;
                    case COMM_MODE_CIPHER:
                        logger.debug("ReadRecords:Cipher");
                        if (CipherContext == null)
                            return AUTHENTICATION_ERROR;
                        if (SessionType == ESessionType.EV2)
                        {
                            /* Check the CMAC on input */
                            byte[] t = BinUtils.Concat(OpCode, DataIn.GetBytes());
                            if (!CipherContext.CheckCmac(t))
                                return INTEGRITY_ERROR;
                            /* Increment the counter before answering */
                            CipherContext.IncrementCounter();
                            /* Cipher the output */
                            if (!CipherContext.CipherSend(ref _pending.Buffer))
                                return INTERNAL_ERROR;
                            /* Add a CMAC to the ciphered output */
                            CipherContext.AppendCmac(ref _pending.Buffer);
                        }
                        else if ((SessionType == ESessionType.EV0) || (SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES))
                        {
                            CipherContext.AppendCrc(ref _pending.Buffer);
                            if (padd80)
                            {
                                if (!CipherContext.Padd(ref _pending.Buffer)) // TODO: Check if this is correct
                                    return INTERNAL_ERROR;
                            }
                            if (!CipherContext.CipherSend(ref _pending.Buffer))
                                return INTERNAL_ERROR;
                        }
                        break;
                }
            }

            if (_pending.Buffer == null)
            {
                return OPERATION_OK;
            }
            else
            {
                bool chaining = false;
                long length = _pending.Buffer.Length - _pending.Offset;
                if (length > SendMaxSize())
                {
                    chaining = true;
                    length = SendMaxSize();
                }

                logger.debug("ReadRecords({0:X02},{1},{2})->{3}/{4} [{5}]", _pending.FileId, _pending.FirstRecord, _pending.MaxCount, _pending.Buffer.Length, length, _pending.Iteration);

                DataOut = new CardBuffer(_pending.Buffer, _pending.Offset, length);

                _pending.Offset += length;

                if (chaining)
                    return ADDITIONAL_FRAME;
                return OPERATION_OK;
            }
        }
    }
}
