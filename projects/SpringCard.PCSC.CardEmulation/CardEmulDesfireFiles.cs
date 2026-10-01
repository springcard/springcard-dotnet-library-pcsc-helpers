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
        protected byte ChangeFileSettings(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (CurrentApplication == null)
                return AUTHENTICATION_ERROR;

            byte[] t;

            if (DataIn.Length == 4)
            {
                t = DataIn.GetBytes(1, 3);
            }
            else if (DataIn.Length == 9)
            {
                t = DataIn.GetBytes(1, 8);
                if (!CipherContext.CipherRecv(ref t))
                    return INTEGRITY_ERROR;
            }
            else if (DataIn.Length == 17)
            {
                t = DataIn.GetBytes(1, 16);
                if (!CipherContext.CipherRecv(ref t))
                    return INTEGRITY_ERROR;
            }
            else
                return LENGTH_ERROR;

            byte Fid = DataIn.GetByte(0);
            byte CommSettings = t[0];
            ushort AccessRights = Get2(t, 1);

            if (!CurrentApplication.SelectFile(Fid))
                return FILE_NOT_FOUND;

            logger.debug("ChangeFileSettings({0:X02},{1:X02},{2:X04})", Fid, CommSettings, AccessRights);

            CurrentApplication.CurrentFile.ChangeFileSettings(CommSettings, AccessRights);

            return OPERATION_OK;
        }

        protected byte GetFileIDs(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (!CheckIn(DataIn, 0))
                return LENGTH_ERROR;

            if (CurrentApplication == null)
            {
                logger.debug("GetFileIDs:No application");
                return PERMISSION_DENIED;
            }

            int c = CurrentApplication.Files.Count;
            if (c != 0)
            {
                byte[] r = new byte[c];

                int i = 0;
                foreach (KeyValuePair<byte, DesfireFile> kvp in CurrentApplication.Files)
                    r[i++] = kvp.Key;

                DataOut = new CardBuffer(r);
            }

            return OPERATION_OK;
        }

        protected byte GetISOFileIDs(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (!CheckIn(DataIn, 0))
                return LENGTH_ERROR;

            if (CurrentApplication == null)
            {
                logger.debug("GetISOFileIDs:No application");
                return PERMISSION_DENIED;
            }

            if (pendingCommand == null)
                pendingCommand = new PendingCommand();

            List<DesfireFile> desfireFiles = new List<DesfireFile>();
            foreach (KeyValuePair<byte, DesfireFile> desfireFile in CurrentApplication.Files)
            {
                if (desfireFile.Value.IsIso)
                    desfireFiles.Add(desfireFile.Value);
            }

            byte[] result;

            switch (pendingCommand.Iteration)
            {
                case 0:
                    if (desfireFiles.Count == 0)
                        return OPERATION_OK;

                    if (desfireFiles.Count > 27)
                    {
                        result = new byte[27 * 2];
                    }
                    else
                    {
                        result = new byte[desfireFiles.Count * 2];
                    }

                    for (int i = 0; (i < desfireFiles.Count) && (i < 27); i++)
                    {
                        ushort IsoFileId = desfireFiles[i].IsoFileId;
                        result[2 * i + 0] = (byte)(IsoFileId & 0x0FF);
                        result[2 * i + 1] = (byte)((IsoFileId >> 8) & 0x0FF);
                    }

                    DataOut = new CardBuffer(result);

                    if (desfireFiles.Count > 19)
                        return ADDITIONAL_FRAME;

                    return OPERATION_OK;

                case 1:
                    if (desfireFiles.Count <= 27)
                        return INTERNAL_ERROR;

                    result = new byte[(desfireFiles.Count - 27) * 2];
                    for (int i = 0; i < (desfireFiles.Count - 27); i++)
                    {
                        ushort IsoFileId = desfireFiles[i + 27].IsoFileId;
                        result[2 * i + 0] = (byte)(IsoFileId & 0x0FF);
                        result[2 * i + 1] = (byte)((IsoFileId >> 8) & 0x0FF);
                    }

                    DataOut = new CardBuffer(result);

                    return OPERATION_OK;
            }

            return INTERNAL_ERROR;
        }

        protected byte DeleteFile(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (!CheckIn(DataIn, 1))
                return LENGTH_ERROR;

            if (CurrentApplication == null)
            {
                logger.debug("DeleteFile:No application");
                return PERMISSION_DENIED;
            }

            byte Fid = DataIn.GetByte(0);

            if (!CurrentApplication.FileExists(Fid))
                return FILE_NOT_FOUND;

            if (CurrentApplication.DeleteFile(Fid))
                return OPERATION_OK;

            return APPL_INTEGRITY_ERROR;
        }

        public abstract class DesfireFile
        {
            public enum EFileType
            {
                StandardDataFile = 0x00,
                BackupDataFile = 0x01,
                ValueFile = 0x02,
                LinearRecordFile = 0x03,
                CyclicRecordFile = 0x04,
            }

            protected CardEmulDesfire Card { get; private set; }
            public uint ApplicationAid { get; private set; }
            public byte FileId { get; private set; }
            protected string FileName
            {
                get
                {
                    return String.Format("{0:X06}.{1:X02}", ApplicationAid, FileId);
                }
            }

            public bool IsIso { get; private set; }
            public ushort IsoFileId { get; private set; }

            public void SetIso(ushort IsoFileId)
            {
                this.IsIso = true;
                this.IsoFileId = IsoFileId;
            }

            public int ByteCount { get; protected set; }

            public EFileType FileType { get; private set; }
            public byte CommMode { get; private set; }
            public ushort AccessRights { get; private set; }

            public virtual bool Readable(byte SessionKeyNumber)
            {
                byte readAccess = (byte)((AccessRights >> 12) & 0x0F);
                byte readWriteAccess = (byte)((AccessRights >> 4) & 0x0F);
                Card.logger.debug("Is file {0:X02} readable with key {1:X02}? {2:X04} R={3:X02} R/W={4:X02}", FileId, SessionKeyNumber, AccessRights, readAccess, readWriteAccess);
                if ((readAccess == 0x0E) || (readWriteAccess == 0x0E))
                    return true;
                if ((SessionKeyNumber == readAccess) || (SessionKeyNumber == readWriteAccess))
                    return true;
                return false;
            }

            public bool Writable(byte SessionKeyNumber)
            {
                byte writeAccess = (byte)((AccessRights >> 8) & 0x0F);
                byte readWriteAccess = (byte)((AccessRights >> 4) & 0x0F);
                Card.logger.debug("Is file {0:X02} writable with key {1:X02}? {2:X04} W={3:X02} R/W={4:X02}", FileId, SessionKeyNumber, AccessRights, writeAccess, readWriteAccess);
                if ((writeAccess == 0x0E) || (readWriteAccess == 0x0E))
                    return true;
                if ((SessionKeyNumber == writeAccess) || (SessionKeyNumber == readWriteAccess))
                    return true;
                return false;
            }

            public bool Manageable(byte SessionKeyNumber)
            {
                byte manageAccess = (byte)((AccessRights >> 0) & 0x0F);
                Card.logger.debug("Is file {0:X02} manageable with key {1:X02}? {2:X04} M={3:X02}", FileId, SessionKeyNumber, AccessRights, manageAccess);
                if (manageAccess == 0x0E)
                    return true;
                if (SessionKeyNumber == manageAccess)
                    return true;
                return false;
            }

            public void SetMetaData(CardEmulDesfire Card, uint ApplicationAid, byte FileId)
            {
                this.Card = Card;
                this.ApplicationAid = ApplicationAid;
                this.FileId = FileId;
            }

            protected DesfireFile(EFileType FileType)
            {
                this.FileType = FileType;
            }

            protected DesfireFile(EFileType FileType, byte CommMode, ushort AccessRights)
            {
                this.FileType = FileType;
                this.CommMode = CommMode;
                this.AccessRights = AccessRights;
            }

            public void ChangeFileSettings(byte CommMode, ushort AccessRights)
            {
                this.CommMode = CommMode;
                this.AccessRights = AccessRights;
            }

            protected abstract byte[] GetFileSettingsEx();

            public byte[] GetFileSettings()
            {
                byte[] r = new byte[4];

                r[0] = (byte)FileType;
                r[1] = CommMode;
                r[2] = (byte)(AccessRights % 0x0100);
                r[3] = (byte)((AccessRights / 0x0100) % 0x0100);

                r = BinUtils.Concat(r, GetFileSettingsEx());

                Card.logger.trace("GetFileSettings({0:X02}) -> {1}", FileId, BinConvert.ToHex(r));

                return r;
            }


            public virtual bool Commit() { return true;  }
            public virtual bool Abort() { return true; }

            public JObject ToJObject()
            {
                JObject result = new JObject
                {
                    ["ID"] = string.Format("{0:X02}", FileId),
                    ["Type"] = FileType.ToString(),
                    ["CommMode"] = String.Format("{0:X02}", CommMode),
                    ["AccessRights"] = String.Format("{0:X04}", AccessRights),
                };

                return result;
            }

        }

        public class DesfireValueFile : DesfireFile
        {
            public long LowerLimit { get; protected set; }
            public long UpperLimit { get; protected set; }
            public long Value { get; protected set; } = 0;
            long pendingValue = 0;
            public long LimitedCreditValue { get; protected set; } = 0;
            public bool LimitedCreditEnabled { get; protected set; } = false;
            public bool FreeGetValue { get; protected set; } = false;

            public DesfireValueFile(byte CommSettings, ushort AccessRights, long LowerLimit, long UpperLimit, long Value, bool LimitedCreditEnabled, bool FreeGetValue) : base(EFileType.ValueFile, CommSettings, AccessRights)
            {
                this.LowerLimit = LowerLimit;
                this.UpperLimit = UpperLimit;
                this.Value = Value;
                pendingValue = Value;
                this.LimitedCreditEnabled = LimitedCreditEnabled;
                this.FreeGetValue = FreeGetValue;

                /* Consider every value file requires 16 bytes */
                this.ByteCount = 16;
            }

            public override bool Readable(byte SessionKeyNumber)
            {
                if (FreeGetValue)
                {
                    Card.logger.debug("File {0:X02} -> free GetValue", FileId);
                    return true;
                }

                return base.Readable(SessionKeyNumber);
            }

            public bool Debitable(byte SessionKeyNumber)
            {
                byte readAccess = (byte)((AccessRights >> 12) & 0x0F);
                byte writeAccess = (byte)((AccessRights >> 8) & 0x0F);
                byte readWriteAccess = (byte)((AccessRights >> 4) & 0x0F);
                Card.logger.debug("Is file {0:X02} debitable with key {1:X02}? {2:X04} R={3:X02} W={4:X02} R/W={5:X02}", FileId, SessionKeyNumber, AccessRights, readAccess, writeAccess, readWriteAccess);
                if ((readAccess == 0x0E) || (readWriteAccess == 0x0E))
                    return true;
                if ((SessionKeyNumber == readAccess) || (SessionKeyNumber == writeAccess) || (SessionKeyNumber == readWriteAccess))
                    return true;
                return false;
            }

            public bool LimitedCreditable(byte SessionKeyNumber)
            {
                if (!LimitedCreditEnabled)
                {
                    Card.logger.debug("File {0:X02} -> no limited credit", FileId);
                    return false;
                }

                byte writeAccess = (byte)((AccessRights >> 8) & 0x0F);
                byte readWriteAccess = (byte)((AccessRights >> 4) & 0x0F);

                Card.logger.debug("Is file {0:X02} limited creditable with key {1:X02}? {2:X04} W={3:X02} R/W={4:X02}", FileId, SessionKeyNumber, AccessRights, writeAccess, readWriteAccess);
                if ((writeAccess == 0x0E) || (readWriteAccess == 0x0E))
                    return true;
                if ((SessionKeyNumber == writeAccess) || (SessionKeyNumber == readWriteAccess))
                    return true;
                return false;
            }

            public bool Creditable(byte SessionKeyNumber)
            {
                byte readWriteAccess = (byte)((AccessRights >> 4) & 0x0F);
                Card.logger.debug("Is file {0:X02} creditable with key {1:X02}? {2:X04} R/W={3:X02}", FileId, SessionKeyNumber, AccessRights, readWriteAccess);
                if (readWriteAccess == 0x0E)
                    return true;
                if (SessionKeyNumber == readWriteAccess)
                    return true;
                return false;
            }

            protected override byte[] GetFileSettingsEx()
            {
                byte[] r = new byte[13];

                r[0] = (byte)((LowerLimit) & 0x0FF);
                r[1] = (byte)((LowerLimit >> 8) & 0x0FF);
                r[2] = (byte)((LowerLimit >> 16) & 0x0FF);
                r[3] = (byte)((LowerLimit >> 24) & 0x0FF);

                r[4] = (byte)((UpperLimit) & 0x0FF);
                r[5] = (byte)((UpperLimit >> 8) & 0x0FF);
                r[6] = (byte)((UpperLimit >> 16) & 0x0FF);
                r[7] = (byte)((UpperLimit >> 24) & 0x0FF);

                r[8] = (byte)((LimitedCreditValue) & 0x0FF);
                r[9] = (byte)((LimitedCreditValue >> 8) & 0x0FF);
                r[10] = (byte)((LimitedCreditValue >> 16) & 0x0FF);
                r[11] = (byte)((LimitedCreditValue >> 24) & 0x0FF);

                r[12] = (byte)(LimitedCreditEnabled ? 1 : 0);

                return r;
            }

            public override bool Commit()
            {
                Card.logger.debug("Commit ValueFile {0:X02} {1:D}", FileId, pendingValue);
                Value = pendingValue;
                return true;
            }

            public override bool Abort()
            {
                if (pendingValue != Value)
                {
                    Card.logger.debug("Abort ValueFile {0:X02}", FileId);
                    pendingValue = Value;
                }
                return true;
            }


            public bool LimitedCredit(long val)
            {
                if (val <= 0)
                    return false;

                pendingValue += val;
                return true;
            }

            public bool Credit(long val)
            {
                if (val <= 0)
                    return false;

                pendingValue += val;
                return true;
            }

            public bool Debit(long val)
            {
                if (val <= 0)
                    return false;

                pendingValue -= val;
                return true;
            }
        }

        public abstract class DesfireStandardOrBackupDataFile : DesfireFile
        {
            public int Size { get; private set; }
            protected byte[] Content;

            protected DesfireStandardOrBackupDataFile(EFileType FileType, byte CommSettings, ushort AccessRights, int Size) : base(FileType, CommSettings, AccessRights)
            {
                this.Size = Size;
                Content = new byte[Size];
            }

            protected override byte[] GetFileSettingsEx()
            {
                byte[] r = new byte[3];

                r[0] = (byte)((Size) & 0x0FF);
                r[1] = (byte)((Size >> 8) & 0x0FF);
                r[2] = (byte)((Size >> 16) & 0x0FF);

                return r;
            }

            public abstract void WriteData(int offset, byte[] bytes, int length);

            public void WriteData(int offset, byte[] bytes)
            {
                if (offset < bytes.Length)
                    WriteData(offset, bytes, bytes.Length - offset);
            }

            public byte[] ReadData(int offset, int length)
            {
                byte[] r = new byte[length];

                for (int i = 0; i < r.Length; i++)
                    r[i] = Content[offset + i];

                return r;
            }

            public byte[] ReadData(int offset)
            {
                return ReadData(offset, Size - offset);
            }

            public byte[] ReadData()
            {
                return ReadData(0, Size);
            }

            public bool MayWriteData(int offset, int length)
            {
                if (offset + length > Size)
                    return false;

                return true;
            }
        }

        protected virtual byte CreateDataFile(bool Backup, CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (CurrentApplication == null)
            {
                logger.debug("CreateDataFile:No application");
                return PERMISSION_DENIED;
            }

            bool isIso = false;

            if (CheckIn(DataIn, 7))
            {

            }
            else if (CheckIn(DataIn, 9))
            {
                isIso = true;
            }
            else
            {
                return LENGTH_ERROR;
            }

            int offset = 0;

            byte fileId = DataIn.GetByte(offset++);
            ushort isoFileId = 0;
            if (isIso)
                isoFileId = (ushort) (DataIn.GetByte(offset++) | (DataIn.GetByte(offset++) << 8));
            byte commSettings = DataIn.GetByte(offset++);
            ushort accessRights = Get2(DataIn.GetBytes(offset, 2)); offset += 2;
            int size = (int)Get3(DataIn.GetBytes(offset, 3)); offset += 3;

            if (CurrentApplication.FileExists(fileId))
                return DUPLICATE_ERROR;

            DesfireFile file;

            if (Backup)
                file = new DesfireBackupDataFile(commSettings, accessRights, size);
            else
                file = new StandardFile(commSettings, accessRights, size);
            file.SetMetaData(this, CurrentApplication.Aid, fileId);

            if (isIso)
                file.SetIso(isoFileId);

            if (CurrentApplication.InsertFile(fileId, file))
                return OPERATION_OK;
            return APPL_INTEGRITY_ERROR;
        }

        public class StandardFile : DesfireStandardOrBackupDataFile
        {
            public StandardFile(byte CommSettings, ushort AccessRights, int Size) : base(EFileType.StandardDataFile, CommSettings, AccessRights, Size)
            {
                this.ByteCount = Size;
            }

            public override void WriteData(int offset, byte[] bytes, int length)
            {
                for (int i = 0; i < length; i++)
                    Content[offset + i] = bytes[i];
            }
        }

        public class DesfireBackupDataFile : DesfireStandardOrBackupDataFile
        {
            private byte[] pendingContent;

            public DesfireBackupDataFile(byte CommSettings, ushort AccessRights, int Size) : base(EFileType.BackupDataFile, CommSettings, AccessRights, Size)
            {
                this.ByteCount = 2 * Size;
                pendingContent = null;
            }

            public override void WriteData(int offset, byte[] bytes, int length)
            {
                if (pendingContent == null)
                    pendingContent = BinUtils.Copy(Content);

                for (int i = 0; i < length; i++)
                    pendingContent[offset + i] = bytes[i];
            }

            public override bool Commit()
            {
                if (pendingContent != null)
                {
                    Card.logger.debug("Commit BackupDataFile {0}", FileName);
                    Content = pendingContent;
                    pendingContent = null;
                }
                return true;
            }

            public override bool Abort()
            {
                if (pendingContent != null)
                {
                    Card.logger.debug("Abort BackupDataFile {0}", FileName);
                    pendingContent = null;
                }
                return true;
            }
        }

        public abstract class LinearOrCyclicRecordFile : DesfireFile
        {
            public int RecordSize { get; private set; }
            public int MaxRecordCount { get; private set; }

            protected List<byte[]> Records = new List<byte[]>();

            protected byte[] WritePending;
            
            public bool ClearPending { get; private set; } = false;

            protected LinearOrCyclicRecordFile(EFileType FileType, byte CommSettings, ushort AccessRights, int RecordSize, int MaxRecordCount) : base(FileType, CommSettings, AccessRights)
            {
                this.RecordSize = RecordSize;
                this.MaxRecordCount = MaxRecordCount;
                this.ByteCount = MaxRecordCount * RecordSize;

                WritePending = null;
                ClearPending = false;
            }

            protected override byte[] GetFileSettingsEx()
            {
                byte[] r = new byte[9];

                r[0] = (byte)((RecordSize) & 0x0FF);
                r[1] = (byte)((RecordSize >> 8) & 0x0FF);
                r[2] = (byte)((RecordSize >> 16) & 0x0FF);

                r[3] = (byte)((MaxRecordCount) & 0x0FF);
                r[4] = (byte)((MaxRecordCount >> 8) & 0x0FF);
                r[5] = (byte)((MaxRecordCount >> 16) & 0x0FF);

                r[6] = (byte)((Records.Count) & 0x0FF);
                r[7] = (byte)((Records.Count >> 8) & 0x0FF);
                r[8] = (byte)((Records.Count >> 16) & 0x0FF);

                return r;
            }

            public byte[] GetRecord(int index)
            {
                if (index >= MaxRecordCount)
                    return null;

                if (index >= Records.Count)
                    return new byte[RecordSize];

                return Records[index];
            }

            public byte ReadRecords(int first, int count, out byte[] data)
            {
                if (count == 0)
                    count = Records.Count;

                data = new byte[0];

                /* First code the the offset of the newest record which is read out */
                /* Count codes the number of records to be read out */
                /* Records are read in chronological order, starting with the oldest, which is count - 1 before the first */
                for (int i = 0; i < count; i++)
                {
                    int index = first + i;

                    if (index >= Records.Count)
                        return BOUNDARY_ERROR;

                    data = BinUtils.Concat(data, BinUtils.EnsureSize(Records[i], RecordSize, RecordSize));
                }


                return OPERATION_OK;
            }

            public bool MayWriteRecord(int offset, int length)
            {
                if (FileType == EFileType.CyclicRecordFile)
                {
                    /* Cyclic files can always write because we are always overwriting the oldest record */
                }
                else
                {
                    if (Records.Count >= MaxRecordCount)
                    {
                        Card.logger.debug("MayWriteRecord({0},{1}) -> false (max record count {2} reached)", offset, length, MaxRecordCount);
                        return false;
                    }
                }

                if (offset + length > RecordSize)
                {
                    Card.logger.debug("MayWriteRecord({0},{1}) -> false (record size is {2})", offset, length, RecordSize);
                    return false;
                }

                return true;
            }

            public void WriteRecord(int offset, byte[] data, int length)
            {
                if (!MayWriteRecord(offset, length))
                    return;

                if (WritePending == null)
                    WritePending = new byte[RecordSize];
                for (int i = 0; i < length; i++)
                    WritePending[offset + i] = data[i];
            }

            public void ClearRecords()
            {
                ClearPending = true;
            }

            public override bool Commit()
            {
                if (ClearPending)
                {
                    Card.logger.debug("Commit RecordFile {0} (clear)", FileName);
                    Records = new List<byte[]>();
                    WritePending = null;
                    ClearPending = false;
                }

                if (WritePending != null)
                {
                    Card.logger.debug("Commit RecordFile {0} (write)", FileName);
                    if (FileType == EFileType.CyclicRecordFile)
                        if (Records.Count >= MaxRecordCount)
                            Records.RemoveAt(0); /* Remove the oldest record */
                    Records.Add(WritePending);
                    WritePending = null;
                }

                return true;
            }

            public override bool Abort()
            {
                if (ClearPending)
                {
                    Card.logger.debug("Abort RecordFile {0} (clear)", FileName);
                    ClearPending = false;
                }

                if (WritePending != null)
                {
                    Card.logger.debug("Abort RecordFile {0} (write)", FileName);
                    WritePending = null;
                }
                return true;
            }
        }

        public class LinearRecordFile : LinearOrCyclicRecordFile
        {
            public LinearRecordFile(byte CommSettings, ushort AccessRights, int RecordSize, int RecordCount) : base(EFileType.LinearRecordFile, CommSettings, AccessRights, RecordSize, RecordCount) { }
        }

        private class CyclicRecordFile : LinearOrCyclicRecordFile
        {
            public CyclicRecordFile(byte CommSettings, ushort AccessRights, int RecordSize, int RecordCount) : base(EFileType.CyclicRecordFile, CommSettings, AccessRights, RecordSize, RecordCount) { }
        }



        protected byte CreateRecordFile(bool Cyclic, CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (CurrentApplication == null)
            {
                logger.debug("CreateRecordFile:No application");
                return PERMISSION_DENIED;
            }

            bool isIso = false;

            if (CheckIn(DataIn, 10))
            {

            }
            else if (CheckIn(DataIn, 12))
            {
                isIso = true;
            }
            else
            {
                return LENGTH_ERROR;
            }

            int offset = 0;

            byte fileId = DataIn.GetByte(offset++);
            ushort isoFileId = 0;
            if (isIso)
            {
                isoFileId = (ushort)(DataIn.GetByte(offset++) | (DataIn.GetByte(offset++) << 8));
            }
            byte commSettings = DataIn.GetByte(offset++);
            ushort accessRights = Get2(DataIn.GetBytes(offset, 2)); offset += 2;
            int recordSize = (int)Get3(DataIn.GetBytes(offset, 3)); offset += 3;
            int recordCount = (int)Get3(DataIn.GetBytes(offset, 3)); offset += 3;

            if (CurrentApplication.FileExists(fileId))
                return DUPLICATE_ERROR;

            DesfireFile file;

            if (Cyclic)
                file = new CyclicRecordFile(commSettings, accessRights, recordSize, recordCount);
            else
                file = new LinearRecordFile(commSettings, accessRights, recordSize, recordCount);
            file.SetMetaData(this, CurrentApplication.Aid, fileId);

            if (isIso)
                file.SetIso(isoFileId);

            if (CurrentApplication.InsertFile(fileId, file))
                return OPERATION_OK;
            return APPL_INTEGRITY_ERROR;
        }

        public byte ClearRecordFile(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (!CheckIn(DataIn, 1))
                return LENGTH_ERROR;

            if (CurrentApplication == null)
            {
                logger.debug("ClearRecordFile:No application");
                return PERMISSION_DENIED;
            }

            byte file_id = DataIn.GetByte(0);

            if (!CurrentApplication.SelectFile(file_id))
                return FILE_NOT_FOUND;

            if (!(CurrentApplication.CurrentFile is LinearOrCyclicRecordFile))
            {
                logger.debug("ClearRecordFile:Not a Linear or Cyclic file");
                return PERMISSION_DENIED;
            }

            LinearOrCyclicRecordFile file = (LinearOrCyclicRecordFile)CurrentApplication.CurrentFile;

            file.ClearRecords();
            return OPERATION_OK;
        }

    }
}