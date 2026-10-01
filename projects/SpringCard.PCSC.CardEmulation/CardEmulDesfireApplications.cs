/*
 * Crée par SharpDevelop.
 * Utilisateur: johann
 * Date: 05/01/2012
 * Heure: 12:02
 * 
 * Pour changer ce modèle utiliser Outils | Options | Codage | Editer les en-têtes standards.
 */
using System;
using System.Collections.Generic;
using Newtonsoft.Json.Linq;
using SpringCard.LibCs;

namespace SpringCard.PCSC.CardEmulation
{
    public partial class CardEmulDesfire
    {
        public class DesfireApplication
        {
            protected CardEmulDesfire Card;
            public uint Aid;
            public byte KeySettings;

            public bool IsIso = false;
            public ushort IsoFileId;
            public byte[] IsoDFName;

            public bool HasIsoFiles { get; private set; } = false;

            public enum EApplicationKeyType
            {
                TDES2K,
                TDES3K,
                AES128,
                AES256
            }

            public EApplicationKeyType ApplicationKeyType { get; private set; }

            public Dictionary<byte, DesfireKey> Keys = new Dictionary<byte, DesfireKey>();
            public Dictionary<byte, DesfireFile> Files = new Dictionary<byte, DesfireFile>();
            public Dictionary<byte, DesfireECCKeyPair> ECCKeyPairs = new Dictionary<byte, DesfireECCKeyPair>();
            public Dictionary<byte, DesfireCARootKey> CARootKeys = new Dictionary<byte, DesfireCARootKey>();

            public DesfireFile CurrentFile = null;

            private static DesfireKey DefaultKey(EApplicationKeyType ApplicationKeyType)
            {
                switch (ApplicationKeyType)
                {
                    case EApplicationKeyType.TDES2K:
                        return new DesfireKey(16);
                    case EApplicationKeyType.TDES3K:
                        return new DesfireKey(24);
                    case EApplicationKeyType.AES128:
                        return new DesfireKey(16);
                    case EApplicationKeyType.AES256:
                        return new DesfireKey(32);
                    default:
                        return null;
                }
            }

            public void SetMetaData(CardEmulDesfire Card, uint Aid)
            {
                this.Card = Card;
                this.Aid = Aid;
            }

            public DesfireApplication(EApplicationKeyType ApplicationKeyType, byte KeyCount)
            {
                this.ApplicationKeyType = ApplicationKeyType;

                DesfireKey defaultKey = DefaultKey(ApplicationKeyType);

                for (byte keyNo = 0; keyNo < KeyCount; keyNo++)
                    Keys[keyNo] = defaultKey;
            }

            public DesfireApplication(byte KeySettings1, byte KeySettings2)
            {
                this.KeySettings = KeySettings1;

                int KeyCount = KeySettings2 & 0x0F;

                if ((KeySettings2 & 0x20) != 0)
                    HasIsoFiles = true;

                switch (KeySettings2 & 0xC0)
                {
                    case 0xC0:
                        ApplicationKeyType = EApplicationKeyType.AES256;
                        break;
                    case 0x80:
                        ApplicationKeyType = EApplicationKeyType.AES128;
                        break;
                    case 0x40:
                        ApplicationKeyType = EApplicationKeyType.TDES3K;
                        break;
                    default:
                        ApplicationKeyType = EApplicationKeyType.TDES3K;
                        break;
                }

                DesfireKey defaultKey = DefaultKey(ApplicationKeyType);

                for (byte keyNo = 0; keyNo < KeyCount; keyNo++)
                    Keys[keyNo] = defaultKey;
            }

            public void GetStatistics(out int KeyCount, out int FileCount, out int ByteCount)
            {
                ByteCount = 0;
                KeyCount = Keys.Count;
                ByteCount += 32 * KeyCount;
                FileCount = Files.Count;
                ByteCount += 32 * FileCount;
                foreach (KeyValuePair<byte, DesfireFile> file in Files)
                    ByteCount += file.Value.ByteCount;
            }

            bool MasterKeyChangeable
            {
                get
                {
                    return (KeySettings & 0x01) != 0;
                }
            }

            bool FreeDirectory
            {
                get
                {
                    return (KeySettings & 0x02) != 0;
                }
            }

            bool FreeCreateDelete
            {
                get
                {
                    return (KeySettings & 0x04) != 0;
                }
            }

            bool ConfigurationChangeable
            {
                get
                {
                    return (KeySettings & 0x08) != 0;
                }
            }

            byte ChangeKeyNumber
            {
                get
                {
                    return (byte)((KeySettings >> 4) & 0x0F);
                }
            }


            public void SetIso(ushort IsoFileId, byte[] IsoDFName)
            {
                this.IsIso = true;
                this.IsoFileId = IsoFileId;
                this.IsoDFName = IsoDFName;
            }

            public JObject ToJObject()
            {
                JObject result = new JObject
                {
                    ["AID"] = string.Format("{0:X06}", Aid),
                    ["Type"] = ApplicationKeyType.ToString(),
                    ["KeySettings"] = BinConvert.ToHex(KeySettings),
                    ["KeyCount"] = Keys.Count,
                };

                if (Keys.Count > 0)
                {
                    result["Keys"] = new JObject();
                    foreach (KeyValuePair<byte, DesfireKey> kvp in Keys)
                        result["Keys"][String.Format("{0:X02}", kvp.Key)] = kvp.Value.ToJObject();
                }

                if (Files.Count > 0)
                {
                    result["Files"] = new JObject();
                    foreach (KeyValuePair<byte, DesfireFile> kvp in Files)
                        result["Files"][String.Format("{0:X02}", kvp.Key)] = kvp.Value.ToJObject();
                }

                return result;
            }

            public bool FileExists(byte FileId)
            {
                if (Files == null)
                    return false;
                return Files.ContainsKey(FileId);
            }

            public bool SelectFile(byte FileId)
            {
                CurrentFile = null;
                if (Files == null)
                    return false;
                if (!Files.ContainsKey(FileId))
                    return false;
                CurrentFile = Files[FileId];
                return true;
            }

            public bool DeleteFile(byte FileId)
            {
                CurrentFile = null;
                if (Files == null)
                    return false;
                if (!Files.ContainsKey(FileId))
                    return false;
                Files.Remove(FileId);
                return true;
            }

            public bool InsertFile(byte FileId, DesfireFile File)
            {
                CurrentFile = null;
                if (Files == null)
                    return false;
                if (Files.ContainsKey(FileId))
                    return false;
                Files.Remove(FileId);
                Files[FileId] = File;
                return SelectFile(FileId);
            }

            public bool Commit()
            {
                foreach (KeyValuePair<byte, DesfireFile> kvp in Files)
                    if (!kvp.Value.Commit())
                        return false;

                return true;
            }

            public bool Abort()
            {
                foreach (KeyValuePair<byte, DesfireFile> kvp in Files)
                    if (!kvp.Value.Abort())
                        return false;

                return true;
            }
        }

        protected byte CreateApplication(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (CurrentApplication != null)
                return PERMISSION_DENIED;

            if (!RootFreeCreateDelete)
                if (CipherContext == null)
                    return AUTHENTICATION_ERROR;

            if (!CheckIn(DataIn, 5, 23))
                return LENGTH_ERROR;

            uint Aid = Get3(DataIn.GetBytes(0, 3));

            if (Aid == 0)
                return PARAMETER_ERROR;

            if (Applications.ContainsKey(Aid))
                return DUPLICATE_ERROR;

            byte KeySet1 = DataIn.GetByte(3);
            byte KeySet2 = DataIn.GetByte(4);

            DesfireApplication desfireApplication = new DesfireApplication(KeySet1, KeySet2);
            desfireApplication.SetMetaData(this, Aid);

            if (DataIn.Length >= 7)
            {
                ushort IsoFileId = Get2(DataIn.GetBytes(5, 2));
                byte[] IsoDFName = DataIn.GetBytes(7, DataIn.Length - 7);
                desfireApplication.SetIso(IsoFileId, IsoDFName);
            }

            Applications[Aid] = desfireApplication;

            return OPERATION_OK;
        }

        public bool DeleteApplication(uint Aid)
        {
            logger.debug("DeleteApplication({0:X06})", Aid);
            if (Aid == 0)
                return false;
            if (!Applications.ContainsKey(Aid))
                return false;
            Applications.Remove(Aid);
            return true;
        }

        protected byte DeleteApplication(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (!CheckIn(DataIn, 3))
                return LENGTH_ERROR;

            uint Aid = Get3(DataIn.GetBytes(0, 3));

            if (CurrentApplication == null)
            {
                if (!RootFreeCreateDelete)
                    if (CipherContext == null)
                        return AUTHENTICATION_ERROR;
            }
            else
            {
                if (CurrentApplication.Aid != Aid)
                    return PERMISSION_DENIED;

                if (CipherContext == null)
                    return AUTHENTICATION_ERROR;

                SelectApplication(0);
            }

            DeleteApplication(Aid);
            return OPERATION_OK;
        }


        protected byte GetApplicationIDs(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (!RootFreeDirectory)
                if (CipherContext == null)
                    return AUTHENTICATION_ERROR;

            if (!CheckIn(DataIn, 0))
                return LENGTH_ERROR;

            if (pendingCommand == null)
                pendingCommand = new PendingCommand();

            byte[] result;

            List<uint> aids = new List<uint>();
            foreach (KeyValuePair<uint, DesfireApplication> kvp in Applications)
                aids.Add(kvp.Key);

            switch (pendingCommand.Iteration)
            {
                case 0:
                    if (Applications.Count == 0)
                        return OPERATION_OK;

                    if (Applications.Count > 19)
                    {
                        result = new byte[19 * 3];
                    }
                    else
                    {
                        result = new byte[aids.Count * 3];
                    }

                    for (int i = 0; (i < aids.Count) && (i < 19); i++)
                    {
                        uint aid = aids[i];
                        result[3 * i + 0] = (byte)(aid & 0x0FF);
                        result[3 * i + 1] = (byte)((aid >> 8) & 0x0FF);
                        result[3 * i + 2] = (byte)((aid >> 16) & 0x0FF);
                    }

                    DataOut = new CardBuffer(result);

                    if (Applications.Count > 19)
                        return ADDITIONAL_FRAME;

                    return OPERATION_OK;

                case 1:
                    if (Applications.Count <= 19)
                        return INTERNAL_ERROR;

                    result = new byte[(aids.Count - 19) * 3];
                    for (int i = 0; i < (aids.Count - 19); i++)
                    {
                        uint aid = aids[i + 19];
                        result[3 * i + 0] = (byte)(aid & 0x0FF);
                        result[3 * i + 1] = (byte)((aid >> 8) & 0x0FF);
                        result[3 * i + 2] = (byte)((aid >> 16) & 0x0FF);
                    }

                    DataOut = new CardBuffer(result);

                    return OPERATION_OK;
            }

            return INTERNAL_ERROR;
        }

        protected byte GetDFNames(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (!RootFreeDirectory)
                if (CipherContext == null)
                    return AUTHENTICATION_ERROR;

            if (!CheckIn(DataIn, 0))
                return LENGTH_ERROR;

            if (pendingCommand == null)
                pendingCommand = new PendingCommand();

            List<DesfireApplication> desfireApplications = new List<DesfireApplication>();
            foreach (KeyValuePair<uint, DesfireApplication> kvp in Applications)
            {
                if (kvp.Value.IsIso)
                    desfireApplications.Add(kvp.Value);
            }

            if (pendingCommand.Iteration < desfireApplications.Count)
            {
                DesfireApplication desfireApplication = desfireApplications[pendingCommand.Iteration];

                byte[] result = new byte[5];

                uint Aid = desfireApplication.Aid;
                result[0] = (byte)(Aid & 0x0FF);
                result[1] = (byte)((Aid >> 8) & 0x0FF);
                result[2] = (byte)((Aid >> 16) & 0x0FF);

                result[3] = (byte)(desfireApplication.IsoFileId & 0x0FF);
                result[4] = (byte)((desfireApplication.IsoFileId >> 8) & 0x0FF);

                if (desfireApplication.IsoDFName != null)
                    result = BinUtils.Concat(result, desfireApplication.IsoDFName);

                DataOut = new CardBuffer(result);

                if (pendingCommand.Iteration == desfireApplications.Count - 1)
                {
                    return OPERATION_OK;
                }
                else
                {
                    return ADDITIONAL_FRAME;
                }
            }

            return INTERNAL_ERROR;
        }
    }
}
