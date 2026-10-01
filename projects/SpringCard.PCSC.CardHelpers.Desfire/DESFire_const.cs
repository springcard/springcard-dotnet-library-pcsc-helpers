/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using System;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of DESFire_const.
    /// </summary>
    public partial class Desfire
    {

        const UInt32 SCARD_E_INSUFFICIENT_BUFFER = 0x80100008;
        const UInt32 SCARD_W_REMOVED_CARD = 0x80100069;
        const UInt32 SCARD_E_COMM_DATA_LOST = 0x8010002F;
        const UInt32 SCARD_E_CARD_UNSUPPORTED = 0x8010001C;

        /* FSC=5 (64 bytes buffer), including the ISO overhead(PCB, optional CID and 2-byte EDC for the 16-bit CRC). */
        const int MAX_INFO_FRAME_SIZE = 64;
        const byte INF = 0;

        public const byte ISO7816_CLA = 0x90;

        /*
         * DESFire commands (codes sent by the PCD)
         * ----------------------------------------
         */

        public enum DesfireCommand : byte
        {
            AUTHENTICATE = 0x0A,
            CREDIT = 0x0C,
            AUTHENTICATE_ISO = 0x1A,
            LIMITED_CREDIT = 0x1C,
            WRITE_RECORD = 0x3B,
            READ_SIGN = 0x3C,
            WRITE_DATA = 0x3D,
            GET_KEY_SETTINGS = 0x45,
            MANAGE_KEY_PAIR = 0x46,
            EXPORT_KEY = 0x47,
            MANAGE_CA_ROOT_KEY = 0x48,
            CRYPTO_REQUEST = 0x4C,
            GET_CARD_UID = 0x51,
            CHANGE_KEY_SETTINGS = 0x54,
            ROLL_KEY_SET = 0x55,
            INITIALIZE_KEY_SET = 0x56,
            FINALIZE_KEY_SET = 0x57,
            SELECT_APPLICATION = 0x5A,
            SET_CONFIGURATION = 0x5C,
            CHANGE_FILE_SETTINGS = 0x5F,
            GET_VERSION = 0x60,
            GET_ISO_FILE_IDS = 0x61,
            GET_KEY_VERSION = 0x64,
            GET_CONFIGURATION = 0x65,
            GET_DELEGATED_INFO = 0x69,
            GET_APPLICATION_IDS = 0x6A,
            GET_VALUE = 0x6C,
            GET_DF_NAMES = 0x6D,
            GET_FREE_MEMORY = 0x6E,
            GET_FILE_IDS = 0x6F,
            AUTHENTICATE_EV2_FIRST = 0x71,
            AUTHENTICATHE_EV2_NONFIRST = 0x77,
            ISO_GENERAL_AUTHENTICATE = 0x87,
            ISO_INTERNAL_AUTHENTICATE = 0x88,
            WRITE_RECORD_ISO = 0x8B,
            WRITE_DATA_ISO = 0x8D,
            ABORT_TRANSACTION = 0xA7,
            AUTHENTICATE_AES = 0xAA,
            READ_RECORDS_ISO = 0xAB,
            READ_DATA_ISO = 0xAD,
            ADDITIONAL_FRAME = 0xAF,
            UPDATE_RECORD_ISO = 0xBA,
            READ_RECORDS = 0xBB,
            READ_DATA = 0xBD,
            CREATE_CYCLIC_RECORD_FILE = 0xC0,
            CREATE_LINEAR_RECORD_FILE = 0xC1,
            CHANGE_KEY = 0xC4,
            CHANGE_KEY_EV2 = 0xC6,
            COMMIT_TRANSACTION = 0xC7,
            CREATE_DELEGATED_APPLICATION = 0xC9,
            CREATE_APPLICATION = 0xCA,
            CREATE_BACKUP_DATA_FILE = 0xCB,
            CREATE_VALUE_FILE = 0xCC,
            CREATE_STD_DATA_FILE = 0xCD,
            DELETE_APPLICATION = 0xDA,
            UPDATE_RECORD = 0xDB,
            DEBIT = 0xDC,
            DELETE_FILE = 0xDF,
            CLEAR_RECORD_FILE = 0xEB,
            ECP2_END_SESSION = 0xEE,
            GET_FILE_SETTINGS = 0xF5,
            FORMAT_PICC = 0xFC,
            /* Virtual Card Architecture Commands */
            CMD_PPC = 0xF0,   /*  EVx Prepare Proximity Check. */
            CMD_PC = 0xF2,   /*  EVx Proximity Check command. */
            CMD_VPC = 0xFD,   /*  EVx Verify Proximity Check command. */
            CMD_ISOSVC = 0xA4,   /*< IsoSelect Virtual Card command code .*/
            CMD_ISOEXT_AUTH = 0x82,   /*< IsoExternalAuthenticate Virtual Card command code. */
        }

        /*
         * DESFire status (codes returned by the PICC)
         * -------------------------------------------
         */

        public const long Success = 0;
        
        /*
         * DESFire API status/error codes
         * ------------------------------
         */

        public enum DesfireCardError : byte
        {
            Unknown = 0x00,
            NoChange = 0x0C,
            OutOfEeprom = 0x0E,
            IllegalCommandCode = 0x1C,
            IntegrityError = 0x1E,
            NoSuchKey = 0x40,
            LengthError = 0x7E,
            MoreOperationOK = 0x90,
            PermissionDenied = 0x9D,
            ParameterError = 0x9E,
            ApplicationNotFound = 0xA0,
            ApplicationIntegrityError = 0xA1,
            AuthenticationCorrect = 0xAC,
            AuthenticationError = 0xAE,
            AdditionalFrame = 0xAF,
            BoundaryError = 0xBE,
            CardIntegrityError = 0xC1,
            CommandAborted = 0xCA,
            CardDisabledError = 0xCD,
            CountError = 0xCE,
            DuplicateError = 0xDE,
            FileNotFound = 0xF0,
            FileIntegrityError = 0xF1,
            EepromError = 0xEE,
        }

        public enum DesfireLibraryError : byte
        {
            Unknown = 0,
            InvalidParameter,
            OutOfMemory,
            Overflow,
            FunctionNotAvailable,
            ExecutionFailed,
            InvalidKeyValue,
            WrongSessionState = 10,
            WrongResponseToChallenge,
            WrongCMAC,
            WrongCRC,
            WrongSignature,
            WrongLength,
            WrongPadding,
            WrongTLV = 20,
            WrongData,
            WrongFileType,
            WrongRecordSize,
            ProximityCheckFailed = 30,
            UnexpectedChaining = 40,
            UnexpectedTermination,
            PcscBadResponseLength = 50,
            PcscBadStatusWord,
        }

        /*
         * DESFire key types
         * -----------------
         */
        public enum DesfireKeyType : byte
        {
            EV0 = 0x00,
            TDES3K = 0x40,
            AES128 = 0x80,
            AES256 = 0xC0,
        }

        /*
         * DESFire file types
         * ------------------
         */
        public enum DesfireFileType : byte
        {
            StandardData = 0x00,
            BackupData = 0x01,
            Value = 0x02,
            LinearRecord = 0x03,
            CyclicRecord = 0x04,
        }


        /*
         * DESFire communication mode flag combinations.
         * ---------------------------------------------
         */
        public enum DesfireCommMode : byte
        {
            Plain = 0x00,
            Maced = 0x01,
            Plain2 = 0x02,
            Full = 0x03
        }

        /*
         * DESFire access rights
         * ---------------------
         */

        public class DesfireAccessRights
        {
            /* AccessRights masks. */
            public const ushort ReadOnly_Mask = 0xF000;
            public const ushort WriteOnly_Mask = 0x0F00;
            public const ushort ReadWrite_Mask = 0x00F0;
            public const ushort ChangeRights_Mask = 0x000F;

            /* Shift counts for extracting the individual AccessRight settings. */
            public const byte ReadOnly_Shift = 12;
            public const byte WriteOnly_Shift = 8;
            public const byte ReadWrite_Shift = 4;
            public const byte ChangeRights_Shift = 0;

            /* Special keys */
            public const byte Free = 0x0E;
            public const byte Locked = 0x0F;

            public DesfireAccessRights(ushort value)
            {
                Value = value;
            }

            public DesfireAccessRights(byte ReadOnly, byte WriteOnly, byte ReadWrite, byte ChangeRights)
            {
                ReadOnly &= 0x0F;
                WriteOnly &= 0x0F;
                ReadWrite &= 0x0F;
                ChangeRights &= 0x0F;

                Value = (ushort)((ReadOnly << ReadOnly_Shift) |
                                 (WriteOnly << WriteOnly_Shift) |
                                 (ReadWrite << ReadWrite_Shift) |
                                 (ChangeRights << ChangeRights_Shift));
            }

            public ushort Value
            {
                get; private set;
            }

            public static DesfireAccessRights Create(ushort value)
            {
                return new DesfireAccessRights(value);
            }

            public static DesfireAccessRights Create(byte ReadOnly, byte WriteOnly, byte ReadWrite, byte ChangeRights)
            {
                return new DesfireAccessRights(ReadOnly, WriteOnly, ReadWrite, ChangeRights);
            }
        }

        /*
         * DESFire flags for CreateApplication
         * -----------------------------------
         */

        public class DesfireApplicationSettings
        {
            [Flags]
            public enum KeySetting1 : byte
            {
                MasterChangeable = 0x01,
                FreeListing = 0x02,
                FreeCreateDelete = 0x04,
                ConfigChangeable = 0x08,
                SameKeyNeeded = 0xE0,
                AllKeysFrozen = 0xF0,
            }

            [Flags]
            public enum KeySetting2 : byte
            {
                KeySetting3Present = 0x10,
                IsoEFIds = 0x20,
                TDES3K = 0x40, /* Same as DesfireKeyType.TDES3K */
                AES128 = 0x80, /* Same as DesfireKeyType.AES128 */
                AES256 = 0xC0, /* Same as DesfireKeyType.AES256 */
            }

            [Flags]
            public enum KeySetting3 : byte
            {
                HaveKeySets = 0x01,
                SpecificVCProximityKey = 0x02,
                SpecificCapabilityData = 0x04,
                AlwaysDeletable = 0x08
            }

        }


        /* Data item lengths for the GetFileSettings command */
        const int FILE_SETTINGS_COMMON_LENGTH = 4;
        const int DATA_FILE_SETTINGS_LENGTH = 3;
        const int VALUE_FILE_SETTINGS_LENGTH = 13;
        const int RECORD_FILE_SETTINGS_LENGTH = 9;

        const int APPLICATION_ID_SIZE = 3;

        const int MAX_FILE_DATA_SIZE = 8192;


        /*
        * DESFire Originality Check
        * ---------------------------------------------
        */
        public const byte ORIGINALITY_SIGN_LENGTH = 0x38;  /* NXP Originality Signature length */
        public const byte ORIGINALITY_SIGN_LENGTH_ENC = 0x40;   /* NXP Originality Signature length */

        /*
         * Mifare DuoX
         * -----------
         */

        public enum MifareDuoXEccCurve : byte
        {
            NistP256 = 0x0C,
            BrainPoolP256R1 = 0x0D
        }

        [Flags]
        public enum MifareDuoXKeyPairPolicy : ushort
        {
            FreezeKUC = 0x8000,
            PiccAuth = 0x0100,
            MutualAuth = 0x0080,
            TransSign = 0x0040,
            SDM = 0x0020,
            Sign = 0x0010,
        }

        public class MifareDuoXCARootKeyAccessRights
        {
            public MifareDuoXCARootKeyAccessRights(ushort value)
            {
                Value = value;
            }

            public ushort Value
            {
                get; private set;
            }

            public static MifareDuoXCARootKeyAccessRights Create(ushort value)
            {
                return new MifareDuoXCARootKeyAccessRights(value);
            }
        }

        public class MifareDuoXAccessRights
        {
            /* AccessRights masks. */
            public const ushort AccessKey_Mask = 0x0F;
            public const ushort CommMode_Mask = 0x30;

            /* Shift counts for extracting the individual AccessRight settings. */
            public const byte AccessKey_Shift = 0;
            public const byte CommMode_Shift = 4;

            /* Special keys */
            public const byte Free = 0x0E;
            public const byte Locked = 0x0F;

            public MifareDuoXAccessRights(byte value)
            {
                Value = value;
            }

            public MifareDuoXAccessRights(byte AccessKey, byte CommMode)
            {
                AccessKey &= 0x0F;
                CommMode &= 0x03;

                Value = (byte)((AccessKey << AccessKey_Shift) |
                               (CommMode << CommMode_Shift));
            }

            public MifareDuoXAccessRights(byte AccessKey, DesfireCommMode CommMode)
            {
                AccessKey &= 0x0F;
                byte bCommMode = (byte)(((byte)CommMode) & 0x03);

                Value = (byte)((AccessKey << AccessKey_Shift) |
                               (bCommMode << CommMode_Shift));
            }

            public byte Value
            {
                get; private set;
            }

            public static MifareDuoXAccessRights Create(byte value)
            {
                return new MifareDuoXAccessRights(value);
            }

            public static MifareDuoXAccessRights Create(byte AccessKey, byte CommMode)
            {
                return new MifareDuoXAccessRights(AccessKey, CommMode);
            }

            public static MifareDuoXAccessRights Create(byte AccessKey, DesfireCommMode CommMode)
            {
                return new MifareDuoXAccessRights(AccessKey, CommMode);
            }
        }

        public class MifareDuoXGeneralAuthenticatePcdOptions
        {
            byte[] _value;

            public enum EAuthMethod
            {
                Unset = 0,
                MutualWithPcdCertificate = 0x80,
                MutualWithoutPcdCertificate = 0xA0,
                PcdUnilateralWithPcdCertificate = 0x40,
                PcdUnilateralWithoutPcdCertificate = 0x60
            }

            public EAuthMethod AuthMethod
            {
                get
                {
                    if ((_value == null) || (_value.Length < 1))
                        return EAuthMethod.Unset;

                    return (EAuthMethod)(_value[0]);
                }
                set
                {
                    if (_value == null)
                        _value = new byte[1];

                    switch (value)
                    {
                        case EAuthMethod.MutualWithPcdCertificate:
                        case EAuthMethod.MutualWithoutPcdCertificate:
                            Array.Resize(ref _value, 4);
                            break;
                        case EAuthMethod.PcdUnilateralWithPcdCertificate:
                        case EAuthMethod.PcdUnilateralWithoutPcdCertificate:
                            Array.Resize(ref _value, 2);
                            break;
                        default:
                            throw new ArgumentException("Invalid authentication method");
                    }

                    _value[0] = (byte)value;
                }
            }

            public byte Version
            {
                get
                {
                    if ((_value == null) || (_value.Length < 2))
                        return 0;

                    return _value[1];
                }
                private set
                {
                    if (_value == null)
                        _value = new byte[2];
                    if (_value.Length < 2)
                        Array.Resize(ref _value, 2);
                    _value[1] = value;
                }
            }

            public bool CertificateSAI
            {
                get
                {
                    if ((_value == null) || (_value.Length < 3))
                        return false;

                    return ((_value[2] & 0x80) != 0);
                }
                set
                {
                    if ((_value == null) || (_value.Length < 3))
                        throw new ArgumentException("SAI not available with this authentication method");

                    if (value)
                    {
                        _value[2] |= 0x80;
                    }
                    else
                    {
                        _value[2] &= 0x7F;
                    }
                }
            }

            public byte CertificateFileId
            {
                get
                {
                    if ((_value == null) || (_value.Length < 3))
                        return 0;

                    return (byte)(_value[2] & 0x0F);
                }
                set
                {
                    if ((_value == null) || (_value.Length < 3))
                        throw new ArgumentException("Certificate file not available with this authentication method");

                    _value[2] &= 0xF0;
                    _value[2] |= (byte)(value & 0x0F);
                }
            }

            public byte PrivateKeyNo
            {
                get
                {
                    if ((_value == null) || (_value.Length < 4))
                        return 0;

                    return _value[3];
                }
                set
                {
                    if ((_value == null) || (_value.Length < 4))
                        throw new ArgumentException("Private key not available with this authentication method");

                    _value[3] &= 0x03;
                    _value[3] |= (byte)(value & 0x03);
                }
            }

            public byte[] Value
            {
                get
                {
                    return _value;
                }
            }

            public byte[] GetTLV()
            {
                byte[] result = new byte[_value.Length + 2];
                result[0] = 0x80;
                result[1] = (byte)(_value.Length);
                Array.Copy(_value, 0, result, 2, _value.Length);
                return result;
            }

            public MifareDuoXGeneralAuthenticatePcdOptions(byte[] value)
            {                
                _value = value;
            }

            public MifareDuoXGeneralAuthenticatePcdOptions(EAuthMethod AuthMethod)
            {
                this.AuthMethod = AuthMethod;
            }

            public MifareDuoXGeneralAuthenticatePcdOptions(EAuthMethod AuthMethod, byte PrivateKeyNumber, byte CertificateFileId)
            {
                this.AuthMethod = AuthMethod;
                this.PrivateKeyNo = PrivateKeyNumber;
                this.CertificateFileId = CertificateFileId;
            }

            public MifareDuoXGeneralAuthenticatePcdOptions(EAuthMethod AuthMethod, byte PrivateKeyNumber, byte CertificateFileId, bool SAI)
            {
                this.AuthMethod = AuthMethod;
                this.PrivateKeyNo = PrivateKeyNumber;
                this.CertificateFileId = CertificateFileId;
                this.CertificateSAI = SAI;
            }

            public static MifareDuoXGeneralAuthenticatePcdOptions Create(byte[] value)
            {
                return new MifareDuoXGeneralAuthenticatePcdOptions(value);
            }

            public static MifareDuoXGeneralAuthenticatePcdOptions Create(EAuthMethod AuthMethod)
            {
                return new MifareDuoXGeneralAuthenticatePcdOptions(AuthMethod);
            }

            public static MifareDuoXGeneralAuthenticatePcdOptions Create(EAuthMethod AuthMethod, byte PrivateKeyNumber, byte CertificateFileId)
            {
                return new MifareDuoXGeneralAuthenticatePcdOptions(AuthMethod, PrivateKeyNumber, CertificateFileId);
            }

            public static MifareDuoXGeneralAuthenticatePcdOptions Create(EAuthMethod AuthMethod, byte PrivateKeyNumber, byte CertificateFileId, bool SAI)
            {
                return new MifareDuoXGeneralAuthenticatePcdOptions(AuthMethod, PrivateKeyNumber, CertificateFileId, SAI);
            }
        }

    }
}
