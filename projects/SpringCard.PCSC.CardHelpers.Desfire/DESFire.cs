/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using System;
using System.Collections.Generic;
using System.Reflection;
using SpringCard.LibCs;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        uint CurrentAid;
        byte SessionKeyNumber;
        DesfireCryptoContext SessionCryptoContext;

        int xfer_length;
        byte[] xfer_buffer;

        const int MAX_BUFFER_EXCHANGE = 256;        

        public enum EAuthType : byte
        {
            NONE = 0,
            DES_EV0,
            TDES_EV0,
            DES_EV1,
            TDES2K_EV1,
            TDES3K_EV1,
            AES128_EV1,
            AES128_EV2,
            AES256_EV2
        }

        private Dictionary<string, byte[]> knownKeyValues = new Dictionary<string, byte[]>();

        private void DumpKnownKeys()
        {
            foreach (KeyValuePair<string, byte[]> entry in knownKeyValues)
            {
                logger.debug("\t{0}:{1}", entry.Key, BinConvert.ToHex(entry.Value));
            }
        }

        private void RememberAuthKey(byte[] KeyValue)
        {
            if (!logSecrets)
                return;
            string s = string.Format("{0:X06}.{1:X02}[{2}]", CurrentAid, GetSessionKeyNumber(), GetSessionType().ToString());
            if (knownKeyValues.ContainsKey(s))
                knownKeyValues.Remove(s);
            knownKeyValues[s] = KeyValue;
        }

        private void RememberChangeKey(byte KeyNumber, byte[] KeyValue)
        {
            if (!logSecrets)
                return;
            string s = string.Format("{0:X06}.{1:X02}", CurrentAid, KeyNumber);
            if (knownKeyValues.ContainsKey(s))
                knownKeyValues.Remove(s);
            knownKeyValues[s] = KeyValue;
        }

        public bool InSecureSession()
        {
            return (SessionCryptoContext != null);
        }

        protected void BeginSecureSession(byte KeyNumber, DesfireCryptoContext CryptoContext)
        {
            this.SessionKeyNumber = KeyNumber;
            this.SessionCryptoContext = CryptoContext;
        }

        protected void EndSecureSession()
        {
            if (SessionCryptoContext != null)
                logger.debug("End secure session");
            SessionCryptoContext = null;
        }

        private EAuthType GetSessionType()
        {
            if (SessionCryptoContext != null)
                return SessionCryptoContext.AuthType;

            return EAuthType.NONE;
        }

        private byte GetSessionKeyNumber()
        {
            if (SessionCryptoContext != null)
                return SessionKeyNumber;

            return 0xFF;
        }

        protected int GetSessionKeySize()
        {
            switch (GetSessionType())
            {
                case EAuthType.DES_EV0:
                case EAuthType.TDES_EV0:

                case EAuthType.DES_EV1:
                case EAuthType.TDES2K_EV1:
                
                case EAuthType.AES128_EV1:

                case EAuthType.AES128_EV2:
                    return 16;

                case EAuthType.TDES3K_EV1:
                    return 24;

                case EAuthType.AES256_EV2:
                    return 32;

                default:
                    return 0;
            }
        }


        protected bool SessionIsEV0()
        {
            if (SessionCryptoContext == null)
                return false;
            if (SessionCryptoContext is DesfireCryptoContextEV0)
                return true;
            return false;
        }

        protected bool SessionIsEV1()
        {
            if (SessionCryptoContext != null)
            {
                if (SessionCryptoContext is DesfireCryptoContextEV1)
                {
                    logger.debug("Session is EV1");
                    return true;
                }
            }
            return false;
        }

        protected bool SessionIsEV2()
        {
            switch (GetSessionType())
            {
                case EAuthType.AES128_EV2:
                case EAuthType.AES256_EV2:
                    return true;

                default:
                    return false;
            }
        }

        protected bool SessionIsEV0OrGreater()
        {
            if (SessionIsEV0())
                return true;
            if (SessionIsEV1())
                return true;
            if (SessionIsEV2())
                return true;
            return false;
        }

        protected bool SessionIsEV1OrGreater()
        {
            if (SessionIsEV1())
                return true;
            if (SessionIsEV2())
                return true;
            return false;
        }

        protected bool SessionIsEV2OrGreater()
        {
            if (SessionIsEV2())
                return true;
            return false;
        }

        protected bool SessionIsAES()
        {
            switch (GetSessionType())
            {
                case EAuthType.AES128_EV1:
                case EAuthType.AES128_EV2:
                case EAuthType.AES256_EV2:
                    logger.debug("Session is AES");
                    return true;

                default:
                    logger.debug("Session is _NOT_ AES");
                    return false;
            }
        }

        protected bool SessionIsAES128()
        {
            switch (GetSessionType())
            {
                case EAuthType.AES128_EV1:
                case EAuthType.AES128_EV2:
                    return true;

                default:
                    return false;
            }
        }

        protected bool SessionIsAES256()
        {
            switch (GetSessionType())
            {
                case EAuthType.AES256_EV2:
                    return true;

                default:
                    return false;
            }
        }

        int MaxFrameSize = 64;
        bool FrameUseCid = false;

        ICardTransmitter transmitter;

        /**
         * @brief Library information
         **/
        public static class Library
        {
            /**
             * @brief Read Library information
             **/
            public static readonly AppModuleInfo ModuleInfo = new AppModuleInfo(Assembly.GetExecutingAssembly());
        }

        public void SetIsoWrapping()
        {
            SetIsoWrapping(DesfireIsoWrapping.Card);
        }

        public void SetIsoWrapping(byte mode)
        {
            SetIsoWrapping((DesfireIsoWrapping)mode);
        }

        public void SetIsoWrapping(DesfireIsoWrapping mode)
        {
            IsoWrapping = mode;
        }

        /**
		 * @brief Instanciate a Desfire card object over a card channel. The channel must already be connected.
		 */
        public Desfire(ICardTransmitter transmitter)
        {
            this.transmitter = transmitter;
            this.IsoWrapping = DesfireIsoWrapping.Card;
            xfer_buffer = new byte[MAX_BUFFER_EXCHANGE];            
        }

        /**
		 * @brief Instanciate a Desfire card object over a card channel. The channel must already be connected.
		 */
        public Desfire(ICardTransmitter transmitter, DesfireIsoWrapping isoWrapping = DesfireIsoWrapping.Card)
        {
            this.transmitter = transmitter;
            this.IsoWrapping = isoWrapping;
            xfer_buffer = new byte[MAX_BUFFER_EXCHANGE];
        }

        /**
		 * @brief Instanciate a Desfire card object over a card channel. The channel must already be connected.
		 */
        public Desfire(ICardTransmitter transmitter, byte isoWrapping = (byte)DesfireIsoWrapping.Card)
        {
            this.transmitter = transmitter;
            this.IsoWrapping = (DesfireIsoWrapping)isoWrapping;
            xfer_buffer = new byte[MAX_BUFFER_EXCHANGE];
        }

        public ICardTransmitter GetTransmitter()
        {
            return transmitter;
        }

        private static long CardError(byte error)
        {
            return (long)(-1000 - (long)error);
        }

        private static long CardError(DesfireCardError error)
        {
            return (long)(-1000 - (long) error);
        }

        public static bool IsCardError(long status, out DesfireCardError error)
        {
            if (IsCardError(status))
            {
                error = GetCardError(status);
                return true;
            }
            error = DesfireCardError.Unknown;
            return false;
        }

        public static bool IsCardError(long status)
        {
            if ((status <= -1000) && (status >= -1000 - 255))
                return true;
            return false;
        }

        public static DesfireCardError GetCardError(long status)
        {
            if (IsCardError(status))
            {
                long error = (long)(0 - status - 1000);
                if ((error >= 0) && (error < 256))
                    if (Enum.IsDefined(typeof(DesfireCardError), (byte)error))
                        return (DesfireCardError)((byte)error);
            }
            else if (status != Success)
            {
                Logger.Warning("{0} is not a valid card error code", status);
            }
            return DesfireCardError.Unknown;
        }

        private static long LibraryError(DesfireLibraryError error)
        {
            return (long)(-1000 + (long)error);
        }

        public static bool IsLibraryError(long status, out DesfireLibraryError error)
        {
            if (IsCardError(status))
            {
                error = GetLibraryError(status);
                return true;
            }
            error = DesfireLibraryError.Unknown;
            return false;
        }

        public static bool IsLibraryError(long status)
        {
            if ((status >= -1000) && (status <= -1000 + 255))
                return true;
            return false;
        }

        public static DesfireLibraryError GetLibraryError(long status)
        {
            if (IsLibraryError(status))
            {
                long error = (long)(1000 + status);
                if ((error >= 0) && (error < 256))
                {
                    if (Enum.IsDefined(typeof(DesfireLibraryError), (byte)error))
                        return (DesfireLibraryError)((byte)error);
                }
            }
            else if (status != Success)
            {
                Logger.Warning("{0} is not a valid library error code", status);
            }
            return DesfireLibraryError.Unknown;
        }

        public static string GetErrorMessage(long status)
        {
            if (status == Success)
            {
                return ("Function was executed without failure");
            }
            else if (IsCardError(status))
            {
                DesfireCardError error = GetCardError(status);

                switch (error)
                {
                    case DesfireCardError.NoChange:
                        return ("Desfire : no changes done to backup file, no need to commit/abort");
                    case DesfireCardError.OutOfEeprom:
                        return ("Desfire : insufficient NV-memory to complete command");
                    case DesfireCardError.IllegalCommandCode:
                        return ("Desfire : command code not supported");
                    case DesfireCardError.IntegrityError:
                        return ("Desfire : CRC or MAC does not match, or invalid padding bytes");
                    case DesfireCardError.NoSuchKey:
                        return ("Desfire : invalid key number specified");
                    case DesfireCardError.LengthError:
                        return ("Desfire : length of command string invalid");
                    case DesfireCardError.PermissionDenied:
                        return ("Desfire : current configuration or status does not allow the requested command");
                    case DesfireCardError.ParameterError:
                        return ("Desfire : value of the parameter(s) invalid");
                    case DesfireCardError.ApplicationNotFound:
                        return ("Desfire : requested application not present on the card");
                    case DesfireCardError.ApplicationIntegrityError:
                        return ("Desfire : unrecoverable error within application, application will be disabled");
                    case DesfireCardError.AuthenticationCorrect:
                        return ("Desfire : successfull authentication");
                    case DesfireCardError.AuthenticationError:
                        return ("Desfire : current authentication status does not allow the requested command");
                    case DesfireCardError.AdditionalFrame:
                        return ("Desfire : additionnal data frame is expected to be sent");
                    case DesfireCardError.BoundaryError:
                        return ("Desfire : attempt to read or write data out of the file's or record's limits");
                    case DesfireCardError.CardIntegrityError:
                        return ("Desfire : unrecoverable error within the card, the card will be disabled");
                    case DesfireCardError.CommandAborted:
                        return ("Desfire : the current command has been aborted");
                    case DesfireCardError.CardDisabledError:
                        return ("Desfire : card was disabled by an unrecoverable error");
                    case DesfireCardError.CountError:
                        return ("Desfire : maximum number of 28 applications has been reached");
                    case DesfireCardError.DuplicateError:
                        return ("Desfire : the specified file or application already exists");
                    case DesfireCardError.FileNotFound:
                        return ("Desfire : the specified file does not exists");
                    case DesfireCardError.FileIntegrityError:
                        return ("Desfire : unrecoverable error within file, file will be disabled");
                    case DesfireCardError.EepromError:
                        return ("Desfire : could not complete NV-memory write operation, due to power loss, aborting");

                    default:
                        return error.ToString();
                }
                
            }
            else if (IsLibraryError(status))
            {
                DesfireLibraryError error = GetLibraryError(status);

                switch (error)
                {
                    case DesfireLibraryError.InvalidParameter:
                        return ("Desfire : invalid parameters in function call");
                    case DesfireLibraryError.OutOfMemory:
                        return ("Desfire : not enough memory");
                    case DesfireLibraryError.Overflow:
                        return ("Desfire : supplied buffer is too short");
                    case DesfireLibraryError.WrongResponseToChallenge:
                        return ("Desfire : card authentication denied");
                    case DesfireLibraryError.WrongCMAC:
                        return ("Desfire : wrong MAC in card's frame");
                    case DesfireLibraryError.WrongCRC:
                        return ("Desfire : wrong CRC in card's fame");
                    case DesfireLibraryError.WrongLength:
                        return ("Desfire : length of card's frame is invalid");
                    case DesfireLibraryError.WrongPadding:
                        return ("Desfire : wrong padding in card's frame");
                    case DesfireLibraryError.WrongFileType:
                        return ("Desfire : wrong file type");
                    case DesfireLibraryError.WrongRecordSize:
                        return ("Desfire : wrong record size");

                    case DesfireLibraryError.PcscBadResponseLength:
                        return ("Desfire : card's response is too short");
                    case DesfireLibraryError.PcscBadStatusWord:
                        return ("Desfire : card's status word is invalid");

                    default:
                        return error.ToString();
                }
            }

            return string.Format("Unknown error code {0} ({0:X08})", status);
        }

        public static readonly byte[] BlankKeyAES = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        public static readonly byte[] BlankKeyAES128 = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        public static readonly byte[] BlankKeyAES256 = new byte[32] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        public static readonly byte[] BlankKey3DES16 = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        public static readonly byte[] BlankKey3DES24 = new byte[24] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        public static readonly byte[] SampleMasterKeyAES = new byte[16] { 0x43, 0x61, 0x72, 0x64, 0x20, 0x4D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4B, 0x65, 0x79, 0x21 }; // Card Master Key!

        public static readonly byte[] SampleMasterKeyDES = new byte[16] { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 }; // ABCDEFGHABCDEFGH
        public static readonly byte[] SampleMasterKey3DES = new byte[16] { 0x43, 0x61, 0x72, 0x64, 0x20, 0x4D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4B, 0x65, 0x79, 0x21 }; // Card Master Key!

        public static readonly byte[] SampleMasterKeyDES24 = new byte[24] { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 }; // "ABCDEFGHABCDEFGHABCDEFGH
        public static readonly byte[] SampleMasterKey3DES24 = new byte[24] { 0x43, 0x61, 0x72, 0x64, 0x20, 0x4D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4B, 0x65, 0x79, 0x21, 0x43, 0x61, 0x72, 0x64, 0x20, 0x4D, 0x61, 0x73 }; // "Card Master Key!Card Mas
        public static readonly byte[] SampleMasterKey3DES3K24 = new byte[24] { 0x43, 0x61, 0x72, 0x64, 0x20, 0x4D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4B, 0x65, 0x79, 0x21, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 }; // Card Master Key!         

        /* virtual card configuration key */
        public static readonly byte[] SampleVirtualCardConfigKeyAES= new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
        /* virtual card proximity key */
        public static readonly byte[] SampleProximityKeyAES = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
        /* virtual card mac key */
        public static readonly byte[] SampleVirtualCardSelectMACKeyAES = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 };
        /* virtual card enc key */
        public static readonly byte[] SampleVirtualCardSelectENCKeyAES = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04 };

    }
}
