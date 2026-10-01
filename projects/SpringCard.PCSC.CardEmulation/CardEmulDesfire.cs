/*
 * Crée par SharpDevelop.
 * Utilisateur: johann
 * Date: 05/01/2012
 * Heure: 12:02
 * 
 * Pour changer ce modèle utiliser Outils | Options | Codage | Editer les en-têtes standards.
 */
using SpringCard.LibCs;
using SpringCard.PCSC.CardHelpers;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml;

namespace SpringCard.PCSC.CardEmulation
{
    /// <summary>
    /// Description of PiccEmulDesfire.
    /// </summary>
    public abstract partial class CardEmulDesfire : CardEmulCardlet
    {

        #region Consts

        public const byte OPERATION_OK = 0x00;
        public const byte INTERNAL_ERROR = 0xFF;

        public const byte NO_CHANGES = 0x0C;
        public const byte OUT_OF_EEPROM_ERROR = 0x0E;
        public const byte ILLEGAL_COMMAND_CODE = 0x1C;
        public const byte INTEGRITY_ERROR = 0x1E;
        public const byte NO_SUCH_KEY = 0x40;
        public const byte LENGTH_ERROR = 0x7E;
        public const byte PERMISSION_DENIED = 0x9D;
        public const byte PARAMETER_ERROR = 0x9E;
        public const byte APPLICATION_NOT_FOUND = 0xA0;
        public const byte APPL_INTEGRITY_ERROR = 0xA1;
        public const byte AUTHENTICATION_CORRECT = 0xAC;
        public const byte AUTHENTICATION_ERROR = 0xAE;
        public const byte ADDITIONAL_FRAME = 0xAF;
        public const byte BOUNDARY_ERROR = 0xBE;
        public const byte CARD_INTEGRITY_ERROR = 0xC1;
        public const byte COMMAND_ABORTED = 0xCA;
        public const byte CARD_DISABLED_ERROR = 0xCD;
        public const byte COUNT_ERROR = 0xCE;
        public const byte DUPLICATE_ERROR = 0xDE;
        public const byte FILE_NOT_FOUND = 0xF0;
        public const byte FILE_INTEGRITY_ERROR = 0xF1;
        public const byte EEPROM_ERROR = 0xEE;

        public const byte COMM_MODE_PLAIN = 0x00;
        public const byte COMM_MODE_MACED = 0x01;
        public const byte COMM_MODE_CIPHER = 0x03;

        public const byte ROOT_KEY_ALLOW_CHANGE_SETTINGS = 0x08;
        public const byte ROOT_KEY_FREE_CREATE_DELETE = 0x04;
        public const byte ROOT_KEY_FREE_DIRECTORY = 0x02;
        public const byte ROOT_KEY_ALLOW_CHANGE_KEY = 0x01;

        #endregion

        #region Internal types


        protected class PendingCommand
        {
            public byte OpCode = 0;
            public int Iteration = 0;
        }

        protected PendingCommand pendingCommand;

        protected class PendingResponse
        {
            public byte Command { get; private set; }
            public byte[] Buffer { get; private set; }

            public PendingResponse(byte Command, byte[] Buffer)
            {
                this.Command = Command;
                this.Buffer = BinUtils.Copy(Buffer);
            }

            public void Append(byte[] Buffer)
            {
                this.Buffer = BinUtils.Concat(this.Buffer, Buffer);
            }
        }

        protected PendingResponse pendingResponse;

        #endregion

        #region Logger and Random

        protected IRandomGenerator RandomGenerator = new DefaultRandomGenerator();

        public void SetRandomGenerator(IRandomGenerator RandomGenerator)
        {
            this.RandomGenerator = RandomGenerator;
        }

        public void SetLogger(ILogger logger)
        {
            SetLogger(logger, false, false);
        }

        public void SetLogger(ILogger logger, bool logCrypto)
        {
            SetLogger(logger, logCrypto, false);
        }

        public void SetLogger(ILogger logger, bool logCrypto, bool logSecrets)
        {
            this.logCrypto = logCrypto;
            this.logSecrets = logSecrets;

            if (logger == null)
            {
                this.logger = new Logger(this);
            }
            else
            {
                if (logger is Logger)
                {
                    Logger _logger = new Logger(logger as Logger);
                    _logger.context = this.GetType().FullName;
                    this.logger = _logger;
                }
                else
                {
                    this.logger = new Logger(this);
                }
            }
        }

        #endregion

        #region Variables of the emulator

        internal ILogger logger;
        bool logCrypto = false;
        bool logSecrets = false;

        #endregion


        #region Variables of the emulated card

        bool IsoWrapping = false;



        protected Dictionary<uint, DesfireApplication> Applications = new Dictionary<uint, DesfireApplication>();
        protected DesfireApplication CurrentApplication = null;

        public void GetStatistics(out int ApplicationCount, out int KeyCount, out int FileCount, out int ByteCount)
        {
            ApplicationCount = 0;
            KeyCount = 0;
            FileCount = 0;
            ByteCount = 0;

            foreach (KeyValuePair<uint, DesfireApplication> kvp in Applications)
            {
                ApplicationCount++;
                ByteCount += 32;
                kvp.Value.GetStatistics(out int keyCount, out int fileCount, out int byteCount);
                KeyCount += keyCount;
                FileCount += fileCount;
                ByteCount += byteCount;
            }
        }



        protected int SendMaxSize()
        {
            return 59;
        }

        protected enum ESessionType
        {
            NONE,
            EV0,
            EV1_TDES,
            EV1_AES,
            EV2,
        }

        protected ESessionType SessionType { get; private set; } = ESessionType.NONE;

        private byte _sessionKeyNumber;
        
        public IDesfireCipher CipherContext { get; protected set; } = null;

        public const byte FREE_KEY_NUMBER = 0x0E;

        public byte SessionKeyNumber
        {
            get
            {
                if (CipherContext == null)
                    return FREE_KEY_NUMBER;

                return (byte)(_sessionKeyNumber & 0x03F);
            }
        }

        protected void InitSession(ESessionType SessionType, byte SessionKeyNumber, IDesfireCipher Cipher)
        {
            logger.trace("New session {0} (key={1:X02})", SessionType, SessionKeyNumber);
            this.SessionType = SessionType;
            this._sessionKeyNumber = SessionKeyNumber;
            this.CipherContext = Cipher;
            this.CipherContext.InitSession();
        }

        protected void ClearSession()
        {
            if (this.SessionType != ESessionType.NONE)
                logger.trace("Clear session");
            this.SessionType = ESessionType.NONE;
            this._sessionKeyNumber = 0;
            this.CipherContext = null;
        }


        #endregion

        #region Glue

        public string CardTypeName { get; private set; }
      
        private CardEmulDesfire() { } /* Make sure nobody will instantiate this class directly */

        protected CardEmulDesfire(string CardTypeName, DesfireApplication RootApplication)
        {
            logger = new Logger(this);
            Disconnect();
            this.CardTypeName = CardTypeName;
            this.RootApplication = RootApplication;
            this.RootApplication.SetMetaData(this, 0);
        }

        public override void Reconnect()
        {
            logger.trace("Reconnect");
            IsoWrapping = false;
            CurrentApplication = null;
            pendingCommand = null;
        }

        public override void Disconnect()
        {
            logger.trace("Disconnect");
            IsoWrapping = false;
            CurrentApplication = null;
            pendingCommand = null;
        }

        protected abstract ushort HandleIso7816Command(byte INS, byte P1, byte P2, CardBuffer DataIn, ref CardBuffer DataOut);

        private RAPDU OnIso7816Command(CAPDU capdu)
        {
            if (pendingCommand != null)
                pendingCommand.Iteration++;

            if ((capdu.data == null) || (capdu.data.Length == 0))
            {
                logger.trace("OnIso7816Command<INS={0:X02} P1={1:X02} P2={2:X02} (no DataIn) {3} {4}", capdu.INS, capdu.P1, capdu.P2, capdu.Lc, capdu.Le);
            }
            else
            {
                logger.trace("OnIso7816Command<INS={0:X02} P1={1:X02} P2={2:X02} DataIn={3}", capdu.INS, capdu.P1, capdu.P2, BinConvert.ToHex(capdu.data.GetBytes()));
            }

            CardBuffer dataOut = new CardBuffer();

            ushort SW = HandleIso7816Command(capdu.INS, capdu.P1, capdu.P2, new CardBuffer(capdu.DataBytes), ref dataOut);

            RAPDU rapdu;
            
            if ((dataOut == null) || (dataOut.Length == 0))
            {
                logger.debug("OnIso7816Command>SW={0:X04} (no DataOut)", SW);
                rapdu = new RAPDU(SW);
            }
            else
            {
                logger.debug("OnIso7816Command>SW={0:X04} DataOut={1}", SW, BinConvert.ToHex(dataOut.Bytes));
                rapdu = new RAPDU(dataOut.Bytes, (byte) (SW >> 8), (byte) (SW));
            }

            logger.trace("OnIso7816Command>{0} {1:X02}{2:X02}", BinConvert.ToHex(rapdu.DataBytes), rapdu.SW1, rapdu.SW2);

            return rapdu;
        }

        protected abstract byte HandleDesfireCommand(byte Command, CardBuffer DataIn, ref CardBuffer DataOut);

        private byte OnDesfireCommand(byte Command, byte[] _DataIn, out byte[] _DataOut)
        {
            logger.trace("OnDesfireCommand<{0:X02} {1}", Command, BinConvert.ToHex(_DataIn));

            byte Status;
            _DataOut = null;

            if (Command == ADDITIONAL_FRAME)
            {
                if ((pendingCommand == null) || (pendingCommand.OpCode == 0))
                    return ILLEGAL_COMMAND_CODE;

                Command = pendingCommand.OpCode;
                pendingCommand.OpCode = 0x00;
                pendingCommand.Iteration++;

            }
            else if ((pendingCommand != null) && (pendingCommand.OpCode != 0))
            {
                pendingCommand = null;
                pendingResponse = null;
                return COMMAND_ABORTED;
            }

            CardBuffer DataIn = new CardBuffer(_DataIn);
            CardBuffer DataOut = new CardBuffer();

            Status = HandleDesfireCommand(Command, DataIn, ref DataOut);

            if (Status != ADDITIONAL_FRAME)
                pendingCommand = null;

            if (pendingCommand != null)
                pendingCommand.OpCode = Command;


            _DataOut = DataOut.Bytes;
            logger.trace("OnDesfireCommand>{0:X02} {1}", Status, BinConvert.ToHex(_DataOut));

            if (Status == AUTHENTICATION_ERROR)
                ClearSession();

            return Status;
        }     

        public override byte[] Transmit(byte[] command)
        {
            byte[] response = null;

            logger.debug("Transmit<{0}", BinConvert.ToHex(command));

            if ((command[0] == 0x00) && (command.Length > 5))
            {
                /* This MUST be an ISO 7816-4 command */
                CAPDU capdu = new CAPDU(command);

                RAPDU rapdu = OnIso7816Command(capdu);

                response = rapdu.Bytes;
            }
            else
            {
                /* This MAY be a DESFire command */

                if (!IsoWrapping)
                {
                    if ((command[0] == 0x90) && (command.Length > 5))
                        IsoWrapping = true;
                }

                byte INS;
                byte[] dataIn;

                if (IsoWrapping)
                {
                    CAPDU c = new CAPDU(command);
                    INS = c.INS;
                    dataIn = c.DataBytes;
                }
                else
                {
                    INS = command[0];
                    dataIn = BinUtils.Copy(command, 1);
                }

                byte status = OnDesfireCommand(INS, dataIn, out byte[] dataOut);

                if (IsoWrapping)
                {
                    response = new byte[] { 0x91, status };
                    if (dataOut != null)
                        response = BinUtils.Concat(dataOut, response);
                }
                else
                {
                    response = BinUtils.Concat(status, dataOut);
                }
            }

            logger.debug("Transmit>{0}", BinConvert.ToHex(response));
            return response;
        }

        #endregion

        #region Card basis

        protected byte[] CardUID = new byte[7] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

        public void SetCardUID(byte[] CardUID)
        {
            this.CardUID = CardUID;
        }

        public byte FormatPICC(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            logger.debug("FormatPICC");
            CurrentApplication = null;
            Applications.Clear();
            return OPERATION_OK;
        }

        public byte GetVersion(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (pendingCommand == null)
                pendingCommand = new PendingCommand();

            switch (pendingCommand.Iteration)
            {
                case 0:
                    DataOut = new CardBuffer("04010101001A05");
                    return ADDITIONAL_FRAME;
                case 1:
                    DataOut = new CardBuffer("04010101041A05");
                    return ADDITIONAL_FRAME;
                case 2:
                    DataOut = new CardBuffer("112233445566771122334455AABB");
                    return OPERATION_OK;
            }

            return INTERNAL_ERROR;
        }
        #endregion

        #region Application manipulation

        protected byte SelectApplication(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (!CheckIn(DataIn, 3))
                return LENGTH_ERROR;

            uint Aid = Get3(DataIn.GetBytes(0, 3));

            if (SelectApplication(Aid))
                return OPERATION_OK;

            return APPLICATION_NOT_FOUND;
        }

        public bool SelectApplication(uint Aid)
        {
            logger.debug("SelectApplication({0:X06})", Aid);

            ClearSession();

            if (Aid == 0)
            {
                CurrentApplication = null;
                return true;
            }

            if (!Applications.ContainsKey(Aid))
            {
                logger.debug("Application {0:X06} not found", Aid);
                return false;
            }

            CurrentApplication = Applications[Aid];
            CurrentApplication.CurrentFile = null;
            logger.debug("Application {0:X06} found", Aid);
            return true;
        }





        #endregion


        #region File manipulation





        protected byte GetFileSettings(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (!CheckIn(DataIn, 1))
                return LENGTH_ERROR;

            byte file_id = DataIn.GetByte(0);
            byte[] r;

            if (CurrentApplication == null)
                return FILE_NOT_FOUND;

            if (!CurrentApplication.SelectFile(file_id))
                return FILE_NOT_FOUND;

            r = CurrentApplication.CurrentFile.GetFileSettings();
            DataOut = new CardBuffer(r);
            return OPERATION_OK;
        }

        private byte FileSize(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            return INTERNAL_ERROR;
        }


        #endregion


        #region Transactions
        public byte CommitTransaction(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (CurrentApplication == null)
                return PERMISSION_DENIED;

            if (CurrentApplication.Commit())
                return OPERATION_OK;

            return EEPROM_ERROR;
        }

        public byte AbortTransaction(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (CurrentApplication == null)
                return PERMISSION_DENIED;

            if (CurrentApplication.Abort())
                return OPERATION_OK;

            return EEPROM_ERROR;
        }
        #endregion

        #region Authentication and ciphering
        protected class PendingAuthenticate : PendingCommand
        {
            public byte KeyNumber;
            public DesfireKey AuthKey;
            public IDesfireCipher Cipher;
            public byte[] PcdCap2;
            public byte[] RndPcd;
            public byte[] RndPicc;
        }





        #endregion

        #region Misc

        public bool CheckIn(CardBuffer DataIn, int minLen, int maxLen)
        {
            if (DataIn == null)
            {
                if (minLen > 0)
                {
                    logger.debug("Expected at least {0}B, got none", minLen);
                    return false;
                }
            }
            else if (DataIn.Length < minLen)
            {
                logger.debug("Expected at least {0}B, got {1}", minLen, DataIn.Length);
                return false;
            }
            else if (DataIn.Length > maxLen)
            {
                logger.debug("Expected at most {0}B, got {1}", maxLen, DataIn.Length);
                return false;
            }
            return true;
        }

        public bool CheckIn(CardBuffer DataIn, int Len)
        {
            return CheckIn(DataIn, Len, Len);
        }

        public long Get4(byte[] buf, int offset)
        {
            uint t;
            int r;

            t = buf[offset + 3];
            t *= 0x00000100;
            t += buf[offset + 2];
            t *= 0x00000100;
            t += buf[offset + 1];
            t *= 0x00000100;
            t += buf[offset + 0];

            if (t < 0x80000000)
                r = (int)t;
            else
                r = (int)(t - 0x100000000);

            return r;
        }

        public long Get4(byte[] buf)
        {
            return Get4(buf, 0);
        }

        public uint Get3(byte[] buf, uint offset)
        {
            uint r;

            r = buf[offset + 2];
            r *= 0x00000100;
            r += buf[offset + 1];
            r *= 0x00000100;
            r += buf[offset + 0];

            return r;
        }

        public uint Get3(byte[] buf)
        {
            return Get3(buf, 0);
        }

        public ushort Get2(byte[] buf, uint offset)
        {
            ushort r;

            r = buf[offset + 1];
            r *= 0x0100;
            r += buf[offset + 0];

            return r;
        }

        public ushort Get2(byte[] buf)
        {
            return Get2(buf, 0);
        }

        public void Set4(ref byte[] buf, uint offset, long val)
        {
            uint t;

            if (val >= 0)
                t = (uint)val;
            else
                t = (uint)(val + 0x100000000);

            buf[offset + 0] = (byte)(t % 0x00000100);
            t /= 0x00000100;
            buf[offset + 1] = (byte)(t % 0x00000100);
            t /= 0x00000100;
            buf[offset + 2] = (byte)(t % 0x00000100);
            t /= 0x00000100;
            buf[offset + 3] = (byte)(t % 0x00000100);
        }

        public void Set3(ref byte[] buf, uint offset, int val)
        {
            Set3(ref buf, offset, (uint)val);
        }

        public void Set3(ref byte[] buf, uint offset, uint val)
        {
            buf[offset + 0] = (byte)(val % 0x00000100);
            val /= 0x00000100;
            buf[offset + 1] = (byte)(val % 0x00000100);
            val /= 0x00000100;
            buf[offset + 2] = (byte)(val % 0x00000100);
        }

        public void Set2(ref byte[] buf, uint offset, ushort val)
        {
            buf[offset + 0] = (byte)(val % 0x0100);
            val /= 0x0100;
            buf[offset + 1] = (byte)(val % 0x0100);
        }
        #endregion
    }
}
