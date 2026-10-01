/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {

        /**
         * @brief Structure returned by the card in response to the GetApplicationIDs command
         */
        public struct DesfireIsoApplication
        {
            public uint Aid;
            public ushort IsoId;
            public byte[] IsoName;
        }

        /**
         * @brief Structure returned by the card in response to the GetVersion command
         */
        public struct DesfireVersionInfo
        {
            public byte HwVendorID;
            public byte HwType;
            public byte HwSubType;
            public byte HwMajorVersion;
            public byte HwMinorVersion;
            public byte HwStorageSize;
            public byte HwProtocol;
            public byte SwVendorID;
            public byte SwType;
            public byte SwSubType;
            public byte SwMajorVersion;
            public byte SwMinorVersion;
            public byte SwStorageSize;
            public byte SwProtocol;
            public byte[] Uid;
            public byte[] BatchNo;
            public byte ProductionCW;
            public byte ProductionYear;
        }

        /**
         * @brief Detailed structure returned by the card in response to the GetFileSettings command when the file is a Data (Standard or Backup) file
         */

        public struct DesfireDataFileSettings
        {
            public int FileSize;
        }

        /**
         * @brief Detailed structure returned by the card in response to the GetFileSettings command when the file is a Record (Linear or Cyclic) file
         */
        public struct DesfireRecordFileSettings
        {
            public int RecordSize;
            public int MaxRecordCount;
            public int CurrentRecordCount;
        };

        /**
         * @brief Detailed structure returned by the card in response to the GetFileSettings command when the file is a Value file
         */
        public struct DesfireValueFileSettings
        {
            public long LowerLimit;
            public long UpperLimit;
            public int LimitedCredit;
            public bool LimitedCreditEnabled;
        }

        /**
         * @brief Structure returned by the card in response to the GetFileSettings command
         */

        public class DesfireFileSettings
        {
            /**
             * @brief Type of the file
             */
            public enum FileSettingsType
            { 
                Data, //<- Data (Standard or Backup) file
                Value, //<- Value file
                Record //<- Record (Linear or Cyclic) file
            };

            /**
             * @brief Type of the file
             */
            public FileSettingsType Type { get; private set; }

            /*
             * @brief Details is file is a Data file
             */
            public DesfireDataFileSettings DataFile { get; private set; }
            internal DesfireFileSettings(DesfireDataFileSettings DataFile)
            {
                this.DataFile = DataFile;
                this.Type = FileSettingsType.Data;
            }

            /*
             * @brief Details is file is a Value file
             */
            public DesfireValueFileSettings ValueFile { get; private set; }
            internal DesfireFileSettings(DesfireValueFileSettings ValueFile)
            {
                this.ValueFile = ValueFile;
                this.Type = FileSettingsType.Value;
            }

            /*
             * @brief Details is file is a Record file
             */
            public DesfireRecordFileSettings RecordFile { get; private set; }
            internal DesfireFileSettings(DesfireRecordFileSettings RecordFile)
            {
                this.RecordFile = RecordFile;
                this.Type = FileSettingsType.Record;
            }
        }
    }
}
