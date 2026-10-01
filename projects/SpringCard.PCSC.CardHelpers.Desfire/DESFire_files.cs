/*
 * Created by SharpDevelop.
 * User: Jerome Izaac
 * Date: 13/09/2017
 * Time: 15:49
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using SpringCard.LibCs;
using System;
using System.Collections.Generic;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of DESFire_files.
    /// </summary>
    public partial class Desfire
    {
        /**
 * @file
 * @brief *   DesfireAPI :: File management functions
 * @details *   Implementation of management functions to create or delete
 * @copyright *   (c) 2009 SpringCard - www.springcard.com
 */
        private void PrepareCreateFileCommand(byte CreateCmd, byte FileId, byte CommMode, ushort AccessRights)
        {
            PrepareCreateFileCommand(CreateCmd, FileId, false, 0, CommMode, AccessRights);
        }
        private void PrepareCreateFileCommand(byte CreateCmd, byte FileId, uint IsoEfId, byte CommMode, ushort AccessRights)
        {
            PrepareCreateFileCommand(CreateCmd, FileId, true, IsoEfId, CommMode, AccessRights);
        }

        private void PrepareCreateFileCommand(byte CreateCmd, byte FileId, bool UseIsoEfId, uint IsoEfId, byte CommMode, ushort AccessRights)
        {
            xfer_length = 0;

            /* Create the info block containing the command code and the given parameters. */
            xfer_buffer[xfer_length++] = CreateCmd;

            xfer_buffer[xfer_length++] = FileId;

            if (UseIsoEfId)
            {
                xfer_buffer[xfer_length++] = (byte)(IsoEfId & 0x00FF); IsoEfId >>= 8;
                xfer_buffer[xfer_length++] = (byte)(IsoEfId & 0x00FF);
            }

            xfer_buffer[xfer_length++] = CommMode;

            xfer_buffer[xfer_length++] = (byte)(AccessRights & 0x00FF); AccessRights >>= 8;
            xfer_buffer[xfer_length++] = (byte)(AccessRights & 0x00FF);
        }

        public long CreateStdDataFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, int FileSize)
        {
            return CreateStdDataFile(FileId, (byte)CommMode, AccessRights.Value, FileSize);
        }

        public long CreateStdDataFile(byte FileId, byte CommMode, ushort AccessRights, int FileSize)
        {
            PrepareCreateFileCommand((byte)DesfireCommand.CREATE_STD_DATA_FILE, FileId, CommMode, AccessRights);

            xfer_buffer[xfer_length++] = (byte)(FileSize & 0x00FF); FileSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(FileSize & 0x00FF); FileSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(FileSize & 0x00FF);

            if (SessionIsEV2OrGreater())
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }

        /**
 * @fn *   CreateIsoStdDataFile
 * @brief *   Creates files for the storage of plain unformatted user data within an existing application
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : creation succeeded
 * @note *   Please refer to DESFIRE datasheet for details regarding this function and its
 */
        public long CreateIsoStdDataFile(byte FileId, ushort IsoEfId, byte CommMode, ushort AccessRights, int FileSize)
        {
            PrepareCreateFileCommand((byte)DesfireCommand.CREATE_STD_DATA_FILE, FileId, IsoEfId, CommMode, AccessRights);

            xfer_buffer[xfer_length++] = (byte)(FileSize & 0x00FF); FileSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(FileSize & 0x00FF); FileSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(FileSize & 0x00FF);

            if (SessionIsEV2OrGreater())
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }

        public long CreateBackupDataFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, int FileSize)
        {
            return CreateBackupDataFile(FileId, (byte)CommMode, AccessRights.Value, FileSize);
        }

        public long CreateBackupDataFile(byte FileId, byte CommMode, ushort AccessRights, int FileSize)
        {
            PrepareCreateFileCommand((byte)DesfireCommand.CREATE_BACKUP_DATA_FILE, FileId, CommMode, AccessRights);

            xfer_buffer[xfer_length++] = (byte)(FileSize & 0x000000FF); FileSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(FileSize & 0x000000FF); FileSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(FileSize & 0x000000FF);

            if (SessionIsEV2OrGreater())
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {

                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }

        /**
 * @fn *   CreateIsoBackupDataFile
 * @brief *   Creates files for the storage of plain unformatted user data within an existing application
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : Backup Data File  succeeded
 * @note *   Please refer to DESFIRE datasheet for details regarding this function and its
 */
        public long CreateIsoBackupDataFile(byte FileId, ushort IsoEfId, byte CommMode, ushort AccessRights, int FileSize)
        {
            PrepareCreateFileCommand((byte)DesfireCommand.CREATE_BACKUP_DATA_FILE, FileId, IsoEfId, CommMode, AccessRights);

            xfer_buffer[xfer_length++] = (byte)(FileSize & 0x000000FF); FileSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(FileSize & 0x000000FF); FileSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(FileSize & 0x000000FF);

            if (SessionIsEV2OrGreater())
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {

                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }

        public long CreateValueFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, long LowerLimit, long UpperLimit, long InitialValue, bool LimitedCreditEnabled)
        {
            return CreateValueFile(FileId, (byte)CommMode, AccessRights.Value, LowerLimit, UpperLimit, InitialValue, LimitedCreditEnabled);
        }

        public long CreateValueFile(byte FileId, byte CommMode, ushort AccessRights, long LowerLimit, long UpperLimit, long InitialValue, bool LimitedCreditEnabled)
        {
            return CreateValueFile(FileId, CommMode, AccessRights, LowerLimit, UpperLimit, InitialValue, LimitedCreditEnabled, false);
        }

        public long CreateValueFile(byte FileId, byte CommMode, ushort AccessRights, long LowerLimit, long UpperLimit, long InitialValue, bool LimitedCreditEnabled, bool FreeGetValue)
        {
            byte flags = 0;
            if (LimitedCreditEnabled)
                flags |= 0x01;
            if (FreeGetValue)
                flags |= 0x02;
            return CreateValueFile(FileId, CommMode, AccessRights, LowerLimit, UpperLimit, InitialValue, flags);
        }

        public long CreateValueFile(byte FileId, byte CommMode, ushort AccessRights, long LowerLimit, long UpperLimit, long InitialValue, byte Flags)
        {
            PrepareCreateFileCommand((byte)DesfireCommand.CREATE_VALUE_FILE, FileId, CommMode, AccessRights);

            xfer_buffer[xfer_length++] = (byte)(LowerLimit & 0x000000FF); LowerLimit >>= 8;
            xfer_buffer[xfer_length++] = (byte)(LowerLimit & 0x000000FF); LowerLimit >>= 8;
            xfer_buffer[xfer_length++] = (byte)(LowerLimit & 0x000000FF); LowerLimit >>= 8;
            xfer_buffer[xfer_length++] = (byte)(LowerLimit & 0x000000FF);

            xfer_buffer[xfer_length++] = (byte)(UpperLimit & 0x000000FF); UpperLimit >>= 8;
            xfer_buffer[xfer_length++] = (byte)(UpperLimit & 0x000000FF); UpperLimit >>= 8;
            xfer_buffer[xfer_length++] = (byte)(UpperLimit & 0x000000FF); UpperLimit >>= 8;
            xfer_buffer[xfer_length++] = (byte)(UpperLimit & 0x000000FF);

            xfer_buffer[xfer_length++] = (byte)(InitialValue & 0x000000FF); InitialValue >>= 8;
            xfer_buffer[xfer_length++] = (byte)(InitialValue & 0x000000FF); InitialValue >>= 8;
            xfer_buffer[xfer_length++] = (byte)(InitialValue & 0x000000FF); InitialValue >>= 8;
            xfer_buffer[xfer_length++] = (byte)(InitialValue & 0x000000FF);

            xfer_buffer[xfer_length++] = Flags;

            if (SessionIsEV2OrGreater())
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }

        public long CreateLinearRecordFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, int RecordSize, int MaxRecords)
        {
            return CreateLinearRecordFile(FileId, (byte)CommMode, AccessRights.Value, RecordSize, MaxRecords);
        }

        public long CreateLinearRecordFile(byte FileId, byte CommMode, ushort AccessRights, int RecordSize, int MaxRecords)
        {
            PrepareCreateFileCommand((byte)DesfireCommand.CREATE_LINEAR_RECORD_FILE, FileId, CommMode, AccessRights);

            xfer_buffer[xfer_length++] = (byte)(RecordSize & 0x000000FF); RecordSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(RecordSize & 0x000000FF); RecordSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(RecordSize & 0x000000FF);

            xfer_buffer[xfer_length++] = (byte)(MaxRecords & 0x000000FF); MaxRecords >>= 8;
            xfer_buffer[xfer_length++] = (byte)(MaxRecords & 0x000000FF); MaxRecords >>= 8;
            xfer_buffer[xfer_length++] = (byte)(MaxRecords & 0x000000FF);

            if (SessionIsEV2OrGreater())
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* Communicate the info block to the card and check the operation's return status. */
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }

        /**
 * @fn *   CreateIsoLinearRecordFile
 * @brief *   Creates a linear record file.
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : file created successfully
 * @note *   Please refer to DESFIRE datasheet for details regarding this function and its
 */
        public long CreateIsoLinearRecordFile(byte FileId, ushort IsoEfId, byte CommMode, ushort AccessRights, int RecordSize, int MaxRecords)
        {
            PrepareCreateFileCommand((byte)DesfireCommand.CREATE_LINEAR_RECORD_FILE, FileId, IsoEfId, CommMode, AccessRights);

            xfer_buffer[xfer_length++] = (byte)(RecordSize & 0x000000FF); RecordSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(RecordSize & 0x000000FF); RecordSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(RecordSize & 0x000000FF);

            xfer_buffer[xfer_length++] = (byte)(MaxRecords & 0x000000FF); MaxRecords >>= 8;
            xfer_buffer[xfer_length++] = (byte)(MaxRecords & 0x000000FF); MaxRecords >>= 8;
            xfer_buffer[xfer_length++] = (byte)(MaxRecords & 0x000000FF);

            if (SessionIsEV2OrGreater())
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* Communicate the info block to the card and check the operation's return status. */
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }


        public long CreateCyclicRecordFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, int RecordSize, int MaxRecords)
        {
            return CreateCyclicRecordFile(FileId, (byte)CommMode, AccessRights.Value, RecordSize, MaxRecords);
        }

        public long CreateCyclicRecordFile(byte FileId, byte CommMode, ushort AccessRights, int RecordSize, int MaxRecords)
        {
            PrepareCreateFileCommand((byte)DesfireCommand.CREATE_CYCLIC_RECORD_FILE, FileId, CommMode, AccessRights);

            xfer_buffer[xfer_length++] = (byte)(RecordSize & 0x000000FF); RecordSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(RecordSize & 0x000000FF); RecordSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(RecordSize & 0x000000FF);

            xfer_buffer[xfer_length++] = (byte)(MaxRecords & 0x000000FF); MaxRecords >>= 8;
            xfer_buffer[xfer_length++] = (byte)(MaxRecords & 0x000000FF); MaxRecords >>= 8;
            xfer_buffer[xfer_length++] = (byte)(MaxRecords & 0x000000FF);

            if (SessionIsEV2OrGreater())
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* Communicate the info block to the card and check the operation's return status. */
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }

        /**
 * @fn *   CreateIsoCyclicRecordFile
 * @brief *   Creates a cyclic record file.
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : file created successfully
 * @note *   Please refer to DESFIRE datasheet for details regarding this function and its
 */
        public long CreateIsoCyclicRecordFile(byte FileId, ushort IsoEfId, byte CommMode, ushort AccessRights, int RecordSize, int MaxRecords)
        {
            PrepareCreateFileCommand((byte)DesfireCommand.CREATE_CYCLIC_RECORD_FILE, FileId, IsoEfId, CommMode, AccessRights);

            xfer_buffer[xfer_length++] = (byte)(RecordSize & 0x000000FF); RecordSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(RecordSize & 0x000000FF); RecordSize >>= 8;
            xfer_buffer[xfer_length++] = (byte)(RecordSize & 0x000000FF);

            xfer_buffer[xfer_length++] = (byte)(MaxRecords & 0x000000FF); MaxRecords >>= 8;
            xfer_buffer[xfer_length++] = (byte)(MaxRecords & 0x000000FF); MaxRecords >>= 8;
            xfer_buffer[xfer_length++] = (byte)(MaxRecords & 0x000000FF);

            if (SessionIsEV2OrGreater())
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* Communicate the info block to the card and check the operation's return status. */
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }

        public long DeleteFile(byte FileId)
        {
            /* Create the info block containing the command code and the given parameters. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.DELETE_FILE;
            xfer_buffer[INF + 1] = FileId;
            xfer_length = 2;

            if (SessionIsEV2OrGreater())
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* Communicate the info block to the card and check the operation's return status. */
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }

        public long GetFileSettings(byte FileId, out DesfireFileType FileType, out DesfireCommMode CommMode, out DesfireAccessRights AccessRights, out DesfireFileSettings AdditionnalSettings)
        {
            long status = GetFileSettings(FileId, out byte bFileType, out byte bCommMode, out ushort wAccessRights, out AdditionnalSettings);
            FileType = (DesfireFileType)bFileType;
            CommMode = (DesfireCommMode)bCommMode;
            AccessRights = new DesfireAccessRights(wAccessRights);
            return status;
        }

        public long GetFileSettings(byte FileId, out byte FileType, out byte CommMode, out ushort AccessRights, out DesfireFileSettings AdditionnalSettings)
        {
            long status = LibraryError(DesfireLibraryError.WrongLength);
            int temp;

            CommMode = 0;
            FileType = 0;
            AccessRights = 0;
            AdditionnalSettings = null;

            // create command code and append FileID parameter 
            xfer_buffer[INF + 0] = (byte)DesfireCommand.GET_FILE_SETTINGS;
            xfer_buffer[INF + 1] = FileId;
            xfer_length = 2;

            /* EV2 secure mode */

            if (SessionIsEV2OrGreater())
            {
                /* Under active authentication, the command Cmd.GetFileSettings requires CommMode.MAC */
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                // don't do any implicit length check on the response
                // this has to be resolved depending on the file type 
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }


            if (status != Success)
                return status;


            // there is a fixed section of the response which is common to all file types 
            // therefore the response must at least be of this fixed length              
            // Note the status byte had to be extract!                                  
            xfer_length--;                 // subtract 1 byte for the received status of desfire card
            if (xfer_length < FILE_SETTINGS_COMMON_LENGTH)
                return LibraryError(DesfireLibraryError.WrongLength);

            // extract the file's type 
            FileType = xfer_buffer[INF + 1];

            // extract the file's communication mode
            CommMode = xfer_buffer[INF + 2];

            //extract the file's access rights 
            AccessRights = xfer_buffer[INF + 4];
            AccessRights <<= 8;
            AccessRights += xfer_buffer[INF + 3];

            // the rest of the buffer contains file type specific information      
            // therefore we have to resolve it according to the received file type 
            xfer_length -= FILE_SETTINGS_COMMON_LENGTH; // subtract for the fixed section 
            switch ((DesfireFileType)FileType)
            {
                case DesfireFileType.StandardData:
                case DesfireFileType.BackupData:

                    if (xfer_length != DATA_FILE_SETTINGS_LENGTH)
                        return LibraryError(DesfireLibraryError.WrongLength);

                    DesfireDataFileSettings data_settings = new DesfireDataFileSettings();

                    // extract the file size 
                    temp = xfer_buffer[INF + 7];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 6];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 5];

                    data_settings.FileSize = temp;

                    AdditionnalSettings = new DesfireFileSettings(data_settings);
                    break;

                case DesfireFileType.Value:

                    if (xfer_length != VALUE_FILE_SETTINGS_LENGTH)
                        return LibraryError(DesfireLibraryError.WrongLength);

                    DesfireValueFileSettings value_settings = new DesfireValueFileSettings();

                    // extract the lower limit 
                    temp = xfer_buffer[INF + 8];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 7];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 6];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 5];
                    value_settings.LowerLimit = /*(Int32)*/ temp;

                    // extract the upper limit 
                    temp = xfer_buffer[INF + 12];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 11];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 10];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 9];
                    value_settings.UpperLimit = /*(Int32)*/ temp;

                    // extract the limited credit value
                    temp = xfer_buffer[INF + 16];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 15];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 14];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 13];
                    value_settings.LimitedCredit = temp;

                    // limited Credit enabled ?
                    value_settings.LimitedCreditEnabled = (xfer_buffer[INF + 17] > 0) ? true : false;

                    AdditionnalSettings = new DesfireFileSettings(value_settings);
                    break;

                case DesfireFileType.LinearRecord:
                case DesfireFileType.CyclicRecord:

                    if (xfer_length != RECORD_FILE_SETTINGS_LENGTH)
                        return LibraryError(DesfireLibraryError.WrongLength);

                    DesfireRecordFileSettings record_settings = new DesfireRecordFileSettings();

                    // extract the number of entire records 
                    temp = xfer_buffer[INF + 7];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 6];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 5];
                    record_settings.RecordSize = temp;

                    // get the size of one record 
                    temp = xfer_buffer[INF + 10];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 9];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 8];
                    record_settings.MaxRecordCount = temp;

                    // get the current number of records 
                    temp = xfer_buffer[INF + 13];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 12];
                    temp <<= 8;
                    temp += xfer_buffer[INF + 11];
                    record_settings.CurrentRecordCount = temp;

                    AdditionnalSettings = new DesfireFileSettings(record_settings);
                    break;

                default:
                    // Unknown file type 
                    return LibraryError(DesfireLibraryError.WrongFileType);
            }

            return Success;
        }

        public long ChangeFileSettings(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights)
        {
            return ChangeFileSettings(FileId, (byte)CommMode, AccessRights.Value);
        }

        public long ChangeFileSettings(byte FileId, byte CommMode, ushort AccessRights)
        {
            ushort comm_encrypted;
            long status;

            // Before being able to send the new file settings to the PICC, we need to know whether 
            // the current access rights setting requires the communication to be encrypted.       
            status = GetFileSettings(FileId, out byte fileType, out byte currentCommMode, out ushort currentAccessRights, out DesfireFileSettings fileSettings);
            if (status != Success)
                return status;

            logger.trace("ChangeFileSettings({0:X02},{1:X02},{2:X04})", FileId, CommMode, AccessRights);

            comm_encrypted = (ushort)(currentAccessRights & DesfireAccessRights.ChangeRights_Mask);

            // Create the info block containing the command code and the given parameters. 
            xfer_length = 0;

            xfer_buffer[xfer_length++] = (byte)DesfireCommand.CHANGE_FILE_SETTINGS;
            xfer_buffer[xfer_length++] = FileId;
            xfer_buffer[xfer_length++] = CommMode;

            xfer_buffer[xfer_length++] = (byte)(AccessRights & 0x00FF); AccessRights >>= 8;
            xfer_buffer[xfer_length++] = (byte)(AccessRights & 0x00FF);

            /* EV2 secure mode */
            if (SessionIsEV2OrGreater())
            {
                if (comm_encrypted != 0x0E)
                {
                    logger.trace("\t-> Encrypted EV2");

                    Xfer_Padd_CipherSend(2);
                    Xfer_AppendCmac();

                    return Command(0, DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
                }
                else
                {
                    logger.trace("\t-> Plain (EV2)");

                    // Communicate the info block to the card and check the operation's return status.
                    return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
                }
            }
            else
            {
                if (comm_encrypted != 0x0E)
                {
                    logger.trace("\t-> Encrypted EV0 or EV1");

                    // If encrypted communication is requested, append a CRC, computed over the communication mode         
                    // and access rights arguments (3bytes), to the command string. Then 'Encrypt' these arguments and the 
                    // CRC to ensure that only an authenticated PCD can change the settings.                              
                    XferAppendCrc(2);
                    Xfer_Padd_CipherSend(2);

                    // Communicate the info block to the card and check the operation's return status.
                    return Command(0, DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
                }
                else
                {
                    logger.trace("\t-> Plain (EV0 or EV1)");

                    // Communicate the info block to the card and check the operation's return status.
                    return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
                }
            }
        }

        public long GetFileIDs(out byte[] ListData)
        {
            byte i;
            long status;

            ListData = null;
            List<byte> _ListData = new List<byte>();

            /* create the info block containing the command code */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.GET_FILE_IDS;
            xfer_length = 1;

            /* EV2 secure mode */
            if (SessionIsEV2OrGreater())
            {
                /* Under active authentication, the command Cmd.GetFileSettings requires CommMode.MAC */
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* this command terminates within a single frame (no additional frames necessary) */
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            if (status != Success)
                return status;

            for (i = 0; (byte)(INF + 1 + i) < xfer_length; i++)
                _ListData.Add(xfer_buffer[INF + 1 + i]);

            ListData = _ListData.ToArray();
            return Success;
        }


        public long GetIsoFileIDs(out ushort[] EfIsList)
        {
            EfIsList = null;

            long status;
            byte max_count = 64;
            ushort[] _list = new ushort[max_count];

            status = GetIsoFileIDs(max_count, ref _list, out byte actual_count);
            if (status != Success)
                return status;

            EfIsList = new ushort[actual_count];
            for (byte i = 0; i < actual_count; i++)
                EfIsList[i] = _list[i];

            return Success;
        }

        public long GetIsoFileIDs(byte MaxListCount, ref ushort[] ListData, out byte ActualListCount)
        {
            byte i, c = 0;
            long status;

            /* reset the number of found FileIDs */
            ActualListCount = 0;

            /* create the info block containing the command code */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.GET_ISO_FILE_IDS;
            xfer_length = 1;

        again:

            /* EV2 secure mode */
            if (SessionIsEV2OrGreater())
            {
                /* Under active authentication, the command Cmd.GetFileSettings requires CommMode.MAC */
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME);
            }
            else
            {
                status = Command(0, DesfireCommandFlag.WANTS_OPERATION_OK | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME);
            }

            if (status != Success)
                return status;

            for (i = 0; (byte)(INF + 1 + i) < xfer_length; i += 2)
            {
                if ((ListData != null) && (c < MaxListCount))
                {
                    ListData[c] = xfer_buffer[INF + 2 + i];
                    ListData[c] <<= 8;
                    ListData[c] |= xfer_buffer[INF + 1 + i];
                }
                c++;
            }

            if (xfer_buffer[INF + 0] == (byte) DesfireCardError.AdditionalFrame)
            {
                xfer_length = 1;
                goto again;
            }


            ActualListCount = c;

            if (c > MaxListCount)
                return LibraryError(DesfireLibraryError.Overflow);

            return Success;
        }

    }
}
