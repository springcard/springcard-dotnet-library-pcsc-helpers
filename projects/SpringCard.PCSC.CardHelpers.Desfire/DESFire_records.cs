/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using SpringCard.LibCs;
using System.Collections.Generic;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        #region Clear Record File

        /**
         * @brief Clears all records in a record file.
         *
         * @param FileId The file ID to clear.
         * @return A status code indicating the result of the operation.
         */
        public long ClearRecordFile(byte FileId)
        {
            xfer_buffer[INF + 0] = (byte)DesfireCommand.CLEAR_RECORD_FILE;
            xfer_buffer[INF + 1] = FileId;
            xfer_length = 2;

            if (SessionIsEV2OrGreater())
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* response must be of one byte length if successfully terminated */
                return Command(1, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }

        #endregion

        #region Read Record File

        /**
         * @brief Reads a specific record from a record file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param RecordNumber The record number to read.
         * @param RecordSize The size of the record in bytes.
         * @param[out] Data A byte array containing the read record data.
         * @return A status code indicating the result of the operation.
         */
        public long ReadRecord(byte FileId, DesfireCommMode CommMode, int RecordNumber, int RecordSize, out byte[] Data)
        {
            return ReadRecord(FileId, (byte)CommMode, RecordNumber, RecordSize, out Data);
        }

        /**
         * @brief Reads a specific record from a record file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param RecordNumber The record number to read.
         * @param RecordSize The size of the record in bytes.
         * @param[out] Data A byte array containing the read record data.
         * @return A status code indicating the result of the operation.
         */

        public long ReadRecord(byte FileId, byte CommMode, int RecordNumber, int RecordSize, out byte[] Data)
        {
            return ReadRecords(FileId, CommMode, RecordNumber, 1, RecordSize, out Data, out int dummy);
        }

        /**
         * @brief Reads multiple records from a record file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param RecordSize The size of each record in bytes.
         * @param[out] Data A list of byte arrays containing the read records.
         * @return A status code indicating the result of the operation.
         */
        public long ReadRecords(byte FileId, DesfireCommMode CommMode, int FromRecord, int MaxCount, int RecordSize, out List<byte[]> Data)
        {
            return ReadRecords(FileId, (byte)CommMode, FromRecord, MaxCount, RecordSize, out Data);
        }

        /**
         * @brief Reads multiple records from a record file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param RecordSize The size of each record in bytes.
         * @param[out] Data A list of byte arrays containing the read records.
         * @return A status code indicating the result of the operation.
         */

        public long ReadRecords(byte FileId, byte CommMode, int FromRecord, int MaxCount, int RecordSize, out List<byte[]> Data)
        {
            long status = ReadRecords(FileId, CommMode, FromRecord, MaxCount, RecordSize, out byte[] buffer, out int ActualCount);
            if (status != Success)
            {
                Data = null;
                return status;
            }

            Data = new List<byte[]>();
            for (int i = 0; i < ActualCount; i++)
            {
                Data.Add(BinUtils.Copy(buffer, i * RecordSize, RecordSize));
            }

            return Success;
        }

        /**
         * @brief Reads multiple records from a record file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param RecordSize The size of each record in bytes.
         * @param[out] Data A byte array containing the concatenated read records.
         * @return A status code indicating the result of the operation.
         */

        public long ReadRecords(byte FileId, DesfireCommMode CommMode, int FromRecord, int MaxCount, int RecordSize, out byte[] Data)
        {
            return ReadRecords(FileId, (byte)CommMode, FromRecord, MaxCount, RecordSize, out Data);
        }

        /**
         * @brief Reads multiple records from a record file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param RecordSize The size of each record in bytes.
         * @param[out] Data A byte array containing the concatenated read records.
         * @return A status code indicating the result of the operation.
         */
        public long ReadRecords(byte FileId, byte CommMode, int FromRecord, int MaxCount, int RecordSize, out byte[] Data)
        {
            return ReadRecords(FileId, CommMode, FromRecord, MaxCount, RecordSize, out Data, out int dummy);
        }

        /**
         * @brief Reads multiple records from a record file and retrieves the actual count of records read.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param RecordSize The size of each record in bytes.
         * @param[out] Data A byte array containing the concatenated read records.
         * @param[out] ActualCount The actual number of records read.
         * @return A status code indicating the result of the operation.
         */
        public long ReadRecords(byte FileId, DesfireCommMode CommMode, int FromRecord, int MaxCount, int RecordSize, out byte[] Data, out int ActualCount)
        {
            return ReadRecords(FileId, (byte)CommMode, FromRecord, MaxCount, RecordSize, out Data, out ActualCount);
        }

        /**
         * @brief Reads multiple records from a record file and retrieves the actual count of records read.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param RecordSize The size of each record in bytes.
         * @param[out] Data A byte array containing the concatenated read records.
         * @param[out] ActualCount The actual number of records read.
         * @return A status code indicating the result of the operation.
         */
        public long ReadRecords(byte FileId, byte CommMode, int FromRecord, int MaxCount, int RecordSize, out byte[] Data, out int ActualCount)
        {
            long status;

            ActualCount = 0;

            /* if a pointer was passed for retrieving the number of records read    */
            /* and no record size was specified, we have to get the record size via */
            /* the GetFileSettings command                                          */
            if (RecordSize == 0)
            {
                status = GetFileSettings(FileId, out byte fileType, out byte _CommMode, out ushort accessRights, out DesfireFileSettings file_settings);

                if (status != Success)
                {
                    Data = null;
                    return status;
                }

                /* if the file type indicates that this is not a record file */
                /* we are not able to proceed                                */
                if (((DesfireFileType)fileType != DesfireFileType.LinearRecord) && ((DesfireFileType)fileType != DesfireFileType.CyclicRecord))
                {
                    Data = null;
                    return LibraryError(DesfireLibraryError.WrongFileType);
                }

                RecordSize = file_settings.RecordFile.RecordSize;

                /* if eRecordSize becomes zero under any circumstances this     */
                /* would lead to a division by zero at the end of this function */
                /* thus making it impossible to proceed                         */
                if (RecordSize == 0)
                {
                    Data = null;
                    return LibraryError(DesfireLibraryError.WrongRecordSize);
                }
            }

            /* Call the ReadFile function */
            status = ReadDataEx((byte)DesfireCommand.READ_RECORDS, FileId, CommMode, FromRecord, MaxCount, RecordSize, out Data);
            if (status != Success)
                return status;

            /* we have to check whether we received multiples of record_size   */
            /* if this is not the case this means that a format error occurred */
            if ((Data.Length % RecordSize) != 0)
                return LibraryError(DesfireLibraryError.WrongLength);

            /* calculate the number of records if a pointer has been passed */
            ActualCount = Data.Length / RecordSize;
            return Success;
        }

        /**
         * @brief Reads a specific record from a record file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to read from.
         * @param RecordNumber The record number to read.
         * @param[out] Data A byte array containing the read record data.
         * @return A status code indicating the result of the operation.
         */
        public long ReadRecord2(byte FileId, int RecordNumber, out byte[] Data)
        {
            return ReadRecords2(FileId, RecordNumber, 1, out Data, out int dummy1, out int dummy2);
        }

        /**
         * @brief Reads multiple records from a record file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to read from.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param[out] Data A list of byte arrays containing the read records.
         * @return A status code indicating the result of the operation.
         */
        public long ReadRecords2(byte FileId, int FromRecord, int MaxCount, out List<byte[]> Data)
        {
            long status = ReadRecords2(FileId, FromRecord, MaxCount, out byte[] buffer, out int RecordSize, out int ActualCount);
            if (status != Success)
            {
                Data = null;
                return status;
            }

            Data = new List<byte[]>();
            for (int i = 0; i < ActualCount; i++)
            {
                Data.Add(BinUtils.Copy(buffer, i * RecordSize, RecordSize));
            }

            return Success;
        }

        /**
         * @brief Reads multiple records from a record file and retrieves the record size and actual count of records read.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to read from.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param[out] Data A byte array containing the concatenated read records.
         * @param[out] RecordSize The size of each record in bytes.
         * @param[out] ActualCount The actual number of records read.
         * @return A status code indicating the result of the operation.
         */
        public long ReadRecords2(byte FileId, int FromRecord, int MaxCount, out byte[] Data, out int RecordSize, out int ActualCount)
        {
            byte read_only_access;
            byte read_write_access;
            long status;

            Data = null;
            ActualCount = 0;
            RecordSize = 0;

            /* we have to receive the communications mode first */
            status = GetFileSettings(FileId, out byte fileType, out byte commMode, out ushort accessRights, out DesfireFileSettings fileSettings);
            if (status != Success)
                return status;

            RecordSize = fileSettings.RecordFile.RecordSize;

            /* Depending on the AccessRights field (settings r and r/w) we have to decide whether     */
            /* we are able to communicate in the mode indicated by comm_mode.                         */
            /* If auth_key does neither match r nor r/w and one of this settings                      */
            /* contains the value "ever" (0x0E) communication has to be done in plain mode regardless */
            /* of the mode indicated by comm_mode.                                                    */
            read_only_access = (byte)((accessRights & DesfireAccessRights.ReadOnly_Mask) >> DesfireAccessRights.ReadOnly_Shift);
            read_write_access = (byte)((accessRights & DesfireAccessRights.ReadWrite_Mask) >> DesfireAccessRights.ReadWrite_Shift);

            if ((read_only_access != GetSessionKeyNumber())
             && (read_write_access != GetSessionKeyNumber())
             && ((read_only_access == DesfireAccessRights.Free) || (read_write_access == DesfireAccessRights.Free)))
            {
                commMode = (byte)DesfireCommMode.Plain;
            }

            logger.trace("FileSettings: RecordSize={0}, CommMode={1:X}", RecordSize, commMode);

            /* Now execute the command */
            return ReadRecords(FileId, commMode, FromRecord, MaxCount, RecordSize, out Data, out ActualCount);
        }

        public long ReadRecordsIso(byte FileId, int FromRecord, int MaxRecordCount, int RecordSize, out byte[] Data, out int RecordCount)
        {
            byte comm_mode = 0;
            ushort access_rights = 0;
            byte read_only_access;
            byte read_write_access;
            long status;

            Data = null;
            RecordCount = 0;

            /* we have to receive the communications mode first */
            byte FileType;

            status = GetFileSettings(FileId, out FileType, out comm_mode, out access_rights, out DesfireFileSettings file_settings);
            if (status != Success)
                return status;

            /* Depending on the AccessRights field (settings r and r/w) we have to decide whether     */
            /* we are able to communicate in the mode indicated by comm_mode.                         */
            /* If auth_key does neither match r nor r/w and one of this settings                      */
            /* contains the value "ever" (0x0E) communication has to be done in plain mode regardless */
            /* of the mode indicated by comm_mode.                                                    */
            read_only_access = (byte)((access_rights & DesfireAccessRights.ReadOnly_Mask) >> DesfireAccessRights.ReadOnly_Shift);
            read_write_access = (byte)((access_rights & DesfireAccessRights.ReadWrite_Mask) >> DesfireAccessRights.ReadWrite_Shift);

            if ((read_only_access != GetSessionKeyNumber())
             && (read_write_access != GetSessionKeyNumber())
             && ((read_only_access == DesfireAccessRights.Free) || (read_write_access == DesfireAccessRights.Free)))
            {
                comm_mode = (byte)DesfireCommMode.Plain;
            }

            /* if a pointer was passed for retrieving the number of records read    */
            /* and no record size was specified, we have to get the record size via */
            /* the GetFileSettings command                                          */
            if (RecordSize == 0)
            {
                /* if the file type indicates that this is not a record file */
                /* we are not able to proceed                                */
                if (((DesfireFileType)FileType != DesfireFileType.LinearRecord) && ((DesfireFileType)FileType != DesfireFileType.CyclicRecord))
                    return LibraryError(DesfireLibraryError.WrongFileType);

                RecordSize = file_settings.RecordFile.RecordSize;

                /* if eRecordSize becomes zero under any circumstances this     */
                /* would lead to a division by zero at the end of this function */
                /* thus making it impossible to proceed                         */
                if (RecordSize == 0)
                    return LibraryError(DesfireLibraryError.WrongRecordSize);
            }

            /* Call the ReadFile function */
            status = ReadDataEx((byte)DesfireCommand.READ_RECORDS_ISO, FileId, comm_mode, FromRecord, MaxRecordCount, RecordSize, out Data);
            if (status != Success)
                return status;

            /* we have to check whether we received multiples of record_size   */
            /* if this is not the case this means that a format error occurred */
            if ((Data.Length % RecordSize) != 0)
                return LibraryError(DesfireLibraryError.WrongLength);

            /* calculate the number of records if a pointer has been passed */
            RecordCount = Data.Length / RecordSize;
            return Success;
        }

        #endregion

        #region Write Record File

        /**
         * @brief Writes a specific record to a record file.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset within the record to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long WriteRecord(byte FileId, byte CommMode, int FromOffset, int Size, byte[] Data)
        {
            return WriteOrUpdateEx((byte)DesfireCommand.WRITE_RECORD, FileId, CommMode, FromOffset, Size, Data);
        }

        /**
         * @brief Writes a specific record to a record file.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset within the record to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long WriteRecord(byte FileId, DesfireCommMode CommMode, int FromOffset, int Size, byte[] Data)
        {
            return WriteRecord(FileId, (byte)CommMode, FromOffset, Size, Data);
        }

        /**
         * @brief Writes a specific record to a record file.
         *
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset within the record to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long WriteRecord(byte FileId, byte CommMode, int FromOffset, byte[] Data)
        {
            return WriteOrUpdateEx((byte)DesfireCommand.WRITE_RECORD, FileId, CommMode, FromOffset, Data.Length, Data);
        }

        /**
         * @brief Writes a specific record to a record file.
         *
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset within the record to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long WriteRecord(byte FileId, DesfireCommMode CommMode, int FromOffset, byte[] Data)
        {
            return WriteRecord(FileId, (byte)CommMode, FromOffset, Data);
        }

        /**
         * @brief Writes a specific record to a record file.
         *
         * Offset is 0
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long WriteRecord(byte FileId, byte CommMode, byte[] Data)
        {
            return WriteOrUpdateEx((byte)DesfireCommand.WRITE_RECORD, FileId, CommMode, 0, Data.Length, Data);
        }

        /**
         * @brief Writes a specific record to a record file.
         *
         * Offset is 0
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long WriteRecord(byte FileId, DesfireCommMode CommMode, byte[] Data)
        {
            return WriteRecord(FileId, (byte)CommMode, Data);
        }

        /**
         * @brief Writes a specific record to a record file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to write to.
         * @param FromOffset The starting offset within the record to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long WriteRecord2(byte FileId, int FromOffset, int Size, byte[] Data)
        {
            byte comm_mode = 0;
            ushort access_rights = 0;
            byte write_only_access;
            byte read_write_access;
            long status;

            /* we have to receive the communications mode first */
            byte file_type;
            status = GetFileSettings(FileId, out file_type, out comm_mode, out access_rights, out DesfireFileSettings file_settings);
            if (status != Success)
                return status;

            /* Depending on the access_rights field (settings w and r/w) we have to decide whether   */
            /* we are able to communicate in the mode indicated by comm_mode.                        */
            /* If auth_key does neither match w nor r/w and one of this settings                */
            /* contains the value "ever" (0xE) communication has to be done in plain mode regardless */
            /* of the mode indicated by comm_mode.                                                   */
            write_only_access = (byte)((access_rights & DesfireAccessRights.WriteOnly_Mask) >> DesfireAccessRights.WriteOnly_Shift);
            read_write_access = (byte)((access_rights & DesfireAccessRights.ReadWrite_Mask) >> DesfireAccessRights.ReadWrite_Shift);

            if ((write_only_access != GetSessionKeyNumber())
             && (read_write_access != GetSessionKeyNumber())
             && ((write_only_access == DesfireAccessRights.Free) || (read_write_access == DesfireAccessRights.Free)))
            {
                comm_mode = (byte)DesfireCommMode.Plain;
            }

            /* Now execute the command */
            return WriteRecord(FileId, comm_mode, FromOffset, Size, Data);
        }

        /**
         * @brief Writes a specific record to a record file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param FromOffset The starting offset within the record to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long WriteRecord2(byte FileId, int FromOffset, byte[] Data)
        {
            return WriteRecord2(FileId, FromOffset, Data.Length, Data);
        }

        /**
         * @brief Writes a specific record to a record file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         * Offset is 0.
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long WriteRecord2(byte FileId, byte[] Data)
        {
            return WriteRecord2(FileId, 0, Data);
        }

        public long WriteRecordIso(byte FileId, int FromOffset, int Size, byte[] Data)
        {
            byte comm_mode = 0;
            ushort access_rights = 0;
            byte write_only_access;
            byte read_write_access;
            long status;

            int size_proceed = 0;
            int offset_proceed = FromOffset;

            /* we have to receive the communications mode first */
            byte file_type;
            status = GetFileSettings(FileId, out file_type, out comm_mode, out access_rights, out DesfireFileSettings file_settings);
            if (status != Success)
                return status;

            /* Depending on the access_rights field (settings w and r/w) we have to decide whether   */
            /* we are able to communicate in the mode indicated by comm_mode.                        */
            /* If auth_key does neither match w nor r/w and one of this settings                */
            /* contains the value "ever" (0xE) communication has to be done in plain mode regardless */
            /* of the mode indicated by comm_mode.                                                   */
            write_only_access = (byte)((access_rights & DesfireAccessRights.WriteOnly_Mask) >> DesfireAccessRights.WriteOnly_Shift);
            read_write_access = (byte)((access_rights & DesfireAccessRights.ReadWrite_Mask) >> DesfireAccessRights.ReadWrite_Shift);

            if ((write_only_access != GetSessionKeyNumber())
             && (read_write_access != GetSessionKeyNumber())
             && ((write_only_access == DesfireAccessRights.Free) || (read_write_access == DesfireAccessRights.Free)))
            {
                comm_mode = (byte)DesfireCommMode.Plain;
            }

            // Now execute the command
            if (Size >= MaxIsoDataInSize)
            {
                size_proceed = Size;
                while (size_proceed > 0)
                {
                    if (size_proceed > MaxIsoDataInSize)
                        status = WriteOrUpdateEx((byte)DesfireCommand.WRITE_RECORD_ISO, FileId, comm_mode, offset_proceed, MaxIsoDataInSize, Data);
                    else
                        status = WriteOrUpdateEx((byte)DesfireCommand.WRITE_RECORD_ISO, FileId, comm_mode, offset_proceed, size_proceed, Data);

                    if (status != Success)
                        return status;

                    if (size_proceed > MaxIsoDataInSize)
                    {
                        size_proceed -= MaxIsoDataInSize;
                        offset_proceed += MaxIsoDataInSize;
                    }
                    else
                    {
                        size_proceed = 0;
                    }
                }
            }
            else
            {
                /* Now execute the command */
                status = WriteOrUpdateEx((byte)DesfireCommand.WRITE_RECORD_ISO, FileId, comm_mode, FromOffset, Size, Data);
            }

            return status;
        }

        #endregion


        #region Update Record File

        /**
         * @brief Updates a specific record to a record file.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset within the record to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long UpdateRecord(byte FileId, byte CommMode, int FromOffset, int Size, byte[] Data)
        {
            return WriteOrUpdateEx((byte)DesfireCommand.UPDATE_RECORD, FileId, CommMode, FromOffset, Size, Data);
        }

        /**
         * @brief Updates a specific record to a record file.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset within the record to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long UpdateRecord(byte FileId, DesfireCommMode CommMode, int FromOffset, int Size, byte[] Data)
        {
            return UpdateRecord(FileId, (byte)CommMode, FromOffset, Size, Data);
        }

        /**
         * @brief Updates a specific record to a record file.
         *
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset within the record to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long UpdateRecord(byte FileId, byte CommMode, int FromOffset, byte[] Data)
        {
            return WriteOrUpdateEx((byte)DesfireCommand.UPDATE_RECORD, FileId, CommMode, FromOffset, Data.Length, Data);
        }

        /**
         * @brief Updates a specific record to a record file.
         *
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset within the record to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long UpdateRecord(byte FileId, DesfireCommMode CommMode, int FromOffset, byte[] Data)
        {
            return UpdateRecord(FileId, (byte)CommMode, FromOffset, Data);
        }

        /**
         * @brief Updates a specific record to a record file.
         *
         * Size is automatically calculated based on the length of the Data array.
         * Offset is 0
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long UpdateRecord(byte FileId, byte CommMode, byte[] Data)
        {
            return WriteOrUpdateEx((byte)DesfireCommand.UPDATE_RECORD, FileId, CommMode, 0, Data.Length, Data);
        }

        /**
         * @brief Updates a specific record to a record file.
         *
         * Size is automatically calculated based on the length of the Data array.
         * Offset is 0
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long UpdateRecord(byte FileId, DesfireCommMode CommMode, byte[] Data)
        {
            return UpdateRecord(FileId, (byte)CommMode, Data);
        }

        /**
         * @brief Updates a specific record to a record file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         * Offset is 0.
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long UpdateRecord2(byte FileId, byte[] Data)
        {
            return UpdateRecord2(FileId, 0, Data);
        }

        /**
         * @brief Updates a specific record to a record file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param FromOffset The starting offset within the record to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long UpdateRecord2(byte FileId, int FromOffset, byte[] Data)
        {
            return UpdateRecord2(FileId, FromOffset, Data.Length, Data);
        }

        /**
         * @brief Updates a specific record to a record file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to write to.
         * @param FromOffset The starting offset within the record to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long UpdateRecord2(byte FileId, int FromOffset, int Size, byte[] Data)
        {
            byte comm_mode = 0;
            ushort access_rights = 0;
            byte write_only_access;
            byte read_write_access;
            long status;

            /* we have to receive the communications mode first */
            byte file_type;
            status = GetFileSettings(FileId, out file_type, out comm_mode, out access_rights, out DesfireFileSettings file_settings);
            if (status != Success)
                return status;

            /* Depending on the access_rights field (settings w and r/w) we have to decide whether   */
            /* we are able to communicate in the mode indicated by comm_mode.                        */
            /* If auth_key does neither match w nor r/w and one of this settings                */
            /* contains the value "ever" (0xE) communication has to be done in plain mode regardless */
            /* of the mode indicated by comm_mode.                                                   */
            write_only_access = (byte)((access_rights & DesfireAccessRights.WriteOnly_Mask) >> DesfireAccessRights.WriteOnly_Shift);
            read_write_access = (byte)((access_rights & DesfireAccessRights.ReadWrite_Mask) >> DesfireAccessRights.ReadWrite_Shift);

            if ((write_only_access != GetSessionKeyNumber())
             && (read_write_access != GetSessionKeyNumber())
             && ((write_only_access == DesfireAccessRights.Free) || (read_write_access == DesfireAccessRights.Free)))
            {
                comm_mode = (byte)DesfireCommMode.Plain;
            }

            /* Now execute the command */
            return UpdateRecord(FileId, comm_mode, FromOffset, Size, Data);
        }

        public long UpdateRecordIso(byte FileId, int FromOffset, int Size, byte[] Data)
        {
            byte comm_mode = 0;
            ushort access_rights = 0;
            byte write_only_access;
            byte read_write_access;
            long status;

            int size_proceed = 0;
            int offset_proceed = FromOffset;

            /* we have to receive the communications mode first */
            byte file_type;
            status = GetFileSettings(FileId, out file_type, out comm_mode, out access_rights, out DesfireFileSettings file_settings);
            if (status != Success)
                return status;

            /* Depending on the access_rights field (settings w and r/w) we have to decide whether   */
            /* we are able to communicate in the mode indicated by comm_mode.                        */
            /* If auth_key does neither match w nor r/w and one of this settings                */
            /* contains the value "ever" (0xE) communication has to be done in plain mode regardless */
            /* of the mode indicated by comm_mode.                                                   */
            write_only_access = (byte)((access_rights & DesfireAccessRights.WriteOnly_Mask) >> DesfireAccessRights.WriteOnly_Shift);
            read_write_access = (byte)((access_rights & DesfireAccessRights.ReadWrite_Mask) >> DesfireAccessRights.ReadWrite_Shift);

            if ((write_only_access != GetSessionKeyNumber())
             && (read_write_access != GetSessionKeyNumber())
             && ((write_only_access == DesfireAccessRights.Free) || (read_write_access == DesfireAccessRights.Free)))
            {
                comm_mode = (byte)DesfireCommMode.Plain;
            }

            // Now execute the command
            if (Size >= MaxIsoDataInSize)
            {
                size_proceed = Size;
                while (size_proceed > 0)
                {
                    if (size_proceed > MaxIsoDataInSize)
                        status = WriteOrUpdateEx((byte)DesfireCommand.UPDATE_RECORD_ISO, FileId, comm_mode, offset_proceed, MaxIsoDataInSize, Data);
                    else
                        status = WriteOrUpdateEx((byte)DesfireCommand.UPDATE_RECORD_ISO, FileId, comm_mode, offset_proceed, size_proceed, Data);

                    if (status != Success)
                        return status;

                    if (size_proceed > MaxIsoDataInSize)
                    {
                        size_proceed -= MaxIsoDataInSize;
                        offset_proceed += MaxIsoDataInSize;
                    }
                    else
                    {
                        size_proceed = 0;
                    }
                }
            }
            else
            {
                /* Now execute the command */
                status = WriteOrUpdateEx((byte)DesfireCommand.UPDATE_RECORD_ISO, FileId, comm_mode, FromOffset, Size, Data);
            }

            return status;
        }

        #endregion
    }
}
