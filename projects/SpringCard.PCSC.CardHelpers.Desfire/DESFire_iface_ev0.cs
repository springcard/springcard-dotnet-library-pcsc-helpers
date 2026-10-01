/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using System.Collections.Generic;
using static SpringCard.PCSC.CardHelpers.Desfire;

namespace SpringCard.PCSC.CardHelpers
{
    /**
     * @brief Interface for managing and using the DESFire EV0 chip.
     *
     * This interface provides methods to interact with the DESFire EV0 chip, including
     * security-related commands, PICC-level commands, application-level commands, and
     * data manipulation commands. It supports operations such as authentication, file
     * management, and data transactions.
     *
     * @author Johann.D et al. / SpringCard
     * @copyright Copyright (c) 2018-2025 SpringCard - www.springcard.com. All rights reserved.
     * @see Desfire
     */
    public interface DesfireEV0
    {
        /* Security related commandes */

        /**
         * @brief Authenticates with the DESFire chip using the specified key.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (8 or 16 bytes).
         * @return A status code indicating the result of the operation.
         */
        long Authenticate(byte KeyNumber, byte[] KeyValue);

        /**
         * @brief Changes the key settings of the DESFire chip.
         *
         * @param bKeySettings The new key settings.
         * @return A status code indicating the result of the operation.
         */
        long ChangeKeySettings(byte bKeySettings);

        /**
         * @brief Retrieves the current key settings and key count.
         *
         * @param[out] bKeySettings The current key settings.
         * @param[out] bKeyCount The number of keys available.
         * @return A status code indicating the result of the operation.
         */
        long GetKeySettings(out byte bKeySettings, out byte bKeyCount);

        /**
         * @brief Changes a key on the DESFire chip.
         *
         * @param KeyNumber The key number to change.
         * @param NewKeyValue The new key value.
         * @param OldKeyValue The old key value.
         * @return A status code indicating the result of the operation.
         */
        long ChangeKey(byte KeyNumber, byte[] NewKeyValue, byte[] OldKeyValue);

        /**
         * @brief Retrieves the version of a specific key.
         *
         * @param KeyNumber The key number to query.
         * @param[out] KeyVersion The version of the key.
         * @return A status code indicating the result of the operation.
         */
        long GetKeyVersion(byte KeyNumber, out byte KeyVersion);

        /* PICC level commands */

        /**
         * @brief Creates a new application on the DESFire chip.
         *
         * @param Aid The application identifier (AID).
         * @param KeySetting1 The first key setting byte.
         * @param KeySetting2 The second key setting byte.
         * @return A status code indicating the result of the operation.
         */
        long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2);

        /**
         * @brief Deletes an application from the DESFire chip.
         *
         * @param Aid The application identifier (AID) to delete.
         * @return A status code indicating the result of the operation.
         */
        long DeleteApplication(uint Aid);

        /**
         * @brief Retrieves the list of application IDs on the DESFire chip.
         *
         * @param[out] AidList An array containing the application IDs.
         * @return A status code indicating the result of the operation.
         */
        long GetApplicationIDs(out uint[] AidList);

        /**
         * @brief Selects an application on the DESFire chip.
         *
         * @param Aid The application identifier (AID) to select.
         * @return A status code indicating the result of the operation.
         */
        long SelectApplication(uint Aid);

        /**
         * @brief Formats the entire DESFire chip, deleting all applications.
         *
         * @return A status code indicating the result of the operation.
         */
        long FormatPICC();

        /**
         * @brief Retrieves the version information of the DESFire chip.
         *
         * @param[out] VersionInfo A byte array containing the version information.
         * @return A status code indicating the result of the operation.
         */
        long GetVersion(out byte[] VersionInfo);

        /**
         * @brief Retrieves the version information of the DESFire chip.
         *
         * @param[out] VersionInfo A DesfireCommand.VERSION_INFO structure containing the version information.
         * @return A status code indicating the result of the operation.
         */
        long GetVersion(out DesfireVersionInfo VersionInfo);

        /* Application level commands */

        /**
         * @brief Retrieves the list of file IDs in the currently selected application.
         *
         * @param[out] ListData A byte array containing the file IDs.
         * @return A status code indicating the result of the operation.
         */
        long GetFileIDs(out byte[] ListData);

        /**
         * @brief Retrieves the settings of a specific file.
         *
         * @param FileId The file ID to query.
         * @param[out] FileType The type of the file.
         * @param[out] CommMode The communication mode of the file.
         * @param[out] AccessRights The access rights of the file.
         * @param[out] AdditionnalSettings Additional settings specific to the file type.
         * @return A status code indicating the result of the operation.
         */
        long GetFileSettings(byte FileId, out byte FileType, out byte CommMode, out ushort AccessRights, out DesfireFileSettings AdditionnalSettings);

        /**
         * @brief Retrieves the settings of a specific file.
         *
         * @param FileId The file ID to query.
         * @param[out] FileType The type of the file.
         * @param[out] CommMode The communication mode of the file.
         * @param[out] AccessRights The access rights of the file.
         * @param[out] AdditionnalSettings Additional settings specific to the file type.
         * @return A status code indicating the result of the operation.
         */
        long GetFileSettings(byte FileId, out DesfireFileType FileType, out DesfireCommMode CommMode, out DesfireAccessRights AccessRights, out DesfireFileSettings AdditionnalSettings);

        /**
         * @brief Changes the settings of a specific file.
         *
         * @param FileId The file ID to modify.
         * @param CommMode The new communication mode.
         * @param AccessRights The new access rights.
         * @return A status code indicating the result of the operation.
         */
        long ChangeFileSettings(byte FileId, byte CommMode, ushort AccessRights);

        /**
         * @brief Changes the settings of a specific file.
         *
         * @param FileId The file ID to modify.
         * @param CommMode The new communication mode.
         * @param AccessRights The new access rights.
         * @return A status code indicating the result of the operation.
         */
        long ChangeFileSettings(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights);

        /**
         * @brief Creates a standard data file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param FileSize The size of the file in bytes.
         * @return A status code indicating the result of the operation.
         */
        long CreateStdDataFile(byte FileId, byte CommMode, ushort AccessRights, int FileSize);

        /**
         * @brief Creates a standard data file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param FileSize The size of the file in bytes.
         * @return A status code indicating the result of the operation.
         */
        long CreateStdDataFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, int FileSize);

        /**
         * @brief Creates a backup data file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param FileSize The size of the file in bytes.
         * @return A status code indicating the result of the operation.
         */
        long CreateBackupDataFile(byte FileId, byte CommMode, ushort AccessRights, int FileSize);

        /**
         * @brief Creates a backup data file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param FileSize The size of the file in bytes.
         * @return A status code indicating the result of the operation.
         */
        long CreateBackupDataFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, int FileSize);

        /**
         * @brief Creates a value file in the currently selected application with limited credit enabled.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param LowerLimit The lower limit of the value file.
         * @param UpperLimit The upper limit of the value file.
         * @param InitialValue The initial value of the file.
         * @param LimitedCreditEnabled Whether limited credit is enabled.
         * @return A status code indicating the result of the operation.
         */
        long CreateValueFile(byte FileId, byte CommMode, ushort AccessRights, long LowerLimit, long UpperLimit, long InitialValue, bool LimitedCreditEnabled);

        /**
         * @brief Creates a value file in the currently selected application with limited credit enabled.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param LowerLimit The lower limit of the value file.
         * @param UpperLimit The upper limit of the value file.
         * @param InitialValue The initial value of the file.
         * @param LimitedCreditEnabled Whether limited credit is enabled.
         * @return A status code indicating the result of the operation.
         */
        long CreateValueFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, long LowerLimit, long UpperLimit, long InitialValue, bool LimitedCreditEnabled);

        /**
         * @brief Creates a linear record file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param RecordSize The size of each record in bytes.
         * @param MaxRecords The maximum number of records.
         * @return A status code indicating the result of the operation.
         */
        long CreateLinearRecordFile(byte FileId, byte CommMode, ushort AccessRights, int RecordSize, int MaxRecords);

        /**
         * @brief Creates a linear record file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param RecordSize The size of each record in bytes.
         * @param MaxRecords The maximum number of records.
         * @return A status code indicating the result of the operation.
         */
        long CreateLinearRecordFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, int RecordSize, int MaxRecords);

        /**
         * @brief Creates a cyclic record file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param RecordSize The size of each record in bytes.
         * @param MaxRecords The maximum number of records.
         * @return A status code indicating the result of the operation.
         */
        long CreateCyclicRecordFile(byte FileId, byte CommMode, ushort AccessRights, int RecordSize, int MaxRecords);

        /**
         * @brief Creates a cyclic record file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param RecordSize The size of each record in bytes.
         * @param MaxRecords The maximum number of records.
         * @return A status code indicating the result of the operation.
         */
        long CreateCyclicRecordFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, int RecordSize, int MaxRecords);

        /**
         * @brief Deletes a file in the currently selected application.
         *
         * @param FileId The file ID to delete.
         * @return A status code indicating the result of the operation.
         */
        long DeleteFile(byte FileId);

        /* Data manipulation commands -- linear files */

        /**
         * @brief Reads data from a standard or backup file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset to read from.
         * @param MaxCount The maximum number of bytes to read.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData(byte FileId, byte CommMode, int FromOffset, int MaxCount, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset to read from.
         * @param MaxCount The maximum number of bytes to read.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData(byte FileId, DesfireCommMode CommMode, int FromOffset, int MaxCount, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         *
         * Offset is set to 0.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param MaxCount The maximum number of bytes to read.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData(byte FileId, byte CommMode, int MaxCount, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         *
         * Offset is set to 0.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param MaxCount The maximum number of bytes to read.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData(byte FileId, DesfireCommMode CommMode, int MaxCount, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         *
         * Offset is set to 0.
         * All the bytes in the file are read.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData(byte FileId, byte CommMode, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         *
         * Offset is set to 0.
         * All the bytes in the file are read.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData(byte FileId, DesfireCommMode CommMode, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         * 
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to read from.
         * @param FromOffset The starting offset to read from.
         * @param MaxCount The maximum number of bytes to read.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData2(byte FileId, int FromOffset, int MaxCount, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         * 
         * CommMode is determined by querying GetFileSettings beforehand.
         * Offset is set to 0.
         *
         * @param FileId The file ID to read from.
         * @param MaxCount The maximum number of bytes to read.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData2(byte FileId, int MaxCount, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         * 
         * CommMode is determined by querying GetFileSettings beforehand.
         * Offset is set to 0.
         * All the bytes in the file are read.
         *
         * @param FileId The file ID to read from.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData2(byte FileId, out byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData(byte FileId, byte CommMode, int FromOffset, int Size, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData(byte FileId, DesfireCommMode CommMode, int FromOffset, int Size, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         * 
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData(byte FileId, byte CommMode, int FromOffset, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         * 
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData(byte FileId, DesfireCommMode CommMode, int FromOffset, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         * 
         * Size is automatically calculated based on the length of the Data array.
         * Offset is set to 0.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData(byte FileId, byte CommMode, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         * 
         * Size is automatically calculated based on the length of the Data array.
         * Offset is set to 0.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData(byte FileId, DesfireCommMode CommMode, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         * 
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to write to.
         * @param FromOffset The starting offset to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData2(byte FileId, int FromOffset, int Size, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         * 
         * CommMode is determined by querying GetFileSettings beforehand.
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param FromOffset The starting offset to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData2(byte FileId, int FromOffset, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         * 
         * CommMode is determined by querying GetFileSettings beforehand.
         * Size is automatically calculated based on the length of the Data array.
         * Offset is set to 0.
         *
         * @param FileId The file ID to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData2(byte FileId, byte[] Data);

        /* Data manipulation commands -- value files */

        /**
         * @brief Retrieves the current value of a value file.
         *
         * @param FileId The file ID to query.
         * @param CommMode The communication mode of the file.
         * @param[out] Value The current value of the file.
         * @return A status code indicating the result of the operation.
         */
        long GetValue(byte FileId, byte CommMode, out long Value);

        /**
         * @brief Retrieves the current value of a value file.
         *
         * @param FileId The file ID to query.
         * @param CommMode The communication mode of the file.
         * @param[out] Value The current value of the file.
         * @return A status code indicating the result of the operation.
         */
        long GetValue(byte FileId, DesfireCommMode CommMode, out long Value);

        /**
         * @brief Retrieves the current value of a value file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to query.
         * @param[out] Value The current value of the file.
         * @return A status code indicating the result of the operation.
         */
        long GetValue2(byte FileId, out long Value);

        /**
         * @brief Credits a value file with a specified amount.
         *
         * @param FileId The file ID to credit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        long Credit(byte FileId, byte CommMode, long Amount);

        /**
         * @brief Credits a value file with a specified amount.
         *
         * @param FileId The file ID to credit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        long Credit(byte FileId, DesfireCommMode CommMode, long Amount);

        /**
         * @brief Credits a value file with a specified amount.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to credit.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        long Credit2(byte FileId, long Amount);

        /**
         * @brief Debits a value file by a specified amount.
         *
         * @param FileId The file ID to debit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to debit.
         * @return A status code indicating the result of the operation.
         */
        long Debit(byte FileId, byte CommMode, long Amount);

        /**
         * @brief Debits a value file by a specified amount.
         *
         * @param FileId The file ID to debit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to debit.
         * @return A status code indicating the result of the operation.
         */
        long Debit(byte FileId, DesfireCommMode CommMode, long Amount);

        /**
         * @brief Debits a value file by a specified amount.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to debit.
         * @param Amount The amount to debit.
         * @return A status code indicating the result of the operation.
         */
        long Debit2(byte FileId, long Amount);

        /**
         * @brief Credits a value file with a limited amount.
         *
         * @param FileId The file ID to credit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        long LimitedCredit(byte FileId, byte CommMode, long Amount);

        /**
         * @brief Credits a value file with a limited amount.
         *
         * @param FileId The file ID to credit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        long LimitedCredit(byte FileId, DesfireCommMode CommMode, long Amount);

        /**
         * @brief Credits a value file with a limited amount.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to credit.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        long LimitedCredit2(byte FileId, long Amount);

        /* Data manipulation commands -- record files */

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
        long ReadRecord(byte FileId, byte CommMode, int RecordNumber, int RecordSize, out byte[] Data);

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
        long ReadRecord(byte FileId, DesfireCommMode CommMode, int RecordNumber, int RecordSize, out byte[] Data);

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
        long ReadRecords(byte FileId, byte CommMode, int FromRecord, int MaxCount, int RecordSize, out List<byte[]> Data);

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
        long ReadRecords(byte FileId, DesfireCommMode CommMode, int FromRecord, int MaxCount, int RecordSize, out List<byte[]> Data);

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
        long ReadRecords(byte FileId, byte CommMode, int FromRecord, int MaxCount, int RecordSize, out byte[] Data);

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
        long ReadRecords(byte FileId, DesfireCommMode CommMode, int FromRecord, int MaxCount, int RecordSize, out byte[] Data);

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
        long ReadRecords(byte FileId, byte CommMode, int FromRecord, int MaxCount, int RecordSize, out byte[] Data, out int ActualCount);

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
        long ReadRecords(byte FileId, DesfireCommMode CommMode, int FromRecord, int MaxCount, int RecordSize, out byte[] Data, out int ActualCount);

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
        long ReadRecord2(byte FileId, int RecordNumber, out byte[] Data);

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
        long ReadRecords2(byte FileId, int FromRecord, int MaxCount, out List<byte[]> Data);

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
        long ReadRecords2(byte FileId, int FromRecord, int MaxCount, out byte[] Data, out int RecordSize, out int ActualCount);

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
        long WriteRecord(byte FileId, byte CommMode, int FromOffset, int Size, byte[] Data);

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
        long WriteRecord(byte FileId, DesfireCommMode CommMode, int FromOffset, int Size, byte[] Data);

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
        long WriteRecord(byte FileId, byte CommMode, int FromOffset, byte[] Data);

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
        long WriteRecord(byte FileId, DesfireCommMode CommMode, int FromOffset, byte[] Data);

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
        long WriteRecord(byte FileId, byte CommMode, byte[] Data);

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
        long WriteRecord(byte FileId, DesfireCommMode CommMode, byte[] Data);

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
        long WriteRecord2(byte FileId, int FromOffset, int Size, byte[] Data);

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
        long WriteRecord2(byte FileId, int FromOffset, byte[] Data);

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
        long WriteRecord2(byte FileId, byte[] Data);

        /**
         * @brief Clears all records in a record file.
         *
         * @param FileId The file ID to clear.
         * @return A status code indicating the result of the operation.
         */
        long ClearRecordFile(byte FileId);

        /* Transactions */

        /**
         * @brief Commits all pending transactions on the DESFire chip.
         *
         * @return A status code indicating the result of the operation.
         */
        long CommitTransaction();

        /**
         * @brief Aborts all pending transactions on the DESFire chip.
         *
         * @return A status code indicating the result of the operation.
         */
        long AbortTransaction();
    }
}
