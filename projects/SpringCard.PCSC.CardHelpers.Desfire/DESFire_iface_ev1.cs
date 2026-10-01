/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using static SpringCard.PCSC.CardHelpers.Desfire;

namespace SpringCard.PCSC.CardHelpers
{
    /**
     * @brief Interface for managing and using the DESFire EV0 chip.
     *
     * This interface provides methods to interact with the DESFire EV1 chip.
     * This is an extension of the DesfireEV0 interface, adding support for new features.
     *
     * @author Johann.D et al. / SpringCard
     * @copyright Copyright (c) 2018-2025 SpringCard - www.springcard.com. All rights reserved.
     * @see DesfireEV0
     */
    public interface DesfireEV1 : DesfireEV0
    {
        /* Security related commandes */

        /**
         * @brief Authenticates with the DESFire chip using the specified ISO key (EV1 method).
         *
         * This method is an alias for AuthenticateEV1TDes.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 or 24 bytes for 3DES keys).
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateISO(byte KeyNumber, byte[] KeyValue);

        /**
         * @brief Authenticates with the DESFire chip using the specified 3DES key (EV1 method).
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (8 bytes for DES, keys, 16 bytes for 3DES2K keys and 24 bytes for 3DES3K keys).
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV1TDes(byte KeyNumber, byte[] KeyValue);

        /**
         * @brief Authenticates with the DESFire chip using the specified AES key (EV1 method).
         *
         * This method is an alias for AuthenticateEV1Aes.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateAes(byte KeyNumber, byte[] KeyValue);

        /**
         * @brief Authenticates with the DESFire chip using the specified AES key (EV1 method).
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV1Aes(byte KeyNumber, byte[] KeyValue);

        /**
         * @brief Changes a key on the DESFire chip, providing the version (required for AES keys).
         *
         * @param KeyNumber The key number to change.
         * @param KeyVersion The version of the new key.
         * @param NewKeyValue The new key value.
         * @param OldKeyValue The old key value.
         * @return A status code indicating the result of the operation.
         */
        long ChangeKey(byte KeyNumber, byte KeyVersion, byte[] NewKeyValue, byte[] OldKeyValue);

        /**
         * @brief Changes an AES key on the DESFire chip, providing the version.
         * 
         * This method is an alias for ChangeKey.
         *
         * @param KeyNumber The key number to change.
         * @param KeyVersion The version of the new key.
         * @param NewKeyValue The new key value.
         * @param OldKeyValue The old key value.
         * @return A status code indicating the result of the operation.
         */
        long ChangeKeyAes(byte KeyNumber, byte KeyVersion, byte[] NewKeyValue, byte[] OldKeyValue);

        /* PICC level commands */

        /**
         * @brief Creates a new ISO application on the DESFire chip.
         *
         * @param Aid The application identifier (AID).
         * @param KeySetting1 The first key setting byte.
         * @param KeySetting2 The second key setting byte.
         * @param DFID The ISO DF identifier.
         * @param DFName The ISO DF name.
         * @param DFNameLen The length of the ISO DF name.
         * @return A status code indicating the result of the operation.
         */
        long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, ushort DFID, byte[] DFName, int DFNameLen);

        /**
         * @brief Creates a new ISO application on the DESFire chip.
         *
         * @param Aid The application identifier (AID).
         * @param KeySetting1 The first key setting byte.
         * @param KeySetting2 The second key setting byte.
         * @param DFID The ISO DF identifier.
         * @param DFName The ISO DF name.
         * @return A status code indicating the result of the operation.
         */
        long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, ushort DFID, byte[] DFName);

        /**
         * @brief Creates a new ISO application on the DESFire chip.
         *
         * @param Aid The application identifier (AID).
         * @param KeySetting1 The first key setting byte.
         * @param KeySetting2 The second key setting byte.
         * @param DFID The ISO DF identifier.
         * @param DFName The ISO DF name.
         * @return A status code indicating the result of the operation.
         */
        long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, ushort DFID, string DFName);

        /**
         * @brief Retrieves the list of ISO applications on the DESFire chip.
         *
         * @param[out] AidList An array of DesfireCommand.ISO_APPLICATION structures containing the application details.
         * @return A status code indicating the result of the operation.
         */
        long GetDFNames(out DesfireIsoApplication[] AidList);

        /**
         * @brief Retrieves the amount of free memory on the DESFire chip.
         *
         * @param[out] FreeBytes The amount of free memory in bytes.
         * @return A status code indicating the result of the operation.
         */
        long GetFreeMemory(out uint FreeBytes);

        /**
         * @brief Configures the DESFire chip with the specified settings.
         *
         * @param Option The configuration option.
         * @param Data The configuration data.
         * @return A status code indicating the result of the operation.
         */
        long SetConfiguration(byte Option, byte[] Data);

        /**
         * @brief Disable the Format command inside the DESFire chip.
         *
         * @return A status code indicating the result of the operation.
         */
        long DisableCommandFormat();

        /**
         * @brief Enable the Random ID feature of the DESFire chip.
         *
         * @return A status code indicating the result of the operation.
         */
        long EnableRandomID();

        /**
         * @brief Configures the new applications of the DESFire chip with the specified default key (value and version).
         *
         * @param KeyValue The default key.
         * @param KeyVersion The default version.
         * @return A status code indicating the result of the operation.
         */

        long SetAppDefaultKey(byte[] KeyValue, byte KeyVersion);

        /**
         * @brief Configures the DESFire chip with the specified ATS.
         *
         * Only the length of the string is checked by the card.
         * No other verification of the ATS string is performed by the card nor the library. 
         * Therefore the data string must be formatted in the following: TL T0 TA TB TC + Historical bytes.
         *
         * @param Ats The new ATS.
         * @return A status code indicating the result of the operation.
         */
        long SetUserATS(byte[] Ats);

        /**
         * @brief Retrieves the UID of the DESFire chip.
         *
         * @param[out] CardUid A byte array containing the UID.
         * @return A status code indicating the result of the operation.
         */
        long GetCardUID(out byte[] CardUid);

        /* Application level commands */

        /**
         * @brief Retrieves the list of ISO file IDs in the currently selected application.
         *
         * @param[out] EfIsList An array of ISO EF IDs.
         * @return A status code indicating the result of the operation.
         */
        long GetIsoFileIDs(out ushort[] EfIsList);

        /**
         * @brief Creates a standard ISO data file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param IsoEfId The ISO EF identifier.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param FileSize The size of the file in bytes.
         * @return A status code indicating the result of the operation.
         */
        long CreateIsoStdDataFile(byte FileId, ushort IsoEfId, byte CommMode, ushort AccessRights, int FileSize);

        /**
         * @brief Creates a backup ISO data file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param IsoEfId The ISO EF identifier.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param FileSize The size of the file in bytes.
         * @return A status code indicating the result of the operation.
         */
        long CreateIsoBackupDataFile(byte FileId, ushort IsoEfId, byte CommMode, ushort AccessRights, int FileSize);

        /**
         * @brief Creates a linear ISO record file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param IsoEfId The ISO EF identifier.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param RecordSize The size of each record in bytes.
         * @param MaxRecords The maximum number of records.
         * @return A status code indicating the result of the operation.
         */
        long CreateIsoLinearRecordFile(byte FileId, ushort IsoEfId, byte CommMode, ushort AccessRights, int RecordSize, int MaxRecords);

        /**
         * @brief Creates a cyclic ISO record file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param IsoEfId The ISO EF identifier.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param RecordSize The size of each record in bytes.
         * @param MaxRecords The maximum number of records.
         * @return A status code indicating the result of the operation.
         */
        long CreateIsoCyclicRecordFile(byte FileId, ushort IsoEfId, byte CommMode, ushort AccessRights, int RecordSize, int MaxRecords);
    }
}
