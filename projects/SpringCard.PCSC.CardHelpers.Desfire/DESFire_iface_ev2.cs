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
     * @brief Interface for managing and using the DESFire EV2 chip.
     *
     * This interface provides methods to interact with the DESFire EV2 chip.
     * This is an extension of the DesfireEV1 interface, adding support for new features.
     *
     * @author Johann.D et al. / SpringCard
     * @copyright Copyright (c) 2018-2025 SpringCard - www.springcard.com. All rights reserved.
     * @see DesfireEV1
     * @see DesfireEV0
     */
    public interface DesfireEV2 : DesfireEV1
    {
        /* Memory and Configuration Management Commands */

        /**
         * @brief Enforce the Proximity Check feature of the DESFire chip.
         *
         * @return A status code indicating the result of the operation.
         */
        long SetPCMandatory();

        /**
         * @brief Enforce the Virtual Card feature of the DESFire chip.
         *
         * @return A status code indicating the result of the operation.
         */
        long SetAuthVCMandatory();

        /**
         * @brief Configures the DESFire chip with the specified SAK.
         *
         * @param Sak1 See Desfire datasheet.
         * @param Sak2 See Desfire datasheet.
         * @return A status code indicating the result of the operation.
         */
        long SetUserSAK(byte Sak1, byte Sak2);

        /**
         * @brief Disable the EV0 Secure Messsaging inside the DESFire chip or the current application.
         *
         * @return A status code indicating the result of the operation.
         */
        long DisableSecureMessagingEV0();

        /**
         * @brief Disable the EV1 Secure Messsaging inside the DESFire chip or the current application.
         *
         * @return A status code indicating the result of the operation.
         */
        long DisableSecureMessagingEV1();

        /**
         * @brief Disable the EV2 Chained Writing inside the DESFire chip or the current application.
         *
         * @return A status code indicating the result of the operation.
         */
        long DisableChainedWritingEV2();

        /**
         * @brief Configures the DESFire chip or the currently selected application with the specified Capability Data.
         *
         * @param PiccCap See Desfire datasheet.
         * @return A status code indicating the result of the operation.
         */
        long SetCapabilityData(byte[] PiccCap);

        /**
         * @brief Configures the DESFire chip or the currently selected application with the specified Capability Data.
         *
         * @param PiccCap12 See Desfire datasheet.
         * @param PiccCap25 See Desfire datasheet.
         * @param PiccCap26 See Desfire datasheet.
         * @return A status code indicating the result of the operation.
         */
        long SetCapabilityData(byte PiccCap12, byte PiccCap25, byte PiccCap26);

        /**
         * @brief Configures the DESFire chip with the specified VCIID.
         *
         * @param VCIID See Desfire datasheet.
         * @return A status code indicating the result of the operation.
         */
        long SetVCIID(byte[] VCIID);

        /**
         * @brief Configures the DESFire application with the specified DFName.
         *
         * @param DFName See Desfire datasheet.
         * @return A status code indicating the result of the operation.
         */
        long SetDFName(string DFName);

        /**
         * @brief Configures the DESFire application with the specified DFName.
         *
         * @param DFName See Desfire datasheet.
         * @return A status code indicating the result of the operation.
         */
        long SetDFName(byte[] DFName);

        /**
         * @brief Configures the DESFire application with the specified DFName.
         *
         * @param DFName See Desfire datasheet.
         * @param DAMMAC The MAC for Delegated Application Management.
         * @return A status code indicating the result of the operation.
         */
        long SetDFName(string DFName, byte[] DAMMAC);

        /**
         * @brief Configures the DESFire application with the specified DFName.
         *
         * @param DFName See Desfire datasheet.
         * @param DAMMAC The MAC for Delegated Application Management.
         * @return A status code indicating the result of the operation.
         */
        long SetDFName(byte[] DFName, byte[] DAMMAC);

        /* Desfire EV2 authentication */

        /**
         * @brief Performs the first step of EV2 authentication with the DESFire chip.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue);

        /**
         * @brief Performs the first step of EV2 authentication with the DESFire chip, including PCD capabilities.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @param PcdCaps2 The PCD capabilities (6 bytes).
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, byte[] PcdCaps2);

        /**
         * @brief Performs the first step of EV2 authentication with the DESFire chip, including PICC capabilities.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @param[out] PiccCaps2 The PICC capabilities (6 bytes).
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, out byte[] PiccCaps2);

        /**
         * @brief Performs the first step of EV2 authentication with the DESFire chip, including PCD and PICC capabilities.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @param PcdCaps2 The PCD capabilities (6 bytes).
         * @param[out] PiccCaps2 The PICC capabilities (6 bytes).
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, byte[] PcdCaps2, out byte[] PiccCaps2);

        /**
         * @brief Performs the first step of EV2 authentication with the DESFire chip, including PCD and PICC capabilities.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @param PcdCaps2 The PCD capabilities (6 bytes).
         * @param[out] PiccCaps2 The PICC capabilities (6 bytes).
         * @param[out] TransactionIdentifier The transaction identifier provided by the PICC (4 bytes).* 
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, byte[] PcdCaps2, out byte[] PiccCaps2, out byte[] TransactionIdentifier);

        /**
         * @brief Performs the first step of EV2 authentication with the DESFire chip, including PCD and PICC capabilities.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @param PcdCaps2 The PCD capabilities (6 bytes).
         * @param[out] PcdCaps2 The PCD capabilities echoed by the PICC (6 bytes).
         * @param[out] PiccCaps2 The PICC capabilities (6 bytes).
         * @param[out] TransactionIdentifier The transaction identifier provided by the PICC (4 bytes).* 
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, byte[] PcdCaps2, out byte[] PcdCaps2_echo, out byte[] PiccCaps2, out byte[] TransactionIdentifier);

        /**
         * @brief Performs the non-first step of EV2 authentication with the DESFire chip.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV2NonFirst(byte KeyNumber, byte[] KeyValue);

        /* Key Management Commands */

        /**
         * @brief Changes a key on the DESFire chip, supporting key versioning and key sets.
         *
         * @param KeySetNumber The key set number to use.
         * @param KeyNumber The key number to change.
         * @param KeyVersion The version of the new key.
         * @param NewKeyValue The new key value.
         * @param OldKeyValue The old key value.
         * @return A status code indicating the result of the operation.
         */
        long ChangeKeyEV2(byte KeySetNumber, byte KeyNumber, byte KeyVersion, byte[] NewKeyValue, byte[] OldKeyValue);

        /**
         * @brief Initializes a key set on the DESFire chip.
         *
         * @param KeySetNumber The key set number to initialize.
         * @param KeySetType The type of the key set.
         * @return A status code indicating the result of the operation.
         */
        long InitializeKeySet(byte KeySetNumber, byte KeySetType);

        /**
         * @brief Finalizes a key set on the DESFire chip.
         *
         * @param KeySetNumber The key set number to finalize.
         * @param KeySetVersion The version of the key set.
         * @return A status code indicating the result of the operation.
         */
        long FinalizeKeySet(byte KeySetNumber, byte KeySetVersion);

        /**
         * @brief Rolls a key set on the DESFire chip.
         *
         * This method activates a new key set version and deactivates the current one.
         *
         * @param KeySetNumber The key set number to roll.
         * @return A status code indicating the result of the operation.
         */
        long RollKeySet(byte KeySetNumber);

        /* Application Management Commands */

        /**
         * @brief Creates a new application on the DESFire chip with advanced settings.
         *
         * @param Aid The application identifier (AID).
         * @param KeySetting1 The first key setting byte.
         * @param KeySetting2 The second key setting byte.
         * @param KeySetting3 The third key setting byte.
         * @param AksVersion The version of the Application Key Set.
         * @param NoKeySets The number of key sets.
         * @param MaxKeySize The maximum key size.
         * @param AppKeySetSetting The application key set settings.
         * @param DFID The ISO DF identifier.
         * @param DFName The name of the application (array of bytes).
         * @param DFNameLen The length of the application name.
         * @return A status code indicating the result of the operation.
         */
        long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, byte KeySetting3, byte AksVersion, byte NoKeySets, byte MaxKeySize, byte AppKeySetSetting, ushort DFID, byte[] DFName, int DFNameLen);

        /**
         * @brief Creates a new application on the DESFire chip with advanced settings.
         *
         * @param Aid The application identifier (AID).
         * @param KeySetting1 The first key setting byte.
         * @param KeySetting2 The second key setting byte.
         * @param KeySetting3 The third key setting byte.
         * @param AksVersion The version of the Application Key Set.
         * @param NoKeySets The number of key sets.
         * @param MaxKeySize The maximum key size.
         * @param AppKeySetSetting The application key set settings.
         * @param DFID The ISO DF identifier.
         * @param DFName The name of the application (array of bytes).
         * @return A status code indicating the result of the operation.
         */
        long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, byte KeySetting3, byte AksVersion, byte NoKeySets, byte MaxKeySize, byte AppKeySetSetting, ushort DFID, byte[] DFName);

        /**
         * @brief Creates a new application on the DESFire chip with advanced settings.
         *
         * @param Aid The application identifier (AID).
         * @param KeySetting1 The first key setting byte.
         * @param KeySetting2 The second key setting byte.
         * @param KeySetting3 The third key setting byte.
         * @param AksVersion The version of the Application Key Set.
         * @param NoKeySets The number of key sets.
         * @param MaxKeySize The maximum key size.
         * @param AppKeySetSetting The application key set settings.
         * @param DFID The ISO DF identifier.
         * @param DFName The name of the application (string).
         * @return A status code indicating the result of the operation.
         */
        long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, byte KeySetting3, byte AksVersion, byte NoKeySets, byte MaxKeySize, byte AppKeySetSetting, ushort DFID, string DFName);

        /**
         * @brief Retrieves information about a delegated application management slot.
         *
         * @param DamSlotNumber The DAM slot number.
         * @param[out] DamSlotVersion The version of the DAM slot.
         * @param[out] QuotaLimit The quota limit for the DAM slot.
         * @param[out] FreeBlocks The number of free blocks in the DAM slot.
         * @param[out] Aid The application identifier (AID) associated with the DAM slot.
         * @return A status code indicating the result of the operation.
         */
        long GetDelegatedInfo(ushort DamSlotNumber, out byte DamSlotVersion, out ushort QuotaLimit, out ushort FreeBlocks, out uint Aid);

        /* New Update Record command */

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
        long UpdateRecord(byte FileId, byte CommMode, int FromOffset, int Size, byte[] Data);

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
        long UpdateRecord(byte FileId, DesfireCommMode CommMode, int FromOffset, int Size, byte[] Data);

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
        long UpdateRecord(byte FileId, byte CommMode, int FromOffset, byte[] Data);

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
        long UpdateRecord(byte FileId, DesfireCommMode CommMode, int FromOffset, byte[] Data);

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
        long UpdateRecord(byte FileId, byte CommMode, byte[] Data);

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
        long UpdateRecord(byte FileId, DesfireCommMode CommMode, byte[] Data);

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
        long UpdateRecord2(byte FileId, byte[] Data);

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
        long UpdateRecord2(byte FileId, int FromOffset, int Size, byte[] Data);

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
        long UpdateRecord2(byte FileId, int FromOffset, byte[] Data);

        /* Virtual Card Commands */

        /**
         * @brief Selects a virtual card instance on the DESFire chip.
         *
         * @param IID The Instance Identifier (array of bytes).
         * @param[out] PiccChal The challenge from the PICC (array of bytes).
         * @param[out] VCData The virtual card data (array of bytes).
         * @return A status code indicating the result of the operation.
         */
        long ISOSelect(byte[] IID, out byte[] PiccChal, out byte[] VCData);

        /**
         * @brief Performs external authentication for a virtual card instance.
         *
         * @param PcdChal The challenge from the PCD (array of bytes).
         * @return A status code indicating the result of the operation.
         */
        long ISOExternalAuthenticate(byte[] PcdChal);

        /**
         * @brief Selects and authenticates a virtual card instance on the DESFire chip.
         *
         * @param KeyValue The key value for authentication (array of bytes).
         * @param IID The Instance Identifier (array of bytes).
         * @param[out] PiccChal The challenge from the PICC (array of bytes).
         * @param[out] VCData The virtual card data (array of bytes).
         * @return A status code indicating the result of the operation.
         */
        long ISOSelect(byte[] KeyValue, byte[] IID, out byte[] PiccChal, out byte[] VCData);

        /**
         * @brief Performs external authentication for a virtual card instance.
         *
         * @param KeyValue The key value for authentication (array of bytes).
         * @param PiccChal The challenge from the PICC (array of bytes).
         * @param VCData The virtual card data (array of bytes).
         * @return A status code indicating the result of the operation.
         */
        long ISOExternalAuthenticate(byte[] KeyValue, byte[] PiccChal, byte[] VCData);

        /**
         * @brief Selects and authenticates a virtual card instance on the DESFire chip.
         *
         * @param KeyValue The key value for authentication (array of bytes).
         * @param IID The Instance Identifier (array of bytes).
         * @param[out] VCData The virtual card data (array of bytes).
         * @return A status code indicating the result of the operation.
         */
        long ISOSelectAndExternalAuthenticate(byte[] KeyValue, byte[] IID, out byte[] VCData);

        /* Proximity Check Commands */

        /**
         * @brief Prepares the DESFire chip for a proximity check operation.
         *
         * @param[out] Option The proximity check option.
         * @param[out] PubRespTime The public response time.
         * @param[out] PPS1 The PPS1 value.
         * @return A status code indicating the result of the operation.
         */
        long PreparePC(out byte Option, out ushort PubRespTime, out byte PPS1);

        /**
         * @brief Prepares the DESFire chip for a proximity check operation.
         *
         * @param[out] PubRespTime The public response time.
         * @return A status code indicating the result of the operation.
         */
        long PreparePC(out ushort PubRespTime);

        /**
         * @brief Prepares the DESFire chip for a proximity check operation.
         *
         * @return A status code indicating the result of the operation.
         */
        long PreparePC();

        /**
         * @brief Performs a proximity check operation on the DESFire chip.
         *
         * @param splitCount The number of splits for the proximity check.
         * @param minRespTime The minimum response time.
         * @param maxRespTime The maximum response time.
         * @param[out] meanRespTime The mean response time.
         * @return A status code indicating the result of the operation.
         */
        long ProximityCheck(int splitCount, int minRespTime, int maxRespTime, out int gotMinRespTime, out int gotMaxRespTime, out int gotAverageRespTime);

        /**
         * @brief Performs a proximity check operation on the DESFire chip.
         *
         * @param splitCount The number of splits for the proximity check.
         * @param minRespTime The minimum response time.
         * @param maxRespTime The maximum response time.
         * @param[out] meanRespTime The mean response time.
         * @return A status code indicating the result of the operation.
         */
        long ProximityCheck(int splitCount, int minRespTime, int maxRespTime, out int[] respTimes);

        /**
         * @brief Performs a proximity check operation on the DESFire chip.
         *
         * @param splitCount The number of splits for the proximity check.
         * @param minRespTime The minimum response time.
         * @param maxRespTime The maximum response time.
         * @return A status code indicating the result of the operation.
         */
        long ProximityCheck(int splitCount, int minRespTime, int maxRespTime);

        /**
         * @brief Performs a proximity check operation on the DESFire chip.
         *
         * @param splitCount The number of splits for the proximity check.
         * @param[out] meanRespTime The mean response time.
         * @return A status code indicating the result of the operation.
         */
        long ProximityCheck(int splitCount, out int meanRespTime);

        /**
         * @brief Performs a proximity check operation on the DESFire chip.
         *
         * @param[out] meanRespTime The mean response time.
         * @return A status code indicating the result of the operation.
         */
        long ProximityCheck(out int meanRespTime);

        /**
         * @brief Performs a proximity check operation on the DESFire chip.
         *
         * @param splitCount The number of splits for the proximity check.
         * @return A status code indicating the result of the operation.
         */
        long ProximityCheck(int splitCount);

        /**
         * @brief Performs a proximity check operation on the DESFire chip.
         *
         * @return A status code indicating the result of the operation.
         */
        long ProximityCheck();

        /**
         * @brief Verify the last proximity check operation on the DESFire chip with the given key.
         *
         * @return A status code indicating the result of the operation.
         */
        long VerifyPC(byte[] KeyValue);

        /**
         * @brief Verify the last proximity check operation on the DESFire chip with the current session key.
         *
         * @return A status code indicating the result of the operation.
         */
        long VerifyPC();
    }
}
