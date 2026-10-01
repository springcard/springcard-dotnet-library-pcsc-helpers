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
    public partial class Desfire
    {
        /**
         * @brief Credits a value file with a specified amount.
         *
         * @param FileId The file ID to credit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        public long Credit(byte FileId, DesfireCommMode CommMode, long Amount)
        {
            return Credit(FileId, (byte)CommMode, Amount);
        }

        /**
         * @brief Credits a value file with a specified amount.
         *
         * @param FileId The file ID to credit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        public long Credit(byte FileId, byte CommMode, long Amount)
        {
            return ModifyValue((byte)DesfireCommand.CREDIT, FileId, CommMode, Amount);
        }

        /**
         * @brief Credits a value file with a specified amount.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to credit.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        public long Credit2(byte FileId, long Amount)
        {
            byte comm_mode;
            UInt16 access_rights;
            byte read_write_access;
            long status;
            byte file_type = 0x00;

            /* we have to receive the communications mode first */
            status = GetFileSettings(FileId, out file_type, out comm_mode, out access_rights, out DesfireFileSettings fileSettings);
            if (status != Success)
                return status;

            /* Credit is controlled by the field r/w within the access_rights.                    */
            /* Depending on the AccessRights field (setting r/w) we have to decide whether        */
            /* we are able to communicate in the mode indicated by comm_mode.                     */
            /* If ctx->auth_key does not match r/w and this setting contains the value            */
            /* "ever" (0xE), communication has to be done in plain mode regardless of the mode    */
            /* indicated by comm_mode.                                                            */
            read_write_access = (byte)((access_rights & DesfireAccessRights.ReadWrite_Mask) >> DesfireAccessRights.ReadWrite_Shift);

            if ((read_write_access != GetSessionKeyNumber())
              && (read_write_access == DesfireAccessRights.Free))
            {
                comm_mode = (byte)DesfireCommMode.Plain;
            }

            /* Now execute the command */
            return Credit(FileId, comm_mode, Amount);
        }

        /**
         * @brief Credits a value file with a limited amount.
         *
         * @param FileId The file ID to credit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        public long LimitedCredit(byte FileId, DesfireCommMode CommMode, long Amount)
        {
            return LimitedCredit(FileId, (byte)CommMode, Amount);
        }

        /**
         * @brief Credits a value file with a limited amount.
         *
         * @param FileId The file ID to credit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        public long LimitedCredit(byte FileId, byte CommMode, long Amount)
        {
            return ModifyValue((byte)DesfireCommand.LIMITED_CREDIT, FileId, CommMode, Amount);
        }

        /**
         * @brief Credits a value file with a limited amount.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to credit.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        public long LimitedCredit2(byte FileId, long Amount)
        {
            byte comm_mode;
            UInt16 access_rights;
            byte write_only_access;
            byte read_write_access;
            long status;
            byte file_type = 0x00;

            /* we have to receive the communications mode first */
            status = GetFileSettings(FileId, out file_type, out comm_mode, out access_rights, out DesfireFileSettings fileSettings);
            if (status != Success)
                return status;

            /* LimitedCredit is controlled by the fields w and r/w within the access_rights.         */
            /* Depending on the access_rights field (settings w and r/w) we have to decide whether   */
            /* we are able to communicate in the mode indicated by comm_mode.                        */
            /* If ctx->auth_key does neither match w nor r/w and one of this settings                */
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
            return LimitedCredit(FileId, comm_mode, Amount);
        }

        /**
         * @brief Debits a value file by a specified amount.
         *
         * @param FileId The file ID to debit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to debit.
         * @return A status code indicating the result of the operation.
         */
        public long Debit(byte FileId, DesfireCommMode CommMode, long Amount)
        {
            return Debit(FileId, (byte)CommMode, Amount);
        }

        /**
         * @brief Debits a value file by a specified amount.
         *
         * @param FileId The file ID to debit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to debit.
         * @return A status code indicating the result of the operation.
         */
        public long Debit(byte FileId, byte CommMode, long Amount)
        {
            return ModifyValue((byte)DesfireCommand.DEBIT, FileId, CommMode, Amount);
        }

        /**
         * @brief Debits a value file by a specified amount.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to debit.
         * @param Amount The amount to debit.
         * @return A status code indicating the result of the operation.
         */
        public long Debit2(byte FileId, long Amount)
        {
            byte comm_mode;
            UInt16 access_rights;
            byte read_only_access;
            byte write_only_access;
            byte read_write_access;
            long status;
            byte file_type = 0x00;

            /* we have to receive the communications mode first */
            status = GetFileSettings(FileId, out file_type, out comm_mode, out access_rights, out DesfireFileSettings fileSettings);
            if (status != Success)
                return status;

            /* Debit is controlled by the fields r, w, r/w within the access_rights.                  */
            /* Depending on the access_rights field (settings r, w and r/w) we have to decide whether */
            /* we are able to communicate in the mode indicated by comm_mode.                         */
            /* If ctx->auth_key does neither match r, w nor r/w and one of this settings              */
            /* contains the value "ever" (0xE) communication has to be done in plain mode regardless  */
            /* of the mode indicated by comm_mode.                                                    */
            read_only_access = (byte)((access_rights & DesfireAccessRights.ReadOnly_Mask) >> DesfireAccessRights.ReadOnly_Shift);
            write_only_access = (byte)((access_rights & DesfireAccessRights.WriteOnly_Mask) >> DesfireAccessRights.WriteOnly_Shift);
            read_write_access = (byte)((access_rights & DesfireAccessRights.ReadWrite_Mask) >> DesfireAccessRights.ReadWrite_Shift);

            if ((read_only_access != GetSessionKeyNumber())
              && (write_only_access != GetSessionKeyNumber())
              && (read_write_access != GetSessionKeyNumber())
              && ((read_only_access == DesfireAccessRights.Free) || (write_only_access == DesfireAccessRights.Free) || (read_write_access == DesfireAccessRights.Free)))
            {
                comm_mode = (byte)DesfireCommMode.Plain;
            }

            /* Now execute the command */
            return Debit(FileId, comm_mode, Amount);
        }

        /**
         * @brief Modifies a value file by a specified amount.
         *
         * @param OpCode The operation code (CREDIT, DEBIT, etc.).
         * @param FileId The file ID to modify.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to modify.
         * @return A status code indicating the result of the operation.
         */
        private long ModifyValue(byte OpCode, byte FileId, byte CommMode, long Amount)
        {
            DesfireCommandFlag commandFlags = DesfireCommandFlag.WANTS_OPERATION_OK;

            logger.trace("ModifyValue[{0:X02}]({1:X02},{2:X} amount={3})", OpCode, FileId, CommMode, Amount);

            xfer_length = 0;

            /* Create the info block containing the command code, the file ID argument and the */
            /* modification amount argument.                                                   */
            xfer_buffer[xfer_length++] = OpCode;
            xfer_buffer[xfer_length++] = FileId;

            xfer_buffer[xfer_length++] = (byte)(Amount & 0x000000FF); Amount >>= 8;
            xfer_buffer[xfer_length++] = (byte)(Amount & 0x000000FF); Amount >>= 8;
            xfer_buffer[xfer_length++] = (byte)(Amount & 0x000000FF); Amount >>= 8;
            xfer_buffer[xfer_length++] = (byte)(Amount & 0x000000FF);

            if ((DesfireCommMode)CommMode == DesfireCommMode.Full)
            {
                /* Full communication */
                if (SessionIsEV2OrGreater())
                {
                    /* 'Encrypt' the buffer E(KSesAuth, NewKeyValue[|| KeyVer]) */
                    Xfer_Padd_CipherSend(2);
                    /* Append the CMAC */
                    Xfer_AppendCmac();
                }
                else if (SessionIsEV0OrGreater())
                {
                    /* Append a CRC to the amount argument. */
                    XferAppendCrc(2);
                    /* 'Encrypt' the amount argument bytes and the CRC bytes */
                    Xfer_Padd_CipherSend(2);
                }

                commandFlags |= DesfireCommandFlag.CHECK_RESPONSE_CMAC;
            }
            else if ((DesfireCommMode)CommMode == DesfireCommMode.Maced)
            {
                /* Full communication */
                if (SessionIsEV1OrGreater())
                {
                    /* Compute the CMAC, both ways */
                    commandFlags |= DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC;
                }
                else if (SessionIsEV0OrGreater())
                {
                    SessionCryptoContext.AppendCmacSend(ref xfer_buffer, ref xfer_length, INF + 2, 4);
                }
            }
            else
            {
                if (SessionIsEV2OrGreater())
                {
                    /* Plain is plain, but we must increment the counter */
                    commandFlags |= DesfireCommandFlag.INCREMENT_COUNTER;
                }
                else if (SessionIsEV1OrGreater())
                {
                    /* Check the CMAC in response */
                    commandFlags |= DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC;
                }
            }

            /* Communicate the info block to the card and check the operation's return status. */
            return Command(0, commandFlags);
        }

        /**
         * @brief Retrieves the current value of a value file.
         *
         * @param FileId The file ID to query.
         * @param CommMode The communication mode of the file.
         * @param[out] Value The current value of the file.
         * @return A status code indicating the result of the operation.
         */
        public long GetValue(byte FileId, DesfireCommMode CommMode, out long Value)
        {
            return GetValue(FileId, (byte)CommMode, out Value);
        }

        /**
         * @brief Retrieves the current value of a value file.
         *
         * @param FileId The file ID to query.
         * @param CommMode The communication mode of the file.
         * @param[out] Value The current value of the file.
         * @return A status code indicating the result of the operation.
         */
        public long GetValue(byte FileId, byte CommMode, out long Value)
        {
            long temp;
            long status;

            logger.trace("GetValue({0:X2},{1:X})", FileId, CommMode);

            Value = 0;

            /* Create the info block containing the command code and the file ID argument. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.GET_VALUE;
            xfer_buffer[INF + 1] = FileId;
            xfer_length = 2;

            if (SessionIsEV2OrGreater())
            {
                if ((DesfireCommMode)CommMode == DesfireCommMode.Full)
                {
                    status = Command(17, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
                    if (status != Success)
                        return status;
                    if (!Xfer_CipherRecv_Unpadd(1))
                        return LibraryError(DesfireLibraryError.WrongPadding);
                }
                else if ((DesfireCommMode)CommMode == DesfireCommMode.Maced)
                {
                    status = Command(5, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
                    if (status != Success)
                        return status;
                }
                else
                {
                    status = Command(5, DesfireCommandFlag.INCREMENT_COUNTER | DesfireCommandFlag.WANTS_OPERATION_OK);
                    if (status != Success)
                        return status;
                }
            }
            else
            {
                if ((DesfireCommMode)CommMode == DesfireCommMode.Full)
                {
                    /* The communication mode is EDesfireCommMode.Full.                 */
                    /* GetValue returns 9 bytes in DES/3DES mode and 17 bytes in AES mode */
                    int expected_length;

                    if (SessionIsAES())
                    {
                        status = Command(17, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
                        expected_length = 16;
                    }
                    else
                    {
                        status = Command(9, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
                        expected_length = 8;
                    }
                    if (status != Success)
                        return status;

                    byte[] tmp = new byte[expected_length];
                    Array.ConstrainedCopy(xfer_buffer, 1, tmp, 0, expected_length);
                    /* Decipher the received block. */
                    SessionCryptoContext.CipherRecv(ref tmp, ref expected_length);
                    Array.ConstrainedCopy(tmp, 0, xfer_buffer, 1, expected_length);

                    if (SessionIsEV1OrGreater())
                    {
                        /* Verify the CRC */
                        if (VerifyCrc32(xfer_buffer, INF, 5, true, null) != Success)
                        {
                            /* abortion due to integrity error -> wrong CRC */
                            return LibraryError(DesfireLibraryError.WrongCRC);
                        }
                    }
                    else
                    {
                        /* Verify the CRC */
                        if (VerifyCrc16(xfer_buffer, INF + 1, 4, null) != Success)
                        {
                            /* abortion due to integrity error -> wrong CRC */
                            return LibraryError(DesfireLibraryError.WrongCRC);
                        }
                        /* Check also the padding bytes for enhanced security. */
                        if ((xfer_buffer[INF + 7] != 0x00) || (xfer_buffer[INF + 8] != 0x00))
                        {
                            /* Error: cryptogram contains incorrect padding bytes. */
                            return LibraryError(DesfireLibraryError.WrongPadding);
                        }
                    }
                }
                else if (((DesfireCommMode)CommMode == DesfireCommMode.Maced) && (GetSessionType() != EAuthType.NONE))
                {
                    /* The communication mode is EDesfireCommMode.MacED.                      */

                    if (SessionIsEV1OrGreater())
                    {
                        /* GetValue returns 13 bytes, the status byte, the four byte value and */
                        /* the eight byte MAC.                                                 */
                        status = Command(13, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
                        if (status != Success)
                            return status;
                    }
                    else
                    {
                        /* GetValue returns 9 bytes, the status byte, the four byte value and */
                        /* the four byte MAC.                                                 */
                        byte[] mac32 = new byte[4];

                        status = Command(9, DesfireCommandFlag.WANTS_OPERATION_OK);
                        if (status != Success)
                            return status;
                    }

                    /* Check the received CMAC. */
                    if (!SessionCryptoContext.VerifyAndRemoveCmacRecv(xfer_buffer, ref xfer_length))
                        return LibraryError(DesfireLibraryError.WrongCMAC);
                }
                else
                {
                    /* GetValue returns 5 bytes, the status byte and the four byte value. */
                    status = Command(5, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
                    if (status != Success)
                        return status;
                }
            }

            /* Return the requested value bytes. */
            temp = xfer_buffer[INF + 4]; temp <<= 8;
            temp += xfer_buffer[INF + 3]; temp <<= 8;
            temp += xfer_buffer[INF + 2]; temp <<= 8;
            temp += xfer_buffer[INF + 1];

            //if (value != null)
            Value = temp;

            /* Success. */
            return Success;
        }

        /**
         * @brief Retrieves the current value of a value file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to query.
         * @param[out] Value The current value of the file.
         * @return A status code indicating the result of the operation.
         */
        public long GetValue2(byte FileId, out long Value)
        {
            byte comm_mode;
            UInt16 access_rights;
            byte read_only_access;
            byte write_only_access;
            byte read_write_access;
            long status;

            Value = 0;

            byte file_type = 0x00;

            /* we have to receive the communications mode first */
            status = GetFileSettings(FileId, out file_type, out comm_mode, out access_rights, out DesfireFileSettings fileSettings);
            if (status != Success)
                return status;

            /* GetValue is controlled by the fields r, w, r/w within the access_rights.               */
            /* Depending on the access_rights field (settings r, w and r/w) we have to decide whether */
            /* we are able to communicate in the mode indicated by comm_mode.                         */
            /* If ctx->auth_key does neither match r, w nor r/w and one of this settings              */
            /* contains the value "ever" (0xE) communication has to be done in plain mode regardless  */
            /* of the mode indicated by comm_mode.                                                    */
            read_only_access = (byte)((access_rights & DesfireAccessRights.ReadOnly_Mask) >> DesfireAccessRights.ReadOnly_Shift);
            write_only_access = (byte)((access_rights & DesfireAccessRights.WriteOnly_Mask) >> DesfireAccessRights.WriteOnly_Shift);
            read_write_access = (byte)((access_rights & DesfireAccessRights.ReadWrite_Mask) >> DesfireAccessRights.ReadWrite_Shift);

            if ((read_only_access != GetSessionKeyNumber())
              && (write_only_access != GetSessionKeyNumber())
              && (read_write_access != GetSessionKeyNumber())
              && ((read_only_access == DesfireAccessRights.Free) || (write_only_access == DesfireAccessRights.Free) || (read_write_access == DesfireAccessRights.Free)))
            {
                comm_mode = (byte)DesfireCommMode.Plain;
            }

            /* Now execute the command */
            return GetValue(FileId, comm_mode, out Value);
        }

    }
}
