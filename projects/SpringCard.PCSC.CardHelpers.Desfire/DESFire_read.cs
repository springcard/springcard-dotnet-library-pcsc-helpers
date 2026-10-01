/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using SpringCard.LibCs;
using System;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
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
        public long ReadData(byte FileId, byte CommMode, int FromOffset, int MaxCount, out byte[] Data)
        {
            return ReadDataEx((byte)DesfireCommand.READ_DATA, FileId, CommMode, FromOffset, MaxCount, 1, out Data);
        }

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
        public long ReadData(byte FileId, DesfireCommMode CommMode, int FromOffset, int MaxCount, out byte[] Data)
        {
            return ReadData(FileId, (byte)CommMode, FromOffset, MaxCount, out Data);
        }

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
        public long ReadData(byte FileId, byte CommMode, int MaxCount, out byte[] Data)
        {
            return ReadData(FileId, CommMode, 0, MaxCount, out Data);
        }

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
        public long ReadData(byte FileId, DesfireCommMode CommMode, int MaxCount, out byte[] Data)
        {
            return ReadData(FileId, (byte)CommMode, MaxCount, out Data);
        }

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
        public long ReadData(byte FileId, byte CommMode, out byte[] Data)
        {
            return ReadData(FileId, CommMode, 0, 0, out Data);
        }

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
        public long ReadData(byte FileId, DesfireCommMode CommMode, out byte[] Data)
        {
            return ReadData(FileId, (byte)CommMode, out Data);
        }

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
        public long ReadData2(byte FileId, int FromOffset, int MaxCount, out byte[] Data)
        {
            byte read_only_access;
            byte read_write_access;
            long status;

            Data = null;

            // we have to receive the communications mode first 
            status = GetFileSettings(FileId, out byte fileType, out byte commMode, out ushort accessRights, out DesfireFileSettings fileSettings);
            if (status != Success)
                return status;

            // Depending on the AccessRights field (settings r and r/w) we have to decide whether    
            // we are able to communicate in the mode indicated by comm_mode.                        
            // If auth_key does neither match r nor r/w and one of this settings                
            // contains the value "ever" (0x0E) communication has to be done in plain mode regardless 
            // of the mode indicated by comm_mode.                                                  
            read_only_access = (byte)((accessRights & DesfireAccessRights.ReadOnly_Mask) >> DesfireAccessRights.ReadOnly_Shift);
            read_write_access = (byte)((accessRights & DesfireAccessRights.ReadWrite_Mask) >> DesfireAccessRights.ReadWrite_Shift);

            if ((read_only_access != GetSessionKeyNumber())
             && (read_write_access != GetSessionKeyNumber())
             && ((read_only_access == DesfireAccessRights.Free) || (read_write_access == DesfireAccessRights.Free)))
            {
                commMode = (byte)DesfireCommMode.Plain;
            }

            // Now execute the command
            return ReadData(FileId, commMode, FromOffset, MaxCount, out Data);
        }

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
        public long ReadData2(byte FileId, int MaxCount, out byte[] Data)
        {
            return ReadData2(FileId, 0, MaxCount, out Data);
        }

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
        public long ReadData2(byte FileId, out byte[] Data)
        {
            return ReadData2(FileId, 0, 0, out Data);
        }

        protected long ReadDataEx(byte OpCode, byte FileId, byte CommMode, int FromOffset, int ItemCount, int ItemSize, out byte[] Data)
        {
            long status;
            int recv_length = 0;
            int byte_count, buffer_size;
            int temp;

            Data = null;

            logger.trace("ReadDataEx[{0:X02}]({1:X02},{2:X} offset={3} length={4}*{5})",
                OpCode,
                FileId,
                CommMode,
                FromOffset,
                ItemCount,
                ItemSize); ;

            /* We have to calculate the number of bytes as this function works at byte granularity.
                Cast the UInt32 to double in the multiplication to detect an overflow in the result.
                If an overflow occurs, continue with the maximum number provided by a UInt32. The PICC
                will refuse the read request in this case with a BOUNDARY_ERROR. */
            byte_count = ItemCount * ItemSize;

            if (byte_count > MAX_FILE_DATA_SIZE)
            {
                /* Must overflow */
                byte_count = int.MaxValue;
                buffer_size = MAX_FILE_DATA_SIZE + 32;
            }
            else if (byte_count == 0)
            {
                /* Actual size is unknown */
                buffer_size = MAX_FILE_DATA_SIZE + 32;
            }
            else
            {
                /* Actual size is specified */
                buffer_size = byte_count + 32;
            }

            byte[] recv_buffer = new byte[buffer_size];

            xfer_length = 0;

            xfer_buffer[xfer_length++] = OpCode;
            /* we do not have to take the item_size into account for the
               generation of the command header as the PICC resolves the meaning of this
               parameter due to the specific command code */
            xfer_buffer[xfer_length++] = FileId;

            temp = FromOffset;
            xfer_buffer[xfer_length++] = (byte)(temp & 0x000000FF); temp >>= 8;
            xfer_buffer[xfer_length++] = (byte)(temp & 0x000000FF); temp >>= 8;
            xfer_buffer[xfer_length++] = (byte)(temp & 0x000000FF);

            temp = ItemCount;
            xfer_buffer[xfer_length++] = (byte)(temp & 0x000000FF); temp >>= 8;
            xfer_buffer[xfer_length++] = (byte)(temp & 0x000000FF); temp >>= 8;
            xfer_buffer[xfer_length++] = (byte)(temp & 0x000000FF);

            recv_buffer[recv_length++] = (byte)Success;

            for (; ; )
            {
                if (SessionIsEV2OrGreater())
                {
                    if ((DesfireCommMode)CommMode == DesfireCommMode.Full)
                    {
                        status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME | DesfireCommandFlag.WANTS_OPERATION_OK);
                    }
                    else if ((DesfireCommMode)CommMode == DesfireCommMode.Maced)
                    {
                        status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME | DesfireCommandFlag.WANTS_OPERATION_OK);
                    }
                    else
                    {
                        status = Command(0, DesfireCommandFlag.INCREMENT_COUNTER | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME | DesfireCommandFlag.WANTS_OPERATION_OK);
                    }

                }
                else
                {
                    status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME | DesfireCommandFlag.WANTS_OPERATION_OK);
                }

                if (status != Success)
                    goto done;                

                if ((xfer_length - 1) <= (recv_buffer.Length - recv_length))
                {
                    Array.ConstrainedCopy(xfer_buffer, INF + 1, recv_buffer, recv_length, (xfer_length - 1));
                    recv_length += xfer_length - 1;
                }
                else
                {
                    /* Overflow will be detected later */
                    recv_length += xfer_length - 1;
                }

                if (xfer_buffer[INF + 0] != (byte) DesfireCardError.AdditionalFrame)
                    break;

                xfer_length = 1;
            }

            logger.trace("Received: {0}", BinConvert.ToHex(recv_buffer, recv_length));

            /* correct termination of this loop only is possible if we received
               a frame with the status code sgbOPERATION_OK
               this means that this was the last frame sent by the PICC
               the additional frame status code which was prepared at the end of the loop
               is not sent but discarded */

            if ((SessionIsEV1OrGreater()) && ((DesfireCommMode)CommMode != DesfireCommMode.Full))
            {
                /* Plain communication */
                if ((SessionIsEV2OrGreater()) && (((DesfireCommMode)CommMode == DesfireCommMode.Plain) || ((DesfireCommMode)CommMode == DesfireCommMode.Plain2)))
                {
                    /* EV2 no CMAC for plain option */
                }
                else
                {
                    /* there must be a 8-byte CMAC at the end of the frame */
                    if ((recv_length < 9) || ((ItemSize > 1) && (((recv_length - 9) % ItemSize) != 0)))
                    {
                        logger.trace("Received {0}B with ItemSize={1}B", recv_length, ItemSize);
                        return LibraryError(DesfireLibraryError.WrongLength);
                    }
                }
            }

            /* decide upon the communications mode which cryptographic operation
               is to be applied on the received data */

            if (((DesfireCommMode)CommMode == DesfireCommMode.Plain) || ((DesfireCommMode)CommMode == DesfireCommMode.Plain2))
            {
                /* Plain communication */
                if (SessionIsEV2OrGreater())
                {
                    /* EV2 no CMAC for plain option */
                }
                else if (SessionIsEV1OrGreater())
                {
                    if (!SessionCryptoContext.VerifyAndRemoveCmacRecv(recv_buffer, ref recv_length))
                        status = LibraryError(DesfireLibraryError.WrongCMAC);
                }
            }
            else if ((DesfireCommMode)CommMode == DesfireCommMode.Maced)
            {
                /* MACed communication */
                if (!SessionCryptoContext.VerifyAndRemoveCmacRecv(recv_buffer, ref recv_length))
                {
                    status = LibraryError(DesfireLibraryError.WrongCMAC);
                }

            }
            else if ((DesfireCommMode)CommMode == DesfireCommMode.Full)
            {
                /* Enciphered communication */
                if (SessionIsEV2OrGreater())
                {
                    if (!SessionCryptoContext.VerifyAndRemoveCmacRecv(recv_buffer, ref recv_length))
                    {
                        status = LibraryError(DesfireLibraryError.WrongCMAC);
                        goto done;
                    }

                    status = DecipherAfterReadEV2(recv_buffer, ref recv_length);
                }
                else if (SessionIsEV1OrGreater())
                {
                    status = DecipherAfterReadEV1(recv_buffer, ref recv_length, ItemCount, byte_count);
                }
                else
                {
                    status = DecipherAfterReadEV0(recv_buffer, ref recv_length, ItemCount, byte_count);
                }
            }

            if (status != Success)
                goto done;


            /* Remove status byte from actual length */
            if (recv_length > 0)
                recv_length--;

            if ((ItemCount == 0) || (ItemSize == 0))
            {
                /* if no length parameter has been passed,
                   eNbytes is set with the number of received bytes
                   this is valid for both, record files and data files */
                byte_count = recv_length;
            }
            else if (recv_length != byte_count)
            {
                /* if a length parameter has been passed we check, whether we got exactly that much data. */
                logger.trace("Expected {0}B, got {1}B instead", byte_count, recv_length);
                status = LibraryError(DesfireLibraryError.WrongLength);
                goto done;
            }

            /* copy data */
            Data = BinUtils.Copy(recv_buffer, 1, byte_count);

        done:
            return status;
        }





        long DecipherAfterReadEV0(byte[] recv_buffer, ref int recv_length, int item_count, int byte_count)
        {
            int length;

            length = recv_length;

            /* check whether the received data count is multiple of 8 */
            length--;
            if ((length % 8) != 0)
            {
                return LibraryError(DesfireLibraryError.WrongLength);
            }

            /* at first we have to decipher the recv_buffer */
            byte[] tmp = new byte[length];
            Array.ConstrainedCopy(recv_buffer, 1, tmp, 0, length);

            SessionCryptoContext.CipherRecv(ref tmp, ref length);

            Array.ConstrainedCopy(tmp, 0, recv_buffer, 1, length);

            /* now there are two different paths caused by the two different padding methods */

            /* if the data length was specified in the parameter section of the command
               the recv_buffer content is padded with all zeroes or possibly none,
               after the CRC to reach multiples of 8 bytes, suitable for the DesOperation
               in the other case, where no data length was specified, the recv_buffer content is padded
               at least with one byte coded to 0x80 which is followed by all zeroes or possibly
               none, after the CRC to reach multiples of 8 bytes, suitable for the DesOperation */
            if (item_count != 0)
            {
                while (length > (byte_count + 2))
                {
                    if (recv_buffer[length] != 0x00)
                    {
                        /* Fatal */
                        return LibraryError(DesfireLibraryError.WrongPadding);
                    }
                    length--;
                }

            }
            else
            {
                /* no length was specified, therefore the second padding rule applies
                   we have to find the character 0x80 at the end of the received data
                   and obtain the number of data bytes by subtracting 2 bytes from the position
                   where 0x80 was found ( position + 1 = length ) */
                while (length > 0)
                {
                    if (recv_buffer[length] == 0x80)
                    {
                        /* Size of CRC */
                        length -= 2;
                        break;
                    }
                    if (recv_buffer[length] != 0x00)
                    {
                        /* Wrong padding */
                        return LibraryError(DesfireLibraryError.WrongPadding);
                    }

                    /* Still in padding */
                    length--;
                }

                byte_count = length - 1;
            }

            /* this is the CRC check for both cases (specified and unspecified length) */
            tmp = new byte[byte_count + 2];
            Array.ConstrainedCopy(recv_buffer, 1, tmp, 0, (byte_count + 2));

            if (VerifyCrc16(recv_buffer, 1, byte_count/*+2*/, null) != Success)
            {
                /* abortion due to integrity error -> wrong CRC */
                return LibraryError(DesfireLibraryError.WrongCRC);
            }

            recv_length = byte_count + 1;
            return Success;
        }

        long DecipherAfterReadEV1(byte[] recv_buffer, ref int recv_length, int item_count, int byte_count)
        {
            int length, block_size;

            length = recv_length;

            if (length < 1)
                return LibraryError(DesfireLibraryError.WrongLength);

            length--;

            logger.trace("DecipherAfterReadEV1 length={0} count={1}", length, item_count);

            /* check whether the received data count is multiple of block size */
            block_size = SessionIsAES() ? 16 : 8;
            if ((length % block_size) != 0)
                return LibraryError(DesfireLibraryError.WrongLength);

            /* at first we have to decipher the recv_buffer */
            byte[] tmp = new byte[length];
            Array.ConstrainedCopy(recv_buffer, 1, tmp, 0, length);
            SessionCryptoContext.CipherRecv(ref tmp, ref length);
            Array.ConstrainedCopy(tmp, 0, recv_buffer, 1, length);

            /* now there are two different paths caused by the two different padding methods */

            /* if the data length was specified in the parameter section of the command
               the recv_buffer content is padded with all zeroes or possibly none,
               after the CRC to reach multiples of 8 bytes, suitable for the DesOperation
               in the other case, where no data length was specified, the recv_buffer content is padded
               at least with one byte coded to 0x80 which is followed by all zeroes or possibly
               none, after the CRC to reach multiples of 8 bytes, suitable for the DesOperation */
            if (item_count != 0)
            {
                while (length > (byte_count + 4))
                {
                    if (recv_buffer[length] != 0x00)
                    {
                        return LibraryError(DesfireLibraryError.WrongPadding);
                    }
                    length--;
                }
            }
            else
            {
                /* no length was specified, therefore the second padding rule applies
                    we have to find the character 0x80 at the end of the received data
                    and obtain the number of data bytes by subtracting 2 bytes from the position
                    where 0x80 was found ( position + 1 = length ) */

                while (length > 0)
                {
                    if (recv_buffer[length] == 0x80)
                    {
                        /* Size of CRC */
                        length -= 4;
                        break;
                    }
                    if (recv_buffer[length] != 0x00)
                    {
                        /* Wrong padding */
                        return LibraryError(DesfireLibraryError.WrongPadding);
                    }

                    /* Still in padding */
                    length--;
                }

                byte_count = length - 1;
            }

            /* this is the CRC check for both cases (specified and unspecified length) */
            // In ISO mode the status byte is added at the end of the data block
            // for CRC32 calculation:
            if (VerifyCrc32(recv_buffer, 0, byte_count + 1, true, null) != Success)
            {
                /* abortion due to integrity error -> wrong CRC */
                return LibraryError(DesfireLibraryError.WrongCRC);
            }

            recv_length = byte_count + 1;
            return Success;
        }

        long DecipherAfterReadEV2(byte[] recv_buffer, ref int recv_length)
        {
            int paddedLen = recv_length - 1;
            if ((paddedLen % SessionCryptoContext.BlockSize) != 0)
                return LibraryError(DesfireLibraryError.WrongPadding);
            byte[] buffer = BinUtils.Copy(recv_buffer, 1, paddedLen);
            SessionCryptoContext.CipherRecv(ref buffer);
            if (!SessionCryptoContext.Unpadd(ref buffer))
                return LibraryError(DesfireLibraryError.WrongPadding);
            int unpaddedLen = buffer.Length;
            Array.ConstrainedCopy(buffer, 0, recv_buffer, 1, unpaddedLen);
            recv_length = recv_length - paddedLen + unpaddedLen;
            return Success;
        }

        public long ReadDataIso(byte FileId, int FromOffset, int MaxCount, out byte[] Data, out int ActualCount)
        {
            byte read_only_access;
            byte read_write_access;
            long status;

            Data = null;
            ActualCount = 0;

            status = GetFileSettings(FileId, out byte fileType, out byte commMode, out ushort accessRights, out DesfireFileSettings fileSettings);
            if (status != Success)
                return status;

            // Depending on the AccessRights field (settings r and r/w) we have to decide whether    
            // we are able to communicate in the mode indicated by comm_mode.                        
            // If auth_key does neither match r nor r/w and one of this settings                
            // contains the value "ever" (0x0E) communication has to be done in plain mode regardless 
            // of the mode indicated by comm_mode.                                                  
            read_only_access = (byte)((accessRights & DesfireAccessRights.ReadOnly_Mask) >> DesfireAccessRights.ReadOnly_Shift);
            read_write_access = (byte)((accessRights & DesfireAccessRights.ReadWrite_Mask) >> DesfireAccessRights.ReadWrite_Shift);

            if (    (read_only_access != GetSessionKeyNumber())
                    && (read_write_access != GetSessionKeyNumber())
                    && ((read_only_access == DesfireAccessRights.Free) || (read_write_access == DesfireAccessRights.Free)) )
            {
                commMode = (byte)DesfireCommMode.Plain;
            }

            /* PCB(1) CID(1) CLA(1) INS(1) p1(1) p2(1) Lc(1) ... Le(1) EDC(2)*/
            /* 10 for APDU header, and 7 for Read Desfire command */
            /*max_fsc = (MAX_FSC - (10 + 8));
            done_count = 0;
            
            // Now execute the command
            if (max_count >= max_fsc)
            {
                size_proceed = max_count;
                while (size_proceed > 0)
                {
                    status = ReadDataEx((byte)DesfireCommand.READ_DATA_ISO, file_id, comm_mode, offset_proceed, max_fsc, 1, ref data, offset_read, ref done_count);
                    if (status != DesfireCommand.OPERATION_OK)
                        return status;
                    offset_read += done_count;
                    if (size_proceed > max_fsc)
                    {
                        size_proceed -= max_fsc;
                        offset_proceed += max_fsc;
                    }
                    else
                    {
                        size_proceed = 0;
                    }
                }
            }
            else 
    */
            {
                ActualCount = 0;
                status = ReadDataEx((byte)DesfireCommand.READ_DATA_ISO, FileId, commMode, FromOffset, MaxCount, 1, out Data);
            }
            return status;
        }
    }
}
