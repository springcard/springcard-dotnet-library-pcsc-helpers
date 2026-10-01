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
         * @brief Writes data to a standard or backup file.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        public long WriteData(byte FileId, DesfireCommMode CommMode, int FromOffset, int Size, byte[] Data)
        {
            return WriteData(FileId, (byte)CommMode, FromOffset, Size, Data);
        }

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
        public long WriteData(byte FileId, byte CommMode, int FromOffset, int Size, byte[] Data)
        {
            return WriteOrUpdateEx((byte)DesfireCommand.WRITE_DATA, FileId, CommMode, FromOffset, Size, Data);
        }

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
        public long WriteData(byte FileId, DesfireCommMode CommMode, int FromOffset, byte[] Data)
        {
            return WriteData(FileId, (byte)CommMode, FromOffset, Data);
        }

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
        public long WriteData(byte FileId, byte CommMode, byte[] Data)
        {
            return WriteData(FileId, CommMode, 0, Data.Length, Data);
        }

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
        public long WriteData(byte FileId, DesfireCommMode CommMode, byte[] Data)
        {
            return WriteData(FileId, (byte)CommMode, Data);
        }

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
        public long WriteData(byte FileId, byte CommMode, int FromOffset, byte[] Data)
        {
            return WriteData(FileId, CommMode, FromOffset, Data.Length, Data);
        }


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
        public long WriteData2(byte FileId, int FromOffset, int Size, byte[] Data)
        {
            byte write_only_access;
            byte read_write_access;
            long status;

            // we have to receive the communications mode first
            status = GetFileSettings(FileId, out byte fileType, out byte commMode, out ushort accessRights, out DesfireFileSettings fileSettings);
            if (status != Success)
                return status;

            // Depending on the access_rights field (settings w and r/w) we have to decide whether   
            // we are able to communicate in the mode indicated by comm_mode.                        
            // If ctx->auth_key does neither match w nor r/w and one of this settings                
            // contains the value "ever" (0xE) communication has to be done in plain mode regardless 
            // of the mode indicated by comm_mode.                                                  
            write_only_access = (byte)((accessRights & DesfireAccessRights.WriteOnly_Mask) >> DesfireAccessRights.WriteOnly_Shift);
            read_write_access = (byte)((accessRights & DesfireAccessRights.ReadWrite_Mask) >> DesfireAccessRights.ReadWrite_Shift);

            if ((write_only_access != GetSessionKeyNumber())
             && (read_write_access != GetSessionKeyNumber())
             && ((write_only_access == DesfireAccessRights.Free) || (read_write_access == DesfireAccessRights.Free)))
            {
                commMode = (byte)DesfireCommMode.Plain;
            }

            // Now execute the command
            return WriteData(FileId, commMode, FromOffset, Size, Data);
        }

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
        public long WriteData2(byte FileId, int FromOffset, byte[] Data)
        {
            return WriteData2(FileId, FromOffset, Data.Length, Data);
        }

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
        public long WriteData2(byte FileId, byte[] Data)
        {
            return WriteData2(FileId, 0, Data.Length, Data);
        }



        public long WriteDataIso(byte file_id, int from_offset, int size, byte[] data)
        {
            byte comm_mode = 0;
            ushort access_rights = 0;
            byte write_only_access;
            byte read_write_access;
            long status;
            int size_proceed = 0;
            int offset_proceed = from_offset;
            // we have to receive the communications mode first
            byte file_type;
            DesfireFileSettings file_settings;
            status = GetFileSettings(file_id, out file_type, out comm_mode, out access_rights, out file_settings);
            if (status != Success)
                return status;

            // Depending on the access_rights field (settings w and r/w) we have to decide whether   
            // we are able to communicate in the mode indicated by comm_mode.                        
            // If ctx->auth_key does neither match w nor r/w and one of this settings                
            // contains the value "ever" (0xE) communication has to be done in plain mode regardless 
            // of the mode indicated by comm_mode.                                                  
            write_only_access = (byte)((access_rights & DesfireAccessRights.WriteOnly_Mask) >> DesfireAccessRights.WriteOnly_Shift);
            read_write_access = (byte)((access_rights & DesfireAccessRights.ReadWrite_Mask) >> DesfireAccessRights.ReadWrite_Shift);

            if ((write_only_access != GetSessionKeyNumber())
             && (read_write_access != GetSessionKeyNumber())
             && ((write_only_access == DesfireAccessRights.Free) || (read_write_access == DesfireAccessRights.Free)))
            {
                comm_mode = (byte)DesfireCommMode.Plain;
            }

            // Now execute the command
            if (size >= MaxIsoDataInSize)
            {
                size_proceed = size;
                while (size_proceed > 0)
                {
                    if (size_proceed > MaxIsoDataInSize)
                        status = WriteOrUpdateEx((byte)DesfireCommand.WRITE_DATA_ISO, file_id, comm_mode, offset_proceed, MaxIsoDataInSize, data);
                    else
                        status = WriteOrUpdateEx((byte)DesfireCommand.WRITE_DATA_ISO, file_id, comm_mode, offset_proceed, size_proceed, data);

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
                status = WriteOrUpdateEx((byte)DesfireCommand.WRITE_DATA_ISO, file_id, comm_mode, from_offset, size, data);

            return status;
        }

        protected long WriteOrUpdateEx(byte OpCode, byte FileId, byte CommMode, int FromOffset, int Length, byte[] Data)
        {
            long status;
            int buffer_size, actual_length, next_length, done_length = 0;
            DesfireCommandFlag commandFlags;
            int temp;

            logger.trace("WriteData[{0:X02}]({1:X02},{2:X} offset={3} length={4} data={5})",
                OpCode,
                FileId,
                CommMode,
                FromOffset,
                Length,
                BinConvert.ToHex(Data, 0, Length));

            buffer_size = Length + 64; // TODO : confirmer la longueur

            byte[] buffer = new byte[buffer_size];

            for (int k = 0; k < buffer_size; k++) // TODO
                buffer[k] = 0;

            actual_length = 0;
            buffer[actual_length++] = OpCode;
            buffer[actual_length++] = FileId;

            temp = FromOffset;
            buffer[actual_length++] = (byte)(temp & 0x000000FF); temp >>= 8;
            buffer[actual_length++] = (byte)(temp & 0x000000FF); temp >>= 8;
            buffer[actual_length++] = (byte)(temp & 0x000000FF);

            temp = Length;
            buffer[actual_length++] = (byte)(temp & 0x000000FF); temp >>= 8;
            buffer[actual_length++] = (byte)(temp & 0x000000FF); temp >>= 8;
            buffer[actual_length++] = (byte)(temp & 0x000000FF);

            if (Data.Length >= Length)
            {
                Array.ConstrainedCopy(Data, 0, buffer, actual_length, Length);
                actual_length += Length;
            }
            else
            {
                Array.ConstrainedCopy(Data, 0, buffer, actual_length, Data.Length);
                actual_length += Data.Length;
            }

            /* decide upon the communications mode which cryptographic */
            /* operation is to be applied on the data                  */
            if (SessionIsEV2OrGreater())
            {
                if ((DesfireCommMode)CommMode == DesfireCommMode.Full)
                {
                    SessionCryptoContext.Padd(ref buffer, ref actual_length, 8);
                    SessionCryptoContext.CipherSend(ref buffer, ref actual_length, 8);
                    SessionCryptoContext.AppendCmacSend(ref buffer, ref actual_length);
                }
                else if ((DesfireCommMode)CommMode == DesfireCommMode.Maced)
                {
                    SessionCryptoContext.AppendCmacSend(ref buffer, ref actual_length);
                }
                else
                {
                    /* do nothing (but the counter will be incremented anyway) */
                }
            }
            else if (SessionIsEV1OrGreater())
            {
                if ((DesfireCommMode)CommMode == DesfireCommMode.Full)
                {
                    /* at first we have to append the CRC bytes, computed other the whole buffer */
                    byte[] crc = new byte[4];
                    ComputeCrc32(buffer, actual_length, ref crc);
                    Array.ConstrainedCopy(crc, 0, buffer, actual_length, 4);
                    actual_length += 4;

                    /* finally do the padding and the cipher operation on the data + CRC only */
                    SessionCryptoContext.Padd(ref buffer, ref actual_length, 8, DesfireCryptoContext.EPaddMode.Zeros);
                    SessionCryptoContext.CipherSend(ref buffer, ref actual_length, 8);
                }
                else if ((DesfireCommMode)CommMode == DesfireCommMode.Maced)
                {
                    /* append the 8 bytes CMAC (computed over the whole buffer) */
                    byte[] cmac = SessionCryptoContext.ComputeCmacSend(buffer, actual_length);
                    Array.ConstrainedCopy(cmac, 0, buffer, actual_length, cmac.Length);
                    actual_length += cmac.Length;
                }
                else
                {
                    /* Feed the CMAC unit */
                    SessionCryptoContext.ComputeCmacSend(buffer, actual_length);
                }
            }
            else
            {
                if ((DesfireCommMode)CommMode == DesfireCommMode.Full)
                {

                    /* we compute the CRC other the data only */
                    byte[] crc = new byte[2];
                    ComputeCrc16(buffer, 8, actual_length, ref crc);
                    Array.ConstrainedCopy(crc, 0, buffer, actual_length, 2);
                    actual_length += 2;

                    /* finally do the padding and the cipher operation on the data + CRC only */
                    SessionCryptoContext.Padd(ref buffer, ref actual_length, 8, DesfireCryptoContext.EPaddMode.Zeros);
                    SessionCryptoContext.CipherSend(ref buffer, ref actual_length, 8);
                }
                else if ((DesfireCommMode)CommMode == DesfireCommMode.Maced)
                {
                    /* append the 4 bytes MAC (computed over the data only) */
                    byte[] cmac = SessionCryptoContext.ComputeCmacSend(Data, Length);
                    Array.ConstrainedCopy(cmac, 0, buffer, actual_length, cmac.Length);
                    actual_length += cmac.Length;
                }
            }

            /* Now our data is ready for being sent to the PICC */
            do
            {
                /* determine the limiting factor for the number of bytes to be appended to     */
                /* the ctx->xfer_buffer                                                        */
                /* this is either the maximum frame size or the number of bytes which are left */
                if ((actual_length - done_length) > MaxDataInSize)
                {
                    /* transfer the calculated number of bytes  */
                    next_length = MaxDataInSize;
                    /* first command , we add 1 because opcode is defined inside the APDU header */
                    if (((IsoWrapping == DesfireIsoWrapping.Reader) || (IsoWrapping == DesfireIsoWrapping.Card)) &&
                          (done_length == 0))
                    {
                        next_length++;
                    }
                }
                else
                {
                    /* transfer all the bytes left  */
                    next_length = actual_length - done_length;
                }

                /* Only the first frame has its actual size, others has to be shortened by one */
                /* to put the ADDITIONAL_FRAME header                                          */
                if ((next_length == MaxDataInSize) && (done_length > 0))
                    next_length--;

                logger.debug("\t{0}", BinConvert.ToHex(buffer, done_length, next_length));

                if ((done_length + next_length) >= actual_length)
                {
                    if (SessionIsEV2OrGreater() && (((DesfireCommMode)CommMode == DesfireCommMode.Plain) || ((DesfireCommMode)CommMode == DesfireCommMode.Plain2)))
                    {
                        /* This will be the last frame */
                        commandFlags = DesfireCommandFlag.INCREMENT_COUNTER | DesfireCommandFlag.WANTS_OPERATION_OK;
                    }
                    else
                    {
                        /* This will be the last frame */
                        commandFlags = DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK;
                    }
                }
                else
                {
                    /* Chaining expected */
                    commandFlags = DesfireCommandFlag.WANTS_ADDITIONAL_FRAME;
                }

                /* Now put these bytes into the ctx->xfer_buffer */
                if (done_length == 0)
                {
                    /* First frame */
                    Array.ConstrainedCopy(buffer, 0, xfer_buffer, INF + 0, next_length);
                    xfer_length = next_length;
                }
                else
                {
                    /* Next frame */
                    xfer_buffer[INF + 0] = (byte)DesfireCommand.ADDITIONAL_FRAME;
                    Array.ConstrainedCopy(buffer, done_length, xfer_buffer, INF + 1, next_length);
                    xfer_length = 1 + next_length;
                }

                status = Command(1, commandFlags);

                if (status != Success)
                    break;

                done_length += next_length;

            } while (done_length < actual_length);


            /* because ( eNumOfbytesExtracted = eNbytesToWrite ) is the only way for     */
            /* leaving the loop correctly an interrupted write operation is detected via */
            /* a status code different from DesfireCommand.OPERATION_OK                              */

            return status;
        }


    }
}
