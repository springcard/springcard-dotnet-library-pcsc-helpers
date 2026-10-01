using SpringCard.LibCs;
using System;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        /**
         * @brief Encrypts and pads the data in the transfer buffer.
         *
         * This method applies padding to the data in the transfer buffer starting from the specified offset,
         * then encrypts the padded data using the current cryptographic context.
         *
         * @param offset The starting offset in the transfer buffer.
         * @param mode The padding mode to use (default is DesfireCryptoContext.EPaddMode.Default).
         * \exception Exception Thrown if the offset is greater than the transfer buffer length.
         */
        void Xfer_Padd_CipherSend(int offset, DesfireCryptoContext.EPaddMode mode = DesfireCryptoContext.EPaddMode.Default)
        {
            if (offset >= xfer_length)
                throw new Exception("XferCipherSend called with an offset > xfer_length");
            SessionCryptoContext.Padd(ref xfer_buffer, ref xfer_length, offset, mode);
            SessionCryptoContext.CipherSend(ref xfer_buffer, ref xfer_length, offset);
        }

        /**
         * @brief Appends a CMAC to the transfer buffer.
         *
         * This method computes and appends a CMAC (Cipher-based Message Authentication Code) to the
         * transfer buffer for secure communication.
         */
        void Xfer_AppendCmac()
        {
            SessionCryptoContext.AppendCmacSend(ref xfer_buffer, ref xfer_length, 0, xfer_length);
        }

        /**
         * @brief Decrypts and removes padding from the data in the transfer buffer.
         *
         * This method decrypts the data in the transfer buffer starting from the specified offset,
         * then removes the padding from the decrypted data.
         *
         * @param offset The starting offset in the transfer buffer.
         * @param mode The padding mode to use (default is DesfireCryptoContext.EPaddMode.Default).
         * @return True if the operation succeeds, false otherwise.
         * \warning Logs a warning if the ciphered buffer is shorter than expected or not made of full blocks.
         */
        bool Xfer_CipherRecv_Unpadd(int offset, DesfireCryptoContext.EPaddMode mode = DesfireCryptoContext.EPaddMode.Default)
        {
            if (offset >= xfer_length)
            {
                logger.warning("Ciphered buffer is shorter than expected");
                return false;
            }
            int paddedLen = xfer_length - offset;
            if ((paddedLen % SessionCryptoContext.BlockSize) != 0)
            {
                logger.warning("Ciphered buffer is not made of full blocks");
                return false;
            }
            byte[] buffer = BinUtils.Copy(xfer_buffer, offset, paddedLen);
            SessionCryptoContext.CipherRecv(ref buffer);
            if (!SessionCryptoContext.Unpadd(ref buffer, mode))
            {
                logger.debug("Wrong padding");
                return false;
            }
            int unpaddedLen = buffer.Length;

            Array.ConstrainedCopy(buffer, 0, xfer_buffer, offset, unpaddedLen);
            xfer_length = xfer_length - paddedLen + unpaddedLen;
            return true;
        }
    }
}
