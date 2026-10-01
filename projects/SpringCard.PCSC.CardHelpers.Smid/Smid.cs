/*
 * SpringCard Smid Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard Smid library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using SpringCard.LibCs;
using System.Reflection;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Smid
    {
        private ICardTransmitter transmitter;
        SmidCryptoContext SessionCryptoContext;

        private int xfer_length;
        private byte[] xfer_buffer;

        const int MAX_BUFFER_EXCHANGE = 256;

        /**
         * @brief Library information
         **/
        public static class Library
        {
            /**
             * @brief Read Library information
             **/
            public static readonly AppModuleInfo ModuleInfo = new AppModuleInfo(Assembly.GetExecutingAssembly());
        }


        /**
		 * @brief Instanciate a Smid card object over a card channel. The channel must already be connected.
		 */
        public Smid(ICardTransmitter transmitter)
        {
            this.transmitter = transmitter;
            xfer_buffer = new byte[MAX_BUFFER_EXCHANGE];
        }

        public ICardTransmitter GetTransmitter()
        {
            return transmitter;
        }

        private static long CardError(byte error)
        {
            return (long)(0x8000|error);
        }

        private static long CardError(SmidCardError error)
        {
            return (long)(0x8000 | (long)error);
        }

        public static bool IsCardError(long status)
        {
            if ( (status &0x8000) == 0x8000 )
                return true;
            return false;
        }

        public static SmidCardError GetCardError(long status)
        {
            if (IsCardError(status))
            {
                long error = (long)(status &0x7FFF);
                if ((error >= 0) && (error < 256))
                    if (Enum.IsDefined(typeof(SmidCardError), (byte)error))
                        return (SmidCardError)((byte)error);
            }
            else if (status != Success)
            {
                Logger.Warning("{0} is not a valid card error code", status);
            }
            return SmidCardError.Unknown;
        }

        private static long LibraryError(SmidLibraryError error)
        {
            return (long)( ~0x8000 & (long)error);
        }

        public static bool IsLibraryError(long status)
        {
            if ((status & 0x8000) == 0x0000)
                return true;
            return false;
        }

        public static SmidLibraryError GetLibraryError(long status)
        {
            if (IsLibraryError(status))
            {
                long error = (long)(status);
                if ((error >= 0) && (error < 256))
                {
                    if (Enum.IsDefined(typeof(SmidLibraryError), (byte)error))
                        return (SmidLibraryError)((byte)error);
                }
            }
            else if (status != Success)
            {
                Logger.Warning("{0} is not a valid library error code", status);
            }
            return SmidLibraryError.Unknown;
        }

        public static string GetErrorMessage(long status)
        {
            if (status == Success)
            {
                return ("Function was executed without failure");
            }
            else if (IsCardError(status))
            {
                SmidCardError error = GetCardError(status);

                switch (error)
                {
                    case SmidCardError.NormalProcessing:
                        return ("Smid : ok");
                    case SmidCardError.AuthenticateError:
                        return ("Smid : insufficient NV-memory to complete command");
                    case SmidCardError.LengthError:
                        return ("Smid : command code not supported");
                    case SmidCardError.IntegrityError:
                        return ("Smid : CRC or MAC does not match, or invalid padding bytes");
                    case SmidCardError.TimeoutError:
                        return ("Smid : invalid key number specified");
                    case SmidCardError.PermissionDenied:
                        return ("Smid : length of command string invalid");
                    default:
                        return error.ToString();
                }

            }
            else if (IsLibraryError(status))
            {
                SmidLibraryError error = GetLibraryError(status);

                switch (error)
                {
                    case SmidLibraryError.InvalidParameter:
                        return ("Smid : invalid parameters in function call");
                    case SmidLibraryError.OutOfMemory:
                        return ("Smid : not enough memory");
                    case SmidLibraryError.OperationUnsupported:
                        return ("Smid : operation not supported");
                    case SmidLibraryError.KeyDiversification:
                        return ("Smid : key diversification");
                    case SmidLibraryError.EmptyAnswer:
                        return ("Smid : empty aswer");
                    case SmidLibraryError.LibraryCall:
                        return ("Smid : library call");
                    default:
                        return error.ToString();
                }
            }
            return string.Format("Unknown error code {0} ({0:X08})", status);
        }
        public bool InSecureSession()
        {
            return (SessionCryptoContext != null);
        }

        protected void BeginSecureSession(SmidCryptoContext CryptoContext)
        {
            this.SessionCryptoContext = CryptoContext;
        }

        protected void EndSecureSession()
        {
            if (SessionCryptoContext != null)
                logger.debug("End secure session");
            SessionCryptoContext = null;
        }

    }
}
