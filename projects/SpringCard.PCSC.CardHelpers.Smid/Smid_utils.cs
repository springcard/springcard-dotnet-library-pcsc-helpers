/*
 * SpringCard Smid Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard Smid library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using SpringCard.LibCs;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Smid
    {
        bool logSecrets = false;
        bool logCrypto = false;
        ILogger logger = SCARD.SCardLogger;

        /**
         * @brief Set the logger to use
         * 
         * @param logger The logger to use
         */
        public void SetLogger(ILogger logger)
        {
            SetLogger(logger, false, false);
        }

        /**
         * @brief Set the logger to use and (conditionnaly) enable detailed logging of cryptographic operations
         * 
         * @param logger The logger to use
         * @param logCrypto Whether to log crypto operations
         */
        public void SetLogger(ILogger logger, bool logCrypto)
        {
            SetLogger(logger, logCrypto, false);
        }

        /**
         * @brief Set the logger to use and (conditionnaly) enable detailed logging of cryptographic operations, including secret material
         * 
         * @param logger The logger to use
         * @param logCrypto Whether to log crypto operations
         * @param logSecrets Whether to log key values
         * 
         * @warning This is a security risk, as it may reveal your secret or private keys in the log!!! You've been warned!!!
         */
        public void SetLogger(ILogger logger, bool logCrypto, bool logSecrets)
        {
            this.logCrypto = logCrypto;
            this.logSecrets = logSecrets;

            if (logger == null)
            {
                this.logger = new Logger(this);
            }
            else
            {
                if (logger is Logger)
                {
                    Logger _logger = new Logger(logger as Logger);
                    _logger.context = this.GetType().FullName;
                    this.logger = _logger;
                }
                else
                {
                    this.logger = new Logger(this);
                }
            }
        }

        IRandomGenerator randomGenerator = new DefaultRandomGenerator();

        /**
         * @brief Set the random generator to use
         * 
         * @param logger The random generator to use
         * 
         * @warning This is a security risk: using a weak random number generator weakens the security of the session keys!!! You've been warned!!!
         */
        public void SetRandomGenerator(IRandomGenerator RandomGenerator)
        {
            this.randomGenerator = RandomGenerator;
        }
        static bool Comparebytes(byte[] a1, uint a1_offset, byte[] a2, uint a2_offset, uint size)
        {
            for (int i = 0; i < size; ++i)
            {
                if (a1[a1_offset + i] != a2[a2_offset + i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
