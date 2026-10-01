/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        /**
         * @brief Commits all pending transactions on the DESFire chip.
         *
         * @return A status code indicating the result of the operation.
         */
        public long CommitTransaction()
        {
            logger.trace("CommitTransaction");

            /* Create the info block containing the command code. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.COMMIT_TRANSACTION;
            xfer_length = 1;

            if (SessionIsEV2OrGreater())
            {
                /* Communicate the info block to the card and check the operation's return status. */
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* Communicate the info block to the card and check the operation's return status. */
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }

        /**
         * @brief Aborts all pending transactions on the DESFire chip.
         *
         * @return A status code indicating the result of the operation.
         */
        public long AbortTransaction()
        {
            logger.trace("AbortTransaction");

            /* Create the info block containing the command code. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.ABORT_TRANSACTION;
            xfer_length = 1;

            if (SessionIsEV2OrGreater())
            {
                /* Communicate the info block to the card and check the operation's return status. */
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* Communicate the info block to the card and check the operation's return status. */
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }

    }
}
