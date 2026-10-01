/**
 *
 * @addtogroup Desfire
 *
 * @brief Desfire library (.NET only, no native depedency)
 *
 * @copyright
 *   Copyright (c) 2018 SpringCard - www.springcard.com
 *   All right reserved
 *
 * @author
 *   Johann.D et al. / SpringCard
 *
 */
/*
 * Read LICENSE.txt for license details and restrictions.
 */
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Xml.Schema;
using SpringCard.LibCs;
using SpringCard.PCSC;
using SpringCard.PCSC.CardHelpers;

namespace SpringCard.PCSC.CardHelpers
{ 
    public partial class Desfire : DesfireEV0, DesfireEV1, DesfireEV2, DesfireEV3, MifareDuoX
    {
        /**
		 * @brief Instanciate a Desfire EV0 card object over a card channel. The channel must already be connected.
		 */
        public static DesfireEV0 CreateDesfireEV0(ICardTransmitter transmitter)
        {
            return new Desfire(transmitter) as DesfireEV0;
        }

        /**
		 * @brief Instanciate a Desfire EV0 card object over a card channel. The channel must already be connected.
		 */
        public static DesfireEV0 CreateDesfireEV0(ICardTransmitter transmitter, byte isoWrapping)
        {
            return new Desfire(transmitter, isoWrapping) as DesfireEV0;
        }

        /**
		 * @brief Instanciate a Desfire EV0 card object over a card channel. The channel must already be connected.
		 */
        public static DesfireEV0 CreateDesfireEV0(ICardTransmitter transmitter, DesfireIsoWrapping isoWrapping)
        {
            return new Desfire(transmitter, isoWrapping) as DesfireEV0;
        }

        /**
		 * @brief Instanciate a Desfire EV1 card object over a card channel. The channel must already be connected.
		 */
        public static DesfireEV1 CreateDesfireEV1(ICardTransmitter transmitter)
        {
            return new Desfire(transmitter) as DesfireEV1;
        }

        /**
		 * @brief Instanciate a Desfire EV1 card object over a card channel. The channel must already be connected.
		 */
        public static DesfireEV1 CreateDesfireEV1(ICardTransmitter transmitter, byte isoWrapping)
        {
            return new Desfire(transmitter, isoWrapping) as DesfireEV1;
        }

        /**
		 * @brief Instanciate a Desfire EV1 card object over a card channel. The channel must already be connected.
		 */
        public static DesfireEV1 CreateDesfireEV1(ICardTransmitter transmitter, DesfireIsoWrapping isoWrapping)
        {
            return new Desfire(transmitter, isoWrapping) as DesfireEV1;
        }

        /**
		 * @brief Instanciate a Desfire EV2 card object over a card channel. The channel must already be connected.
		 */
        public static DesfireEV2 CreateDesfireEV2(ICardTransmitter transmitter)
        {
            return new Desfire(transmitter) as DesfireEV2;
        }

        /**
		 * @brief Instanciate a Desfire EV2 card object over a card channel. The channel must already be connected.
		 */
        public static DesfireEV2 CreateDesfireEV2(ICardTransmitter transmitter, byte isoWrapping)
        {
            return new Desfire(transmitter, isoWrapping) as DesfireEV2;
        }

        /**
		 * @brief Instanciate a Desfire EV2 card object over a card channel. The channel must already be connected.
		 */
        public static DesfireEV2 CreateDesfireEV2(ICardTransmitter transmitter, DesfireIsoWrapping isoWrapping)
        {
            return new Desfire(transmitter, isoWrapping) as DesfireEV2;
        }

        /**
		 * @brief Instanciate a Desfire EV3 card object over a card channel. The channel must already be connected.
		 */
        public static DesfireEV3 CreateDesfireEV3(ICardTransmitter transmitter)
        {
            return new Desfire(transmitter) as DesfireEV3;
        }

        /**
		 * @brief Instanciate a Desfire EV3 card object over a card channel. The channel must already be connected.
		 */
        public static DesfireEV3 CreateDesfireEV3(ICardTransmitter transmitter, byte isoWrapping)
        {
            return new Desfire(transmitter, isoWrapping) as DesfireEV3;
        }

        /**
		 * @brief Instanciate a Desfire EV3 card object over a card channel. The channel must already be connected.
		 */
        public static DesfireEV3 CreateDesfireEV3(ICardTransmitter transmitter, DesfireIsoWrapping isoWrapping)
        {
            return new Desfire(transmitter, isoWrapping) as DesfireEV3;
        }

        /**
		 * @brief Instanciate a Mifare DuoX card object over a card channel. The channel must already be connected.
		 */
        public static MifareDuoX CreateMifareDuoX(ICardTransmitter transmitter)
        {
            return new Desfire(transmitter) as MifareDuoX;
        }

        /**
		 * @brief Instanciate a Mifare DuoX card object over a card channel. The channel must already be connected.
		 */
        public static MifareDuoX CreateMifareDuoX(ICardTransmitter transmitter, byte isoWrapping)
        {
            return new Desfire(transmitter, isoWrapping) as MifareDuoX;
        }

        /**
		 * @brief Instanciate a Mifare DuoX card object over a card channel. The channel must already be connected.
		 */
        public static MifareDuoX CreateMifareDuoX(ICardTransmitter transmitter, DesfireIsoWrapping isoWrapping)
        {
            return new Desfire(transmitter, isoWrapping) as MifareDuoX;
        }
    }
}
