using SpringCard.LibCs;
using SpringCard.PCSC.CardHelpers;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace SpringCard.PCSC.CardEmulation
{
    public abstract partial class CardEmulDesfire
    {
        protected DesfireApplication RootApplication { get; private set; } = null;

        protected byte RootKeySettings = ROOT_KEY_ALLOW_CHANGE_SETTINGS | ROOT_KEY_FREE_CREATE_DELETE | ROOT_KEY_FREE_DIRECTORY | ROOT_KEY_ALLOW_CHANGE_KEY;

        public bool RootKeyChangeable
        {
            get
            {
                return (RootKeySettings & ROOT_KEY_ALLOW_CHANGE_KEY) != 0;
            }
        }

        public bool RootFreeDirectory
        {
            get
            {
                return (RootKeySettings & ROOT_KEY_FREE_DIRECTORY) != 0;
            }
        }

        public bool RootFreeCreateDelete
        {
            get
            {
                return (RootKeySettings & ROOT_KEY_FREE_CREATE_DELETE) != 0;
            }
        }

        public bool RootSettingsChangeable
        {
            get
            {
                return (RootKeySettings & ROOT_KEY_ALLOW_CHANGE_SETTINGS) != 0;
            }
        }


    }
}
