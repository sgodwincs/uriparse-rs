use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::str;

const MAX_REGISTERED_SCHEME_LENGTH: usize = 36;
const NUMBER_OF_SCHEMES: usize = 283;
#[cfg_attr(rustfmt, rustfmt_skip)]
const SCHEME_CHAR_MAP: [u8; 256] = [
 // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 0
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 1
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, b'+',    0, b'-', b'.',    0, // 2
 b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',    0,    0,    0,    0,    0,    0, // 3
    0, b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', // 4
 b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z',    0,    0,    0,    0,    0, // 5
    0, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', // 6
 b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z',    0,    0,    0,    0,    0, // 7
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 8
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 9
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // A
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // B
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // C
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // D
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // E
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // F
];

macro_rules! schemes {
    (
        $(
            ($variant:ident, $name:expr, $status:expr);
        )+
    ) => {
        lazy_static! {
            static ref SCHEME_NAME_MAP: HashMap<&'static [u8], Scheme<'static>> = {
                let mut map = HashMap::with_capacity(NUMBER_OF_SCHEMES);

            $(
                map.insert($name.as_bytes(), Scheme::$variant);
            )+

                map
            };
        }

        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        #[non_exhaustive]
        pub enum Scheme<'scheme> {
        $(
            $variant,
        )+
            Unregistered(UnregisteredScheme<'scheme>)
        }

        impl<'scheme> Scheme<'scheme> {
            pub fn as_str(&self) -> &str {
                use self::Scheme::*;

                match self {
                $(
                    $variant => $name,
                )+
                    Unregistered(scheme) => scheme.as_str()
                }
            }

            pub fn into_owned(self) -> Scheme<'static> {
                use self::Scheme::*;

                match self {
                $(
                    $variant => $variant,
                )+
                    Unregistered(scheme) => Unregistered(scheme.into_owned())
                }
            }

            pub fn status(&self) -> SchemeStatus {
                use self::Scheme::*;

                match self {
                $(
                    $variant => $status,
                )+
                    Unregistered(_) => SchemeStatus::Unregistered
                }
            }
        }

        pub(crate) fn parse_scheme(value: &[u8]) -> Result<(Scheme, &[u8]), InvalidScheme> {
            fn unregistered_scheme<'bytes>(value: &'bytes [u8]) -> Scheme<'bytes> {
                let scheme = unsafe { str::from_utf8_unchecked(value) };
                Scheme::Unregistered(UnregisteredScheme(Cow::from(scheme)))
            }

            let mut bytes = value.iter();

            if !bytes.next().ok_or(InvalidScheme::CannotBeEmpty)?.is_ascii_alphabetic() {
                return Err(InvalidScheme::MustStartWithAlphabetic);
            }

            let mut end_index = 1;

            while let Some(&byte) = bytes.next() {
                match SCHEME_CHAR_MAP[byte as usize] {
                    0 if byte == b':' => break,
                    0 => return Err(InvalidScheme::InvalidCharacter),
                    _ => end_index += 1
                }
            }

            let (value, rest) = value.split_at(end_index);

            if end_index > MAX_REGISTERED_SCHEME_LENGTH {
                return Ok((unregistered_scheme(value), rest));
            }

            let mut lowercase_scheme = [0; MAX_REGISTERED_SCHEME_LENGTH];

            for (index, byte) in value.iter().enumerate() {
                lowercase_scheme[index] = byte.to_ascii_lowercase();
            }

            let scheme = SCHEME_NAME_MAP
                .get(&lowercase_scheme[..end_index])
                .cloned()
                .unwrap_or_else(|| unregistered_scheme(value));

            Ok((scheme, rest))
        }
    }
}

impl<'scheme> AsRef<[u8]> for Scheme<'scheme> {
    fn as_ref(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

impl<'scheme> AsRef<str> for Scheme<'scheme> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<'scheme> Display for Scheme<'scheme> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'scheme> PartialEq<str> for Scheme<'scheme> {
    fn eq(&self, other: &str) -> bool {
        self.as_str().eq_ignore_ascii_case(other)
    }
}

impl<'scheme> PartialEq<Scheme<'scheme>> for str {
    fn eq(&self, other: &Scheme<'scheme>) -> bool {
        self.eq_ignore_ascii_case(other.as_str())
    }
}

impl<'a, 'scheme> PartialEq<&'a str> for Scheme<'scheme> {
    fn eq(&self, other: &&'a str) -> bool {
        self.as_str().eq_ignore_ascii_case(other)
    }
}

impl<'a, 'scheme> PartialEq<Scheme<'scheme>> for &'a str {
    fn eq(&self, other: &Scheme<'scheme>) -> bool {
        self.eq_ignore_ascii_case(other.as_str())
    }
}

impl<'scheme> TryFrom<&'scheme [u8]> for Scheme<'scheme> {
    type Error = InvalidScheme;

    fn try_from(value: &'scheme [u8]) -> Result<Scheme<'scheme>, Self::Error> {
        let (scheme, rest) = parse_scheme(value)?;

        if rest.is_empty() {
            Ok(scheme)
        } else {
            Err(InvalidScheme::ExpectedEOF)
        }
    }
}

impl<'scheme> TryFrom<&'scheme str> for Scheme<'scheme> {
    type Error = InvalidScheme;

    fn try_from(value: &'scheme str) -> Result<Scheme<'scheme>, Self::Error> {
        Scheme::try_from(value.as_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct UnregisteredScheme<'scheme>(Cow<'scheme, str>);

impl<'scheme> UnregisteredScheme<'scheme> {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_owned(self) -> UnregisteredScheme<'static> {
        UnregisteredScheme(Cow::from(self.0.into_owned()))
    }
}

impl<'scheme> AsRef<[u8]> for UnregisteredScheme<'scheme> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<'scheme> AsRef<str> for UnregisteredScheme<'scheme> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'scheme> Display for UnregisteredScheme<'scheme> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'scheme> Eq for UnregisteredScheme<'scheme> {}

impl<'scheme> Hash for UnregisteredScheme<'scheme> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.0.to_lowercase().hash(state)
    }
}

impl<'scheme> PartialEq for UnregisteredScheme<'scheme> {
    fn eq(&self, other: &UnregisteredScheme) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl<'scheme> PartialEq<str> for UnregisteredScheme<'scheme> {
    fn eq(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }
}

impl<'scheme> PartialEq<UnregisteredScheme<'scheme>> for str {
    fn eq(&self, other: &UnregisteredScheme<'scheme>) -> bool {
        self.eq_ignore_ascii_case(&other.0)
    }
}

impl<'a, 'scheme> PartialEq<&'a str> for UnregisteredScheme<'scheme> {
    fn eq(&self, other: &&'a str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }
}

impl<'a, 'scheme> PartialEq<UnregisteredScheme<'scheme>> for &'a str {
    fn eq(&self, other: &UnregisteredScheme<'scheme>) -> bool {
        self.eq_ignore_ascii_case(&other.0)
    }
}

impl<'scheme> TryFrom<&'scheme [u8]> for UnregisteredScheme<'scheme> {
    type Error = InvalidUnregisteredScheme;

    fn try_from(value: &'scheme [u8]) -> Result<Self, Self::Error> {
        match Scheme::try_from(value) {
            Ok(Scheme::Unregistered(scheme)) => Ok(scheme),
            _ => Err(InvalidUnregisteredScheme),
        }
    }
}

impl<'scheme> TryFrom<&'scheme str> for UnregisteredScheme<'scheme> {
    type Error = InvalidUnregisteredScheme;

    fn try_from(value: &'scheme str) -> Result<Self, Self::Error> {
        UnregisteredScheme::try_from(value.as_bytes())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidScheme {
    CannotBeEmpty,
    ExpectedEOF,
    InvalidCharacter,
    MustStartWithAlphabetic,
}

impl Display for InvalidScheme {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

impl Error for InvalidScheme {
    fn description(&self) -> &str {
        use self::InvalidScheme::*;

        match self {
            CannotBeEmpty => "scheme cannot be empty",
            ExpectedEOF => "expected EOF",
            InvalidCharacter => "invalid scheme character",
            MustStartWithAlphabetic => "scheme must start with alphabetic character",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InvalidUnregisteredScheme;

impl Display for InvalidUnregisteredScheme {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

impl Error for InvalidUnregisteredScheme {
    fn description(&self) -> &str {
        "invalid unregistered URI scheme"
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SchemeStatus {
    Historical,
    Permanent,
    Provisional,
    Unregistered,
}

impl SchemeStatus {
    pub fn is_historical(&self) -> bool {
        match self {
            SchemeStatus::Historical => true,
            _ => false,
        }
    }

    pub fn is_permanent(&self) -> bool {
        match self {
            SchemeStatus::Permanent => true,
            _ => false,
        }
    }

    pub fn is_provisional(&self) -> bool {
        match self {
            SchemeStatus::Provisional => true,
            _ => false,
        }
    }

    pub fn is_unregistered(&self) -> bool {
        match self {
            SchemeStatus::Unregistered => true,
            _ => false,
        }
    }
}

schemes! {
    (AAA, "aaa", SchemeStatus::Permanent);
    (AAAS, "aaas", SchemeStatus::Permanent);
    (About, "about", SchemeStatus::Permanent);
    (ACAP, "acap", SchemeStatus::Permanent);
    (ACCT, "acat", SchemeStatus::Permanent);
    (ACR, "aaas", SchemeStatus::Provisional);
    (AdiumXtra, "adiumxtra", SchemeStatus::Provisional);
    (AFP, "afp", SchemeStatus::Provisional);
    (AFS, "afs", SchemeStatus::Provisional);
    (AIM, "aim", SchemeStatus::Provisional);
    (AppData, "appdata", SchemeStatus::Provisional);
    (APT, "apt", SchemeStatus::Provisional);
    (Attachment, "attachment", SchemeStatus::Provisional);
    (AW, "aw", SchemeStatus::Provisional);
    (Barion, "barion", SchemeStatus::Provisional);
    (BeShare, "beshare", SchemeStatus::Provisional);
    (Bitcoin, "bitcoin", SchemeStatus::Provisional);
    (Blob, "blob", SchemeStatus::Provisional);
    (Bolo, "bolo", SchemeStatus::Provisional);
    (BrowserExt, "browserext", SchemeStatus::Provisional);
    (CallTo, "callto", SchemeStatus::Provisional);
    (CAP, "cap", SchemeStatus::Permanent);
    (Chrome, "chrome", SchemeStatus::Provisional);
    (ChromeExtension, "chrome-extension", SchemeStatus::Provisional);
    (CID, "cid", SchemeStatus::Permanent);
    (CoAP, "coap", SchemeStatus::Permanent);
    (CoAPTCP, "coap+tcp", SchemeStatus::Permanent);
    (CoAPWS, "coap+ws", SchemeStatus::Permanent);
    (CoAPS, "coaps", SchemeStatus::Permanent);
    (CoAPSTCP, "coaps+tcp", SchemeStatus::Permanent);
    (CoAPSWS, "coaps+ws", SchemeStatus::Permanent);
    (ComEventBriteAttendee, "com-eventbrite-attendee", SchemeStatus::Provisional);
    (Content, "content", SchemeStatus::Provisional);
    (Conti, "conti", SchemeStatus::Provisional);
    (CRID, "crid", SchemeStatus::Permanent);
    (CVS, "cvs", SchemeStatus::Provisional);
    (Data, "data", SchemeStatus::Permanent);
    (DAV, "dav", SchemeStatus::Permanent);
    (Diaspora, "diaspora", SchemeStatus::Provisional);
    (DICT, "dict", SchemeStatus::Permanent);
    (DID, "did", SchemeStatus::Provisional);
    (DIS, "dis", SchemeStatus::Provisional);
    (DLNAPlayContainer, "dlna-playcontainer", SchemeStatus::Provisional);
    (DLNAPlaySingle, "dlna-playsingle", SchemeStatus::Provisional);
    (DNS, "dns", SchemeStatus::Permanent);
    (DNTP, "dntp", SchemeStatus::Provisional);
    (DTN, "dtn", SchemeStatus::Provisional);
    (DVB, "dvb", SchemeStatus::Provisional);
    (ED2K, "ed2k", SchemeStatus::Provisional);
    (ELSI, "elsi", SchemeStatus::Provisional);
    (Example, "example", SchemeStatus::Permanent);
    (FaceTime, "facetime", SchemeStatus::Provisional);
    (Fax, "fax", SchemeStatus::Historical);
    (Feed, "feed", SchemeStatus::Provisional);
    (FeedReady, "feedready", SchemeStatus::Provisional);
    (File, "file", SchemeStatus::Permanent);
    (FileSystem, "filesystem", SchemeStatus::Historical);
    (Finger, "finger", SchemeStatus::Provisional);
    (Fish, "fish", SchemeStatus::Provisional);
    (FTP, "ftp", SchemeStatus::Permanent);
    (Geo, "geo", SchemeStatus::Permanent);
    (GG, "gg", SchemeStatus::Provisional);
    (Git, "git", SchemeStatus::Provisional);
    (GizmoProject, "gizmoproject", SchemeStatus::Provisional);
    (Go, "go", SchemeStatus::Permanent);
    (Gopher, "gopher", SchemeStatus::Permanent);
    (Graph, "graph", SchemeStatus::Provisional);
    (GTalk, "gtalk", SchemeStatus::Provisional);
    (H323, "h323", SchemeStatus::Permanent);
    (HAM, "ham", SchemeStatus::Provisional);
    (HCP, "hcp", SchemeStatus::Provisional);
    (HTTP, "http", SchemeStatus::Permanent);
    (HTTPS, "https", SchemeStatus::Permanent);
    (HXXP, "hxxp", SchemeStatus::Provisional);
    (HXXPS, "hxxps", SchemeStatus::Provisional);
    (HydraZone, "hydrazone", SchemeStatus::Provisional);
    (IAX, "iax", SchemeStatus::Permanent);
    (ICAP, "icap", SchemeStatus::Permanent);
    (Icon, "icon", SchemeStatus::Provisional);
    (IM, "im", SchemeStatus::Permanent);
    (IMAP, "imap", SchemeStatus::Permanent);
    (Info, "info", SchemeStatus::Permanent);
    (IoTDisc, "iotdisc", SchemeStatus::Provisional);
    (IPN, "ipn", SchemeStatus::Provisional);
    (IPP, "ipp", SchemeStatus::Permanent);
    (IPPS, "ipps", SchemeStatus::Permanent);
    (IRC, "irc", SchemeStatus::Provisional);
    (IRC6, "irc6", SchemeStatus::Provisional);
    (IRCS, "ircs", SchemeStatus::Provisional);
    (IRIS, "iris", SchemeStatus::Permanent);
    (IRISBEEP, "iris.beep", SchemeStatus::Permanent);
    (IRISLWZ, "iris.lwz", SchemeStatus::Permanent);
    (IRISXPC, "iris.xpc", SchemeStatus::Permanent);
    (IRISXPCS, "iris.xpcs", SchemeStatus::Permanent);
    (IsoStore, "isostore", SchemeStatus::Provisional);
    (ITMS, "itms", SchemeStatus::Provisional);
    (Jabber, "jabber", SchemeStatus::Permanent);
    (JAR, "jar", SchemeStatus::Provisional);
    (JMS, "jms", SchemeStatus::Provisional);
    (KeyParc, "keyparc", SchemeStatus::Provisional);
    (LastFM, "lastfm", SchemeStatus::Provisional);
    (LDAP, "ldap", SchemeStatus::Permanent);
    (LDAPS, "ldaps", SchemeStatus::Provisional);
    (LVLT, "lvlt", SchemeStatus::Provisional);
    (Magnet, "magnet", SchemeStatus::Provisional);
    (MailServer, "mailserver", SchemeStatus::Historical);
    (MailTo, "mailto", SchemeStatus::Permanent);
    (Maps, "maps", SchemeStatus::Provisional);
    (Market, "market", SchemeStatus::Provisional);
    (Message, "message", SchemeStatus::Provisional);
    (MicrosoftWindowsCamera, "microsoft.windows.camera", SchemeStatus::Provisional);
    (MicrosoftWindowsCameraMultiPicker, "microsoft.windows.camera.multipicker", SchemeStatus::Provisional);
    (MicrosoftWindowsCameraPicker, "microsoft.windows.camera.picker", SchemeStatus::Provisional);
    (MID, "mid", SchemeStatus::Permanent);
    (MMS, "mms", SchemeStatus::Provisional);
    (Modem, "modem", SchemeStatus::Historical);
    (MongoDB, "mongodb", SchemeStatus::Provisional);
    (Moz, "moz", SchemeStatus::Provisional);
    (MSAccess, "ms-access", SchemeStatus::Provisional);
    (MSBrowserExtension, "ms-browser-extension", SchemeStatus::Provisional);
    (MSDriverTo, "ms-drive-to", SchemeStatus::Provisional);
    (MSEnrollment, "ms-enrollment", SchemeStatus::Provisional);
    (MSExcel, "ms-excel", SchemeStatus::Provisional);
    (MSGameBarServices, "ms-gamebaresrvices", SchemeStatus::Provisional);
    (MSGamingOverlay, "ms-gamingoverlay", SchemeStatus::Provisional);
    (MSGetOffice, "ms-getoffice", SchemeStatus::Provisional);
    (MSHelp, "ms-help", SchemeStatus::Provisional);
    (MSInfoPath, "ms-infopath", SchemeStatus::Provisional);
    (MSInputApp, "ms-inputapp", SchemeStatus::Provisional);
    (MSLockScreenComponentConfig, "ms-lockscreencomponent-config", SchemeStatus::Provisional);
    (MSMediaStreamID, "ms-media-stream-id", SchemeStatus::Provisional);
    (MSMixedRealityCapture, "ms-mixedrealitycapture", SchemeStatus::Provisional);
    (MSOfficeApp, "ms-officeapp", SchemeStatus::Provisional);
    (MSPeople, "ms-people", SchemeStatus::Provisional);
    (MSProject, "ms-project", SchemeStatus::Provisional);
    (MSPowerPoint, "ms-powerpoint", SchemeStatus::Provisional);
    (MSPublisher, "ms-publisher", SchemeStatus::Provisional);
    (MSRestoreTabCompanion, "ms-restoretabcompanion", SchemeStatus::Provisional);
    (MSSearchRepair, "ms-search-repair", SchemeStatus::Provisional);
    (MSSecondaryScreenController, "ms-secondary-screen-controller", SchemeStatus::Provisional);
    (MSSeocndaryScreenSetup, "ms-secondary-screen-setup", SchemeStatus::Provisional);
    (MSSettings, "ms-settings", SchemeStatus::Provisional);
    (MSSettingsAirplaneMode, "ms-settings-airplanemode", SchemeStatus::Provisional);
    (MSSettingsBluetooth, "ms-settings-bluetooth", SchemeStatus::Provisional);
    (MSSettingsCamera, "ms-settings-camera", SchemeStatus::Provisional);
    (MSSettingsCellular, "ms-settings-cellular", SchemeStatus::Provisional);
    (MSSettingsCloudStorage, "ms-settings-cloudstorage", SchemeStatus::Provisional);
    (MSSettingsConnectableDevices, "ms-settings-connectabledevices", SchemeStatus::Provisional);
    (MSSettingsDisplaysTopology, "ms-settings-displays-topology", SchemeStatus::Provisional);
    (MSSettingsEmailAndAccounts, "ms-settings-emailandaccounts", SchemeStatus::Provisional);
    (MSSettingsLanguage, "ms-settings-language", SchemeStatus::Provisional);
    (MSSettingsLocation, "ms-settings-location", SchemeStatus::Provisional);
    (MSSettingsLock, "ms-settings-lock", SchemeStatus::Provisional);
    (MSSettingsNFCTransactions, "ms-settings-nfctransactions", SchemeStatus::Provisional);
    (MSSettingsNotifications, "ms-settings-notifications", SchemeStatus::Provisional);
    (MSSettingsPower, "ms-settings-power", SchemeStatus::Provisional);
    (MSSettingsPrivacy, "ms-settings-privacy", SchemeStatus::Provisional);
    (MSSettingsProximity, "ms-settings-proximity", SchemeStatus::Provisional);
    (MSSettingsScreenRotation, "ms-settings-screenrotation", SchemeStatus::Provisional);
    (MSSettingsWiFi, "ms-settings-wifi", SchemeStatus::Provisional);
    (MSSettingsWorkplace, "ms-settings-workplace", SchemeStatus::Provisional);
    (MSSPD, "ms-spd", SchemeStatus::Provisional);
    (MSSTTOverlay, "ms-sttoverlay", SchemeStatus::Provisional);
    (MSTransitTo, "ms-transit-to", SchemeStatus::Provisional);
    (MSUserActivitySet, "ms-useractivityset", SchemeStatus::Provisional);
    (MSVirtualTouchPad, "ms-virtualtouchpad", SchemeStatus::Provisional);
    (MSVisio, "ms-visio", SchemeStatus::Provisional);
    (MSWalkTo, "ms-walk-to", SchemeStatus::Provisional);
    (MSWhiteboard, "ms-whiteboard", SchemeStatus::Provisional);
    (MSWhiteboardCMD, "ms-whiteboard-cmd", SchemeStatus::Provisional);
    (MSWord, "ms-word", SchemeStatus::Provisional);
    (MSNIM, "msnim", SchemeStatus::Provisional);
    (MSRP, "msrp", SchemeStatus::Permanent);
    (MSRPS, "msrps", SchemeStatus::Permanent);
    (MTQP, "mtqp", SchemeStatus::Permanent);
    (Mumble, "mumble", SchemeStatus::Provisional);
    (MUpdate, "mupdate", SchemeStatus::Permanent);
    (MVN, "mvn", SchemeStatus::Provisional);
    (News, "news", SchemeStatus::Permanent);
    (NFS, "nfs", SchemeStatus::Permanent);
    (NI, "ni", SchemeStatus::Permanent);
    (NIH, "nih", SchemeStatus::Permanent);
    (NNTP, "nntp", SchemeStatus::Permanent);
    (Notes, "notes", SchemeStatus::Provisional);
    (OCF, "ocf", SchemeStatus::Provisional);
    (OID, "oid", SchemeStatus::Provisional);
    (OneNote, "onenote", SchemeStatus::Provisional);
    (OneNoteCMD, "onenote-cmd", SchemeStatus::Provisional);
    (OpaqueLockToken, "opaquelocktoken", SchemeStatus::Permanent);
    (OpenPGP4FPR, "openpgp4fpr", SchemeStatus::Provisional);
    (Pack, "pack", SchemeStatus::Historical);
    (Palm, "palm", SchemeStatus::Provisional);
    (Paparazzi, "paparazzi", SchemeStatus::Provisional);
    (PKCKS11, "pkcs11", SchemeStatus::Permanent);
    (Platform, "platform", SchemeStatus::Provisional);
    (POP, "pop", SchemeStatus::Permanent);
    (Pres, "pres", SchemeStatus::Permanent);
    (Prospero, "prospero", SchemeStatus::Historical);
    (Proxy, "proxy", SchemeStatus::Provisional);
    (PWID, "pwid", SchemeStatus::Provisional);
    (PSYC, "psyc", SchemeStatus::Provisional);
    (QB, "qb", SchemeStatus::Provisional);
    (Query, "query", SchemeStatus::Provisional);
    (Redis, "redis", SchemeStatus::Provisional);
    (RedisS, "rediss", SchemeStatus::Provisional);
    (Reload, "reload", SchemeStatus::Permanent);
    (Res, "res", SchemeStatus::Provisional);
    (Resource, "resource", SchemeStatus::Provisional);
    (RMI, "rmi", SchemeStatus::Provisional);
    (RSync, "rsync", SchemeStatus::Provisional);
    (RTMFP, "rtmfp", SchemeStatus::Provisional);
    (RTMP, "rtmp", SchemeStatus::Provisional);
    (RTSP, "rtsp", SchemeStatus::Permanent);
    (RTSPS, "rtsps", SchemeStatus::Permanent);
    (RTSPU, "rtspu", SchemeStatus::Permanent);
    (SecondLife, "secondlife", SchemeStatus::Provisional);
    (Service, "service", SchemeStatus::Permanent);
    (Session, "session", SchemeStatus::Permanent);
    (SFTP, "sftp", SchemeStatus::Provisional);
    (SGN, "sgn", SchemeStatus::Provisional);
    (SHTTP, "shttp", SchemeStatus::Permanent);
    (Sieve, "sieve", SchemeStatus::Permanent);
    (SIP, "sip", SchemeStatus::Permanent);
    (SIPS, "sips", SchemeStatus::Permanent);
    (SimpleLedger, "simpleledger", SchemeStatus::Provisional);
    (Skype, "skype", SchemeStatus::Provisional);
    (SMB, "smb", SchemeStatus::Provisional);
    (SMS, "sms", SchemeStatus::Permanent);
    (SMTP, "smtp", SchemeStatus::Provisional);
    (SNews, "snews", SchemeStatus::Historical);
    (SNMP, "snmp", SchemeStatus::Permanent);
    (SOAPBEEP, "soap.beep", SchemeStatus::Permanent);
    (SOAPBEEPS, "soap.beeps", SchemeStatus::Permanent);
    (Soldat, "soldat", SchemeStatus::Provisional);
    (SPIFFE, "spiffe", SchemeStatus::Provisional);
    (Spotify, "spotify", SchemeStatus::Provisional);
    (SSH, "ssh", SchemeStatus::Provisional);
    (Steam, "steam", SchemeStatus::Provisional);
    (STUN, "stun", SchemeStatus::Permanent);
    (STUNS, "stuns", SchemeStatus::Permanent);
    (Submit, "submit", SchemeStatus::Provisional);
    (SVN, "svn", SchemeStatus::Provisional);
    (Tag, "tag", SchemeStatus::Permanent);
    (TeamSpeak, "teamspeak", SchemeStatus::Provisional);
    (Tel, "tag", SchemeStatus::Permanent);
    (TeliaEID, "teliaeid", SchemeStatus::Provisional);
    (Telnet, "telnet", SchemeStatus::Permanent);
    (TFTP, "tftp", SchemeStatus::Permanent);
    (Things, "things", SchemeStatus::Provisional);
    (ThisMessage, "thismessage", SchemeStatus::Permanent);
    (TIP, "tip", SchemeStatus::Permanent);
    (TN3270, "tn3270", SchemeStatus::Permanent);
    (Tool, "tool", SchemeStatus::Provisional);
    (TURN, "turn", SchemeStatus::Permanent);
    (TURNS, "turns", SchemeStatus::Permanent);
    (TV, "tv", SchemeStatus::Permanent);
    (UDP, "udp", SchemeStatus::Provisional);
    (Unreal, "unreal", SchemeStatus::Provisional);
    (URN, "urn", SchemeStatus::Permanent);
    (UT2004, "ut2004", SchemeStatus::Provisional);
    (VEvent, "v-event", SchemeStatus::Provisional);
    (VEMMI, "vemmi", SchemeStatus::Permanent);
    (Ventrilo, "ventrilo", SchemeStatus::Provisional);
    (Videotex, "videotex", SchemeStatus::Historical);
    (VNC, "vnc", SchemeStatus::Permanent);
    (ViewSource, "view-source", SchemeStatus::Provisional);
    (WAIS, "wais", SchemeStatus::Historical);
    (Webcal, "webcal", SchemeStatus::Provisional);
    (WPID, "wpid", SchemeStatus::Historical);
    (WS, "ws", SchemeStatus::Permanent);
    (WSS, "wss", SchemeStatus::Permanent);
    (WTAI, "wtai", SchemeStatus::Provisional);
    (WYCIWYG, "wyciwyg", SchemeStatus::Provisional);
    (XCON, "xcon", SchemeStatus::Permanent);
    (XCONUserID, "xcon-userid", SchemeStatus::Permanent);
    (Xfire, "xfire", SchemeStatus::Provisional);
    (XMLRPCBEEP, "xmlrpc.beep", SchemeStatus::Permanent);
    (XMLRPCBEEPS, "xmlrpc.beeps", SchemeStatus::Permanent);
    (XMPP, "xmpp", SchemeStatus::Permanent);
    (XRI, "xri", SchemeStatus::Provisional);
    (YMSGR, "ymsgr", SchemeStatus::Provisional);
    (Z3950, "z39.50", SchemeStatus::Historical);
    (Z3950R, "z39.50r", SchemeStatus::Permanent);
    (Z3950S, "z39.50s", SchemeStatus::Permanent);
}
