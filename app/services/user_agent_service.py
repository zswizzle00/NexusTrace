import re
from typing import Dict, Any

class UserAgentParser:
    """A comprehensive user agent parser that extracts detailed browser, OS, and device information."""

    # Browser patterns - order matters (more specific first)
    BROWSER_PATTERNS = [
        # Mobile browsers first
        ('Samsung Internet', r'SamsungBrowser/(\d+(?:\.\d+)*)'),
        ('UC Browser', r'UCBrowser/(\d+(?:\.\d+)*)'),
        ('Opera Mini', r'Opera Mini/(\d+(?:\.\d+)*)'),
        ('Opera Mobile', r'OPiOS/(\d+(?:\.\d+)*)'),
        ('Opera Touch', r'OPT/(\d+(?:\.\d+)*)'),
        ('Firefox Focus', r'Focus/(\d+(?:\.\d+)*)'),
        ('Firefox iOS', r'FxiOS/(\d+(?:\.\d+)*)'),
        ('Chrome iOS', r'CriOS/(\d+(?:\.\d+)*)'),
        ('Edge iOS', r'EdgiOS/(\d+(?:\.\d+)*)'),
        ('DuckDuckGo', r'DuckDuckGo/(\d+(?:\.\d+)*)'),
        ('Brave', r'Brave/(\d+(?:\.\d+)*)'),
        ('Vivaldi', r'Vivaldi/(\d+(?:\.\d+)*)'),
        ('Yandex', r'YaBrowser/(\d+(?:\.\d+)*)'),
        ('Whale', r'Whale/(\d+(?:\.\d+)*)'),
        ('QQ Browser', r'QQBrowser/(\d+(?:\.\d+)*)'),
        ('Sogou', r'SogouMobileBrowser/(\d+(?:\.\d+)*)'),
        ('Puffin', r'Puffin/(\d+(?:\.\d+)*)'),
        ('Maxthon', r'Maxthon/(\d+(?:\.\d+)*)'),
        ('Sleipnir', r'Sleipnir/(\d+(?:\.\d+)*)'),
        ('Waterfox', r'Waterfox/(\d+(?:\.\d+)*)'),
        ('Pale Moon', r'PaleMoon/(\d+(?:\.\d+)*)'),
        ('SeaMonkey', r'SeaMonkey/(\d+(?:\.\d+)*)'),
        ('Basilisk', r'Basilisk/(\d+(?:\.\d+)*)'),
        ('Tor Browser', r'Tor Browser'),
        # Desktop browsers
        ('Edge', r'Edg(?:e|A|iOS)?/(\d+(?:\.\d+)*)'),
        ('Opera', r'(?:OPR|Opera)[/ ](\d+(?:\.\d+)*)'),
        ('Chrome', r'Chrome/(\d+(?:\.\d+)*)'),
        ('Firefox', r'Firefox/(\d+(?:\.\d+)*)'),
        ('Safari', r'Version/(\d+(?:\.\d+)*).*Safari'),
        ('Internet Explorer', r'(?:MSIE |rv:)(\d+(?:\.\d+)*)'),
        ('Chromium', r'Chromium/(\d+(?:\.\d+)*)'),
        ('Konqueror', r'Konqueror/(\d+(?:\.\d+)*)'),
        ('Epiphany', r'Epiphany/(\d+(?:\.\d+)*)'),
        ('Midori', r'Midori/(\d+(?:\.\d+)*)'),
        ('Links', r'Links \((\d+(?:\.\d+)*)'),
        ('Lynx', r'Lynx/(\d+(?:\.\d+)*)'),
        ('curl', r'curl/(\d+(?:\.\d+)*)'),
        ('wget', r'Wget/(\d+(?:\.\d+)*)'),
        ('Python Requests', r'python-requests/(\d+(?:\.\d+)*)'),
        ('Go-http-client', r'Go-http-client/(\d+(?:\.\d+)*)'),
    ]

    # OS patterns - order matters (specific distros/versions before generic)
    OS_PATTERNS = [
        # Windows versions
        ('Windows 11', r'Windows NT 10\.0.*(?:Win64|WOW64)'),  # Win11 uses NT 10.0 but usually 64-bit
        ('Windows 10', r'Windows NT 10\.0'),
        ('Windows 8.1', r'Windows NT 6\.3'),
        ('Windows 8', r'Windows NT 6\.2'),
        ('Windows 7', r'Windows NT 6\.1'),
        ('Windows Vista', r'Windows NT 6\.0'),
        ('Windows XP', r'Windows NT 5\.[12]'),
        ('Windows 2000', r'Windows NT 5\.0'),
        ('Windows Phone', r'Windows Phone(?: OS)? (\d+(?:\.\d+)*)'),
        ('Windows', r'Windows'),
        # macOS versions
        ('macOS Sequoia', r'Mac OS X 15[._](\d+(?:[._]\d+)*)'),
        ('macOS Sonoma', r'Mac OS X 14[._](\d+(?:[._]\d+)*)'),
        ('macOS Ventura', r'Mac OS X 13[._](\d+(?:[._]\d+)*)'),
        ('macOS Monterey', r'Mac OS X 12[._](\d+(?:[._]\d+)*)'),
        ('macOS Big Sur', r'Mac OS X 11[._](\d+(?:[._]\d+)*)'),
        ('macOS Catalina', r'Mac OS X 10[._]15'),
        ('macOS Mojave', r'Mac OS X 10[._]14'),
        ('macOS High Sierra', r'Mac OS X 10[._]13'),
        ('macOS Sierra', r'Mac OS X 10[._]12'),
        ('OS X El Capitan', r'Mac OS X 10[._]11'),
        ('OS X Yosemite', r'Mac OS X 10[._]10'),
        ('Mac OS X', r'Mac OS X (\d+[._]\d+(?:[._]\d+)?)'),
        # iOS versions
        ('iOS', r'(?:iPhone|iPad|iPod).*OS (\d+[._]\d+(?:[._]\d+)?)'),
        # Android versions
        ('Android 14', r'Android 14'),
        ('Android 13', r'Android 13'),
        ('Android 12', r'Android 12'),
        ('Android 11', r'Android 11'),
        ('Android 10', r'Android 10'),
        ('Android 9', r'Android 9'),
        ('Android 8', r'Android 8'),
        ('Android', r'Android (\d+(?:\.\d+)*)'),
        # Chrome OS
        ('Chrome OS', r'CrOS'),
        # Linux distributions (specific before generic)
        ('Ubuntu', r'Ubuntu(?:/(\d+\.\d+))?'),
        ('Fedora', r'Fedora(?:/(\d+))?'),
        ('Debian', r'Debian'),
        ('Arch Linux', r'Arch'),
        ('Linux Mint', r'(?:Linux Mint|Mint)'),
        ('CentOS', r'CentOS'),
        ('Red Hat', r'(?:Red Hat|RHEL)'),
        ('openSUSE', r'(?:openSUSE|SUSE)'),
        ('Gentoo', r'Gentoo'),
        ('Manjaro', r'Manjaro'),
        ('Kali Linux', r'Kali'),
        ('Pop!_OS', r'Pop'),
        ('elementary OS', r'elementary'),
        ('Zorin OS', r'Zorin'),
        ('Slackware', r'Slackware'),
        ('Mageia', r'Mageia'),
        ('PCLinuxOS', r'PCLinuxOS'),
        ('FreeBSD', r'FreeBSD'),
        ('OpenBSD', r'OpenBSD'),
        ('NetBSD', r'NetBSD'),
        ('Linux', r'Linux|X11'),
        # Other
        ('BlackBerry', r'BlackBerry|BB10'),
        ('PlayStation', r'PlayStation'),
        ('Xbox', r'Xbox'),
        ('Nintendo', r'Nintendo'),
        ('Roku', r'Roku'),
        ('Tizen', r'Tizen'),
        ('WebOS', r'webOS|Web0S'),
        ('KaiOS', r'KAIOS'),
        ('HarmonyOS', r'HarmonyOS'),
    ]

    # Mobile device patterns
    MOBILE_DEVICE_PATTERNS = [
        # Apple devices
        ('iPhone 15', r'iPhone16,[12]', 'Apple', 'Mobile'),
        ('iPhone 14', r'iPhone15,[23]', 'Apple', 'Mobile'),
        ('iPhone 14 Pro', r'iPhone15,[45]', 'Apple', 'Mobile'),
        ('iPhone 13', r'iPhone14,[45]', 'Apple', 'Mobile'),
        ('iPhone 13 Pro', r'iPhone14,[23]', 'Apple', 'Mobile'),
        ('iPhone 12', r'iPhone13,[12]', 'Apple', 'Mobile'),
        ('iPhone 12 Pro', r'iPhone13,[34]', 'Apple', 'Mobile'),
        ('iPhone 11', r'iPhone12,1', 'Apple', 'Mobile'),
        ('iPhone SE', r'iPhone12,8|iPhone14,6', 'Apple', 'Mobile'),
        ('iPhone', r'iPhone', 'Apple', 'Mobile'),
        ('iPad Pro', r'iPad[68],', 'Apple', 'Tablet'),
        ('iPad Air', r'iPad5,[34]|iPad11', 'Apple', 'Tablet'),
        ('iPad Mini', r'iPad[45],|iPad14,[12]', 'Apple', 'Tablet'),
        ('iPad', r'iPad', 'Apple', 'Tablet'),
        ('iPod', r'iPod', 'Apple', 'Mobile'),
        # Samsung devices
        ('Galaxy S24', r'SM-S92[1-8]', 'Samsung', 'Mobile'),
        ('Galaxy S23', r'SM-S91[1-8]', 'Samsung', 'Mobile'),
        ('Galaxy S22', r'SM-S90[1-8]', 'Samsung', 'Mobile'),
        ('Galaxy S21', r'SM-G99[0-8]', 'Samsung', 'Mobile'),
        ('Galaxy S20', r'SM-G98[0-8]', 'Samsung', 'Mobile'),
        ('Galaxy Z Fold', r'SM-F9', 'Samsung', 'Mobile'),
        ('Galaxy Z Flip', r'SM-F7', 'Samsung', 'Mobile'),
        ('Galaxy A', r'SM-A\d', 'Samsung', 'Mobile'),
        ('Galaxy Note', r'SM-N9', 'Samsung', 'Mobile'),
        ('Galaxy Tab', r'SM-T|SM-X', 'Samsung', 'Tablet'),
        ('Galaxy', r'Galaxy|SM-G', 'Samsung', 'Mobile'),
        # Google devices
        ('Pixel 8', r'Pixel 8', 'Google', 'Mobile'),
        ('Pixel 7', r'Pixel 7', 'Google', 'Mobile'),
        ('Pixel 6', r'Pixel 6', 'Google', 'Mobile'),
        ('Pixel 5', r'Pixel 5', 'Google', 'Mobile'),
        ('Pixel 4', r'Pixel 4', 'Google', 'Mobile'),
        ('Pixel', r'Pixel', 'Google', 'Mobile'),
        ('Nexus', r'Nexus', 'Google', 'Mobile'),
        # OnePlus
        ('OnePlus 12', r'OnePlus.*12|CPH25', 'OnePlus', 'Mobile'),
        ('OnePlus 11', r'OnePlus.*11|CPH24', 'OnePlus', 'Mobile'),
        ('OnePlus 10', r'OnePlus.*10|NE2', 'OnePlus', 'Mobile'),
        ('OnePlus 9', r'OnePlus.*9|LE2', 'OnePlus', 'Mobile'),
        ('OnePlus', r'OnePlus|ONEPLUS', 'OnePlus', 'Mobile'),
        # Xiaomi
        ('Xiaomi 14', r'2311[A-Z]', 'Xiaomi', 'Mobile'),
        ('Xiaomi 13', r'2210[A-Z]|2304[A-Z]', 'Xiaomi', 'Mobile'),
        ('Redmi Note', r'Redmi Note', 'Xiaomi', 'Mobile'),
        ('Redmi', r'Redmi', 'Xiaomi', 'Mobile'),
        ('Mi ', r'Mi \d|MI \d', 'Xiaomi', 'Mobile'),
        ('POCO', r'POCO', 'Xiaomi', 'Mobile'),
        ('Xiaomi', r'Xiaomi', 'Xiaomi', 'Mobile'),
        # Huawei
        ('Huawei P', r'(?:HUAWEI )?P\d0', 'Huawei', 'Mobile'),
        ('Huawei Mate', r'(?:HUAWEI )?Mate', 'Huawei', 'Mobile'),
        ('Huawei Nova', r'(?:HUAWEI )?Nova', 'Huawei', 'Mobile'),
        ('Honor', r'Honor', 'Honor', 'Mobile'),
        ('Huawei', r'Huawei|HUAWEI', 'Huawei', 'Mobile'),
        # Other brands
        ('Sony Xperia', r'Xperia|SO-\d', 'Sony', 'Mobile'),
        ('LG', r'LG-|LM-', 'LG', 'Mobile'),
        ('Motorola', r'moto|Motorola|XT\d', 'Motorola', 'Mobile'),
        ('Nokia', r'Nokia', 'Nokia', 'Mobile'),
        ('HTC', r'HTC', 'HTC', 'Mobile'),
        ('ASUS', r'ASUS|ZenFone', 'ASUS', 'Mobile'),
        ('Oppo', r'OPPO|CPH', 'Oppo', 'Mobile'),
        ('Vivo', r'vivo|V\d{4}', 'Vivo', 'Mobile'),
        ('Realme', r'RMX|Realme', 'Realme', 'Mobile'),
        ('Nothing Phone', r'A063', 'Nothing', 'Mobile'),
        ('Kindle Fire', r'KF\w{2}|Kindle Fire', 'Amazon', 'Tablet'),
        ('Kindle', r'Kindle', 'Amazon', 'E-Reader'),
        ('PlayBook', r'PlayBook', 'BlackBerry', 'Tablet'),
        ('Surface', r'Surface', 'Microsoft', 'Tablet'),
    ]

    # Bot/crawler patterns
    BOT_PATTERNS = [
        ('Googlebot', r'Googlebot', 'Google'),
        ('Bingbot', r'bingbot', 'Microsoft'),
        ('Yahoo! Slurp', r'Slurp', 'Yahoo'),
        ('DuckDuckBot', r'DuckDuckBot', 'DuckDuckGo'),
        ('Baiduspider', r'Baiduspider', 'Baidu'),
        ('YandexBot', r'YandexBot', 'Yandex'),
        ('Sogou Spider', r'Sogou', 'Sogou'),
        ('Exabot', r'Exabot', 'Exalead'),
        ('facebot', r'facebookexternalhit|facebot', 'Facebook'),
        ('ia_archiver', r'ia_archiver', 'Alexa'),
        ('Twitterbot', r'Twitterbot', 'Twitter'),
        ('LinkedInBot', r'LinkedInBot', 'LinkedIn'),
        ('WhatsApp', r'WhatsApp', 'WhatsApp'),
        ('Slackbot', r'Slackbot', 'Slack'),
        ('TelegramBot', r'TelegramBot', 'Telegram'),
        ('Discordbot', r'Discordbot', 'Discord'),
        ('Applebot', r'Applebot', 'Apple'),
        ('PetalBot', r'PetalBot', 'Huawei'),
        ('SemrushBot', r'SemrushBot', 'Semrush'),
        ('AhrefsBot', r'AhrefsBot', 'Ahrefs'),
        ('MJ12bot', r'MJ12bot', 'Majestic'),
        ('DotBot', r'DotBot', 'Moz'),
        ('Screaming Frog', r'Screaming Frog', 'Screaming Frog'),
        ('Uptimebot', r'Uptimebot', 'Uptime'),
        ('Pingdom', r'Pingdom', 'Pingdom'),
        ('StatusCake', r'StatusCake', 'StatusCake'),
        ('GTmetrix', r'GTmetrix', 'GTmetrix'),
        ('PageSpeed', r'PageSpeed', 'Google'),
        ('HeadlessChrome', r'HeadlessChrome', 'Automated'),
        ('PhantomJS', r'PhantomJS', 'Automated'),
        ('Puppeteer', r'Puppeteer', 'Automated'),
        ('Playwright', r'Playwright', 'Automated'),
        ('Selenium', r'Selenium', 'Automated'),
        ('Bot', r'[Bb]ot|[Cc]rawler|[Ss]pider', 'Generic Bot'),
    ]

    # Architecture patterns
    ARCH_PATTERNS = [
        ('x86_64', r'x86_64|x64|Win64|WOW64|amd64'),
        ('x86', r'i[3-6]86|x86'),
        ('ARM64', r'arm64|aarch64'),
        ('ARM', r'arm(?:v[67])?'),
    ]

    @staticmethod
    def parse(user_agent: str) -> Dict[str, Any]:
        """
        Parse a user agent string and return comprehensive structured information.
        """
        if not user_agent or not user_agent.strip():
            return UserAgentParser._empty_result()

        ua = user_agent.strip()
        result = {
            'raw': ua,
            'browser': {'name': 'Other', 'version': 'N/A'},
            'os': {'name': 'Other', 'version': 'N/A'},
            'device': {'type': 'Desktop', 'brand': 'Generic', 'model': 'Computer'},
            'is_mobile': False,
            'is_tablet': False,
            'is_desktop': True,
            'is_bot': False,
            'bot_info': None,
            'architecture': 'N/A',
            'engine': {'name': 'N/A', 'version': 'N/A'},
        }

        # Check for bots first
        for bot_name, pattern, operator in UserAgentParser.BOT_PATTERNS:
            if re.search(pattern, ua, re.IGNORECASE):
                result['is_bot'] = True
                result['is_desktop'] = False
                result['bot_info'] = {'name': bot_name, 'operator': operator}
                result['device'] = {'type': 'Bot', 'brand': operator, 'model': bot_name}
                result['browser'] = {'name': bot_name, 'version': 'N/A'}
                break

        # Parse rendering engine
        engine_patterns = [
            ('Blink', r'Chrome/(\d+)'),
            ('Gecko', r'Gecko/(\d+)'),
            ('WebKit', r'AppleWebKit/(\d+(?:\.\d+)*)'),
            ('Trident', r'Trident/(\d+(?:\.\d+)*)'),
            ('EdgeHTML', r'Edge/(\d+)'),
            ('Presto', r'Presto/(\d+(?:\.\d+)*)'),
        ]
        for engine, pattern in engine_patterns:
            match = re.search(pattern, ua)
            if match:
                result['engine'] = {'name': engine, 'version': match.group(1)}
                break

        # Parse browser
        if not result['is_bot']:
            for browser, pattern in UserAgentParser.BROWSER_PATTERNS:
                match = re.search(pattern, ua)
                if match:
                    result['browser']['name'] = browser
                    if match.groups():
                        result['browser']['version'] = match.group(1)
                    break

        # Parse OS
        for os_name, pattern in UserAgentParser.OS_PATTERNS:
            match = re.search(pattern, ua, re.IGNORECASE)
            if match:
                result['os']['name'] = os_name
                if match.groups() and match.group(1):
                    version = match.group(1).replace('_', '.')
                    result['os']['version'] = version
                break

        # Parse architecture
        for arch, pattern in UserAgentParser.ARCH_PATTERNS:
            if re.search(pattern, ua, re.IGNORECASE):
                result['architecture'] = arch
                break

        # Parse device (mobile/tablet)
        if not result['is_bot']:
            for model, pattern, brand, device_type in UserAgentParser.MOBILE_DEVICE_PATTERNS:
                if re.search(pattern, ua, re.IGNORECASE):
                    result['device'] = {'type': device_type, 'brand': brand, 'model': model}
                    result['is_mobile'] = device_type == 'Mobile'
                    result['is_tablet'] = device_type == 'Tablet'
                    result['is_desktop'] = False
                    break

        # If still desktop, determine type based on OS
        if result['is_desktop'] and not result['is_bot']:
            os_name = result['os']['name']
            if 'Windows' in os_name:
                result['device'] = {'type': 'Desktop', 'brand': 'PC', 'model': 'Windows PC'}
            elif 'Mac' in os_name or 'OS X' in os_name:
                result['device'] = {'type': 'Desktop', 'brand': 'Apple', 'model': 'Mac'}
            elif os_name == 'Chrome OS':
                result['device'] = {'type': 'Desktop', 'brand': 'Google', 'model': 'Chromebook'}
            elif os_name in ['Linux', 'Ubuntu', 'Fedora', 'Debian', 'Arch Linux', 'Linux Mint',
                            'CentOS', 'Red Hat', 'openSUSE', 'Gentoo', 'Manjaro', 'Kali Linux',
                            'Pop!_OS', 'elementary OS', 'Zorin OS', 'Slackware', 'Mageia', 'PCLinuxOS']:
                result['device'] = {'type': 'Desktop', 'brand': 'PC', 'model': f'{os_name} PC'}
            elif os_name in ['FreeBSD', 'OpenBSD', 'NetBSD']:
                result['device'] = {'type': 'Desktop', 'brand': 'PC', 'model': f'{os_name} Workstation'}

        # Additional mobile detection fallback
        if not result['is_mobile'] and not result['is_tablet'] and not result['is_bot']:
            mobile_keywords = ['Mobile', 'Android', 'webOS', 'BlackBerry', 'Opera Mini', 'IEMobile']
            tablet_keywords = ['Tablet', 'iPad']
            if any(kw in ua for kw in mobile_keywords) and 'iPad' not in ua:
                result['is_mobile'] = True
                result['is_desktop'] = False
                if result['device']['type'] == 'Desktop':
                    result['device']['type'] = 'Mobile'
            elif any(kw in ua for kw in tablet_keywords):
                result['is_tablet'] = True
                result['is_desktop'] = False
                if result['device']['type'] == 'Desktop':
                    result['device']['type'] = 'Tablet'

        return result

    @staticmethod
    def _empty_result() -> Dict[str, Any]:
        """Return result for empty/invalid user agent."""
        return {
            'raw': '',
            'browser': {'name': 'N/A', 'version': 'N/A'},
            'os': {'name': 'N/A', 'version': 'N/A'},
            'device': {'type': 'N/A', 'brand': 'N/A', 'model': 'N/A'},
            'is_mobile': False,
            'is_tablet': False,
            'is_desktop': False,
            'is_bot': False,
            'bot_info': None,
            'architecture': 'N/A',
            'engine': {'name': 'N/A', 'version': 'N/A'},
        }


def parse_user_agent(user_agent: str) -> Dict[str, Any]:
    """
    Parse a user agent string and return structured information.
    """
    return UserAgentParser.parse(user_agent)
