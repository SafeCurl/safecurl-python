# coding: utf8

from __future__ import unicode_literals
from __future__ import print_function

from numbers import Number
from socket import gethostbyname_ex

import re
import netaddr
import pycurl
import StringIO

# Python 2.7/3 urlparse
try:
    # Python 2.7
    from urlparse import urlparse
    from urllib import quote
except:
    # Python 3
    from urllib.parse import urlparse
    from urllib.parse import quote

class InvalidOptionException(Exception): pass
class InvalidURLException(Exception): pass
class InvalidDomainException(Exception): pass
class InvalidIPException(Exception): pass
class InvalidPortException(Exception): pass
class InvalidSchemeException(Exception): pass

class Empty(object):
    pass

# TODO: Remove this ugly hack!
def _mutable(obj):
    newobj = Empty()
    for i in dir(obj):
        if not i.startswith("_"):
            setattr(newobj, i, getattr(obj, i))
    return newobj

def _check_allowed_keys(val):
    if val not in ["ip", "port", "domain", "scheme"]:
        raise InvalidOptionException("Provided type 'type' must be 'ip', 'port', 'domain' or 'scheme'")

def _check_allowed_lists(val):
    if val not in ["whitelist", "blacklist"]:
        raise InvalidOptionException("Provided list 'list' must be 'whitelist' or 'blacklist'")

class Options(object):
    def __init__(self):
        self._follow_location = False
        self._follow_location_limit = 0
        self._send_credentials = False
        self._pin_dns = False
        self._lists = {
                "whitelist": {
                    "ip": [],
                    "port": ["80", "443", "8080"],
                    "domain": [],
                    "scheme": ["http", "https"]},
                "blacklist": {
                    "ip": ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                        "172.16.0.0/12", "192.0.0.0/29", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
                        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"],
                    "port": [],
                    "domain": [],
                    "scheme": []}
        }

    def getFollowLocation(self):
        return self._follow_location

    def enableFollowLocation(self):
        self._follow_location = True
        return self

    def disableFollowLocation(self):
        self._follow_location = False
        return self

    def getFollowLocationLimit(self):
        return self._follow_location_limit

    def setFollowLocationLimit(self, limit):
        if not isinstance(limit, Number) or limit < 0:
            raise InvalidOptionException("Provided limit 'limit' must be an integer >= 0")

        self._follow_location_limit = limit
        return self

    def getSendCredentials(self):
        return self._send_credentials

    def enableSendCredentials(self):
        self._send_credentials = True
        return self

    def disableSendCredentials(self):
        self._send_credentials = False
        return self

    def getPinDns(self):
        return self._pin_dns

    def enablePinDns(self):
        self._pin_dns = True
        return self

    def disablePinDns(self):
        self._pin_dns = False
        return self

    def isInList(self, lst, type_, value):
        _check_allowed_lists(lst)
        _check_allowed_keys(type_)

        dst = self._lists[lst][type_]

        if len(dst) == 0:
            if lst == "whitelist":
                return True
            else:
                return False

        # For domains, a regex match is needed
        if type_ == "domain":
            for domain in dst:
                if re.match("(?i)^%s" % domain, value) is not None:
                    return True
            return False
        else:
            return value in dst

    def getList(self, lst, type_=None):
        _check_allowed_lists(lst)

        dst = self._lists[lst]

        if type_ != None:
            _check_allowed_keys(type_)
            return dst[type_]

        return dst

    def setList(self, lst, values, type_=None):
        _check_allowed_lists(lst)

        if type_ is not None:
            if not isinstance(values, list):
                raise InvalidOptionException("Provided values must be a list")

            _check_allowed_keys(type_)
            self._lists[lst][type_] = values
            return self

        if not isinstance(values, dict):
            raise InvalidOptionException("Provided values must be a dictionary")

        for k, v in values.iteritems():
            _check_allowed_keys(k)
            self._lists[lst][k] = v

        return self

    def clearList(self, lst):
        _check_allowed_lists(lst)
        self._lists[lst] = {"ip": [], "domain": [], "port": [], "scheme": []}

    def addToList(self, lst, type_, values):
        _check_allowed_lists(lst)
        _check_allowed_keys(type_)

        if len(values) == 0:
            raise InvalidOptionException("Provided values cannot be empty")

        if not isinstance(values, list):
            values = list(values)

        dst = self._lists[lst][type_]

        for v in values:
            if not v in dst:
                dst.append(v)
        return self

    def removeFromList(self, lst, type_, values):
        _check_allowed_lists(lst)
        _check_allowed_keys(type_)

        if len(values) == 0:
            raise InvalidOptionException("Provided values cannot be empty")

        if not isinstance(values, list):
            values = [values]

        dst = self._lists[lst][type_]
        self._lists[lst][type_] = [x for x in dst if x not in values]
        return self

class Url(object):
    @staticmethod
    def validateUrl(url, options):
        if len(url) == 0:
            raise InvalidURLException("Provided URL 'url' cannot be empty")

        # Split URL into parts first
        parts = _mutable(urlparse(url))

        if parts is None:
            raise InvalidURLException("Error parsing URL 'url'")

        if parts.hostname is None:
            raise InvalidURLException("Provided URL 'url' doesn't contain a hostname")

        # First, validate the scheme
        if len(parts.scheme) != 0:
            parts.scheme = Url.validateScheme(parts.scheme, options)
        else:
            # Default to http
            parts.scheme = "http"

        # Validate the port
        if not parts.port is None:
            parts.port = Url.validatePort(parts.port, options)

        # Reolve host to ip(s)
        parts.ips = Url.resolveHostname(parts.hostname)

        # Validate the host
        parts.hostname = Url.validateHostname(parts.hostname, parts.ips, options)

        if options.getPinDns():
            # Since we"re pinning DNS, we replace the host in the URL
            # with an IP, then get cURL to send the Host header
            parts.hostname = parts.ips[0]

        # Rebuild the URL
        cleanUrl = Url.buildUrl(parts)

        return {"originalUrl": str(url), "cleanUrl": str(cleanUrl), "parts": parts}

    @staticmethod
    def validateScheme(scheme, options):
        # Whitelist always takes precedence over a blacklist
        if not options.isInList("whitelist", "scheme", scheme):
            raise InvalidSchemeException("Provided scheme 'scheme' doesn't match whitelisted values: %s" % (", ".join(options.getList("whitelist", "scheme"))))

        if options.isInList("blacklist", "scheme", scheme):
            raise InvalidSchemeException("Provided scheme 'scheme' matches a blacklisted value")

        # Existing value is fine
        return scheme

    @staticmethod
    def validatePort(port, options):
        if not options.isInList("whitelist", "port", port):
            raise InvalidPortException("Provided port 'port' doesn't match whitelisted values: %s" % (", ".join(options.getList("whitelist", "port"))))

        if options.isInList("blacklist", "port", port):
            raise InvalidPortException("Provided port 'port' matches a blacklisted value")

        # Existing value is fine
        return port

    @staticmethod
    def validateHostname(hostname, ips, options):
        # Check the host against the domain lists
        if not options.isInList("whitelist", "domain", hostname):
            raise InvalidDomainException("Provided hostname 'hostname' doesn't match whitelisted values: %s" % (", ".join(options.getList("whitelist", "domain"))))

        if options.isInList("blacklist", "domain", hostname):
            raise InvalidDomainException("Provided hostname 'hostname' matches a blacklisted value")

        whitelistedIps = options.getList("whitelist", "ip")

        if len(whitelistedIps) != 0:
            has_match = any(Url.cidrMatch(ip, wlip) for ip in ips for wlip in whitelistedIps)
            if not has_match:
                raise InvalidIPException("Provided hostname 'hostname' resolves to '%s', which doesn't match whitelisted values: %s" % (", ".join(ips), \
                        ", ".join(whitelistedIps)))

        blacklistedIps = options.getList("blacklist", "ip")

        if len(blacklistedIps) != 0:
            has_match = any(Url.cidrMatch(ip, blip) for ip in ips for blip in blacklistedIps)
            if has_match:
                raise InvalidIPException("Provided hostname 'hostname' resolves to '%s', which matches a blacklisted value: %s" % (", ".join(ips), blacklistedIp))

        return hostname

    @staticmethod
    def buildUrl(parts):
        url = []

        if len(parts.scheme) != 0:
            url.append("%s://" % parts.scheme)

        if not parts.username is None:
            url.append(quote(parts.username))

        if not parts.password is None:
            url.append(":%s" % quote(parts.password))

        # If we have a user or pass, make sure to add an "@"
        if (not parts.username is None) or (not parts.password is None):
            url.append("@")

        if not parts.hostname is None:
            url.append(parts.hostname)

        if not parts.port is None:
            url.append(":%d" % int(parts.port))

        if len(parts.path) != 0:
            url.append("/%s" % quote(parts.path[1:]))

        # The query string is difficult to encode properly
        # We need to ensure no special characters can be
        # used to mangle the URL, but URL encoding all of it
        # prevents the query string from being parsed properly
        if len(parts.query) != 0:
            query = quote(parts.query)
            # Replace encoded &, =, ;, [ and ] to originals
            query = query.replace("%26", "&").replace("%3D", "=").replace("%3B", ";").replace("%5B", "[").replace("%5D", "]")
            url.append("?")
            url.append(query)

        if len(parts.fragment) != 0:
            url.append("#%s" % quote(parts.fragment))

        return "".join(url)

    @staticmethod
    def resolveHostname(hostname):
        try:
            ips = gethostbyname_ex(hostname)
            return ips[2]
        except:
            raise InvalidDomainException("Provided hostname 'hostname' doesn't resolve to an IP address")

    @staticmethod
    def cidrMatch(ip, cidr):
        return netaddr.IPAddress(ip) in netaddr.IPNetwork(cidr)

class SafeCurl(object):
    def __init__(self, handle=None, options=None):
        self.setCurlHandle(handle)

        if options == None:
            options = Options()

        self.setOptions(options)

        # To start with, disable FOLLOWLOCATION since we'll handle it
        self._handle.setopt(pycurl.FOLLOWLOCATION, False)

        # Force IPv4, since this class isn't yet compatible with IPv6
        self._handle.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V4)

    def getCurlHandle(self):
        return self._handle

    def setCurlHandle(self, handle):
        if handle is None:
            handle = pycurl.Curl()

        # TODO: Fix this hack!
        if repr(handle).find("pycurl.Curl") == -1:
            raise Exception("SafeCurl expects a valid cURL object!")

        self._handle = handle

    def getOptions(self):
        return self._options

    def setOptions(self, options):
        self._options = options

    def execute(self, url):
        # Backup the existing URL
        originalUrl = url

        # Execute, catch redirects and validate the URL
        redirected = False
        redirectCount = 0
        redirectLimit = self._options.getFollowLocationLimit()
        followLocation = self._options.getFollowLocation()

        while True:
            # Validate the URL
            url = Url.validateUrl(url, self._options)

            # Are there credentials, but we don"t want to send them?
            if not self._options.getSendCredentials() and \
                (url["parts"].username is not None or url["parts"].password is not None):
                raise InvalidURLException("Credentials passed in but 'sendCredentials' is set to false")

            if self._options.getPinDns():
                # Send a Host header
                self._handle.setopt(pycurl.HTTPHEADER, ["Host: %s" % url["parts"].hostname])
                # The "fake" URL
                self._handle.setopt(pycurl.URL, url["cleanUrl"])

                # We also have to disable SSL cert verification, which is not great
                # Might be possible to manually check the certificate ourselves?
                self._handle.setopt(pycurl.SSL_VERIFYPEER, False)
            else:
                self._handle.setopt(pycurl.URL, url["cleanUrl"])

            # Execute the cURL request
            response = StringIO.StringIO()
            self._handle.setopt(pycurl.WRITEFUNCTION, response.write)
            self._handle.perform()

            # Check for an HTTP redirect
            if followLocation:
                statuscode = self._handle.getinfo(pycurl.HTTP_CODE)

                if statuscode in [301, 302, 303, 307, 308]:
                    redirectCount += 1
                    if redirectLimit == 0 or redirectCount < redirectLimit:
                        # Redirect received, so rinse and repeat
                        url = self._handle.getinfo(pycurl.REDIRECT_URL)
                        redirected = True
                    else:
                        raise Exception("Redirect limit 'redirectLimit' hit")
                else:
                    redirected = False

            if not redirected:
                break

        return response.getvalue()
