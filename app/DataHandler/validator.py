import os
import ipaddress
import re
import validators
import tldextract
from hashid import HashID
import hashlib
import socket
from pydantic import BaseModel, field_validator, Field


def get_service_name(port, protocol='tcp'):
    try:
        return socket.getservbyport(int(port), protocol)
    except OSError:
        return None

class DataValidator:
    """
    A robust class for validating IPs, domains, hashes, and URLs.
    Utilizes specialized libraries for improved accuracy.
    """

    def __init__(self):
        self.hashid = HashID()  # Hash detection engine
        self.extractor = tldextract.TLDExtract(cache_dir="app/DataHandler/public", fallback_to_snapshot=True)
        # Regex patterns for additional validation
        self.ssdeep_regex = re.compile(r"(?i)^[0-9]+:[a-zA-Z0-9/+]{1,}:[a-zA-Z0-9/+]{1,}$")
        self.empty_ssdeep = "3::"

    ### === IP VALIDATION === ###

    def validate_ip(self, ip: str) -> str | None:
        """
        Validates an IP address and determines its type.

        :param ip: The IP address to validate.
        :return: IP type (e.g., 'Public IPv4', 'Private IPv6') or None if invalid.
        """
        try:
            ip_obj = ipaddress.ip_address(ip[0])
            ip_type = "IPv4" if ip_obj.version == 4 else "IPv6"

            if ip_obj.is_private:
                return f"Private {ip_type}"
            elif ip_obj.is_global:
                return f"Public {ip_type}"
            elif ip_obj.is_reserved:
                return f"Reserved {ip_type}"
            elif ip_obj.is_unspecified:
                return f"Unspecified {ip_type}"
            elif ip_obj.is_loopback:
                return f"Loopback {ip_type}"
            elif ip_obj.is_link_local:
                return f"Link-local {ip_type}"
            elif ip_obj.is_multicast:
                return f"Multicast {ip_type}"
        except ValueError:
            return None  # Invalid IP

    ### === DOMAIN VALIDATION === ###

    def validate_domain(self, domain: str) -> str | None:
        """
        Validates a domain.

        :param domain: The domain to validate.
        :return: 'DOMAIN' if valid, otherwise None.
        """
        # os.environ["HTTP_PROXY"] = os.getenv("PROXY")
        # os.environ["HTTPS_PROXY"] = os.getenv("PROXY")
        extracted = self.extractor(domain)
        if extracted.domain and extracted.suffix:
            return "DOMAIN"
        return None

    ### === HASH VALIDATION === ###

    def validate_hash(self, hash_str: str) -> str | None:
        """
        Validates a hash and identifies its type.

        :param h: The hash value.
        :return: The hash type (e.g., 'MD5', 'SHA-256', 'SSDEEP') or None if invalid.
        """
        hash_str = hash_str.strip().lower()
        if len(hash_str) == 32:
            return 'MD5'
        elif len(hash_str) == 40:
            return 'SHA-1'
        elif len(hash_str) == 64:
            return 'SHA-256'  # or verify further with actual checks
        elif self.ssdeep_regex.match(hash_str):
            return 'SSDEEP'
        if hash_str == self.empty_ssdeep:
            return None
        return None


    ### === URL VALIDATION === ###

    def validate_url(self, url: str) -> str | None:
        """
        Validates a URL.

        :param url: The URL to validate.
        :return: 'URL' if valid, otherwise None.
        """
        return "URL" if validators.url(url) else None

    ### === STRUCTURED VALIDATION WITH Pydantic (v2) === ###

    class IPModel(BaseModel):
        ip: str = Field(..., description="IP address")

        @field_validator("ip")
        @classmethod
        def check_ip(cls, v):
            try:
                ipaddress.ip_address(v)  # Check if valid IP
                return v
            except ValueError:
                raise ValueError("Invalid IP address")

    class DomainModel(BaseModel):
        domain: str = Field(..., description="Domain name")

        @field_validator("domain")
        @classmethod
        def check_domain(cls, v):
            extracted = tldextract.extract(v)
            if not extracted.domain or not extracted.suffix:
                raise ValueError("Invalid domain")
            return v

    class HashModel(BaseModel):
        hash: str = Field(..., description="Hash value")

        @field_validator("hash")
        @classmethod
        def check_hash(cls, v):
            hashid = HashID()
            hash_info = hashid.identify_hash(v)
            if not hash_info:
                raise ValueError("Invalid hash")
            return v

    class URLModel(BaseModel):
        url: str = Field(..., description="URL")

        @field_validator("url")
        @classmethod
        def check_url(cls, v):
            if not validators.url(v):
                raise ValueError("Invalid URL")
            return v
