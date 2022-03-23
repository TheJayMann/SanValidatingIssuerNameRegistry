using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace SanValidatingIssuerNameRegistry {
    public class SanValidatingIssuerNameRegistry : IssuerNameRegistry {

        // A utility struct to store extra options per issuer name without relying on
        // ValueTuple type which is not easily available with older projects, and
        // removes any extra dependency needs for direct dll copy deployment.
        public struct ValidationOptions {
            public readonly bool AllowUriValidation;
            public readonly bool AllowIpValidation;

            public ValidationOptions(bool allowUriValidation, bool allowIpValidation) {
                AllowUriValidation = allowUriValidation;
                AllowIpValidation = allowIpValidation;
            }
        }

        readonly Dictionary<Uri, ValidationOptions> _IssuerUris = new();

        // In order to properly validate an issuer name against a security token, the issuer name itself must be provided
        // as the list of valid issuer names are not assigned to security tokens before hand.
        public override string GetIssuerName(SecurityToken securityToken) => throw new NotImplementedException();

        public override void LoadCustomConfiguration(XmlNodeList nodelist) {
            foreach (var element in nodelist.OfType<XmlElement>()) {
                if (element.LocalName != "add") throw new ConfigurationErrorsException("Only `<add>` elements are allowed.", element);
                var issuerUriAttribute = element.GetAttribute("issuerUri");
                if (string.IsNullOrEmpty(issuerUriAttribute)) throw new ConfigurationErrorsException("`<add>` element requires attribute `issuerUri`", element);
                if (!Uri.TryCreate(issuerUriAttribute, UriKind.Absolute, out var issuerUri)) throw new ConfigurationErrorsException("`issuerUri` must be a valid URI", element);
                var allowUriValidation = string.Equals(element.GetAttribute("allowUriValidation"), "true", StringComparison.InvariantCultureIgnoreCase);
                var allowIpValidation = string.Equals(element.GetAttribute("allowIpValidation"), "true", StringComparison.InvariantCultureIgnoreCase);
                _IssuerUris.Add(issuerUri, new (allowUriValidation, allowIpValidation));
            }
        }

        public override string GetIssuerName(SecurityToken securityToken, string requestedIssuerName) =>
            // Require an X509SecurityToken, as access to a Subject Alternative Name is required
            securityToken is X509SecurityToken { Certificate: var certificate }
            &&
            // Issuer name must be in the format of a uri, in order to compare it to the Subject Alternative Name
            Uri.TryCreate(requestedIssuerName, UriKind.Absolute, out Uri requestedIssuerUri)
            &&
            // Issuer must exist in the list of allowed issuers as configured
            _IssuerUris.TryGetValue(requestedIssuerUri, out var validationOptions)
            &&
            // Issuer name must match the Subject Alternative Name present in the signing certificate
            CertificateValidForIssuer(certificate, requestedIssuerUri, validationOptions)
            
            ? requestedIssuerName

            // Returning null will end up throwing an exception stating that the configuration is missing the
            // requested issuer, which is good enough information for this component.
            : null
        ;
        private bool TryReadLength(byte[] data, ref int currentIndex, out int length) {
            length = 0;
            if (currentIndex is < 0 || currentIndex >= data.Length) return false;
            var l = data[currentIndex++];
            // DER does not support 0x80 or 0xFF as length header
            if (l is 0x80 or 0xFF) return false;

            // length header less than 0x80 is the length itself
            if (l < 0x80) {
                length = l;
                return true;
            }
            
            // otherwise, the length header is 0x80 plus the length of the length, to allow lengths larger than 127 bytes
            // if at any time the length would represent a larger length than would be valid using 31 bit indexing,
            // return false to indicate the SAN is not possible to parse.
            l -= 0x80;
            if (l > sizeof(int)) return false;

            int endIndex = currentIndex + l;
            if (endIndex >= data.Length) return false;
            var lengthBuilder = 0L;
            while (currentIndex < endIndex) {
                lengthBuilder <<= 8;
                lengthBuilder |= data[currentIndex++];
                if (lengthBuilder > int.MaxValue) return false;
                if (lengthBuilder + endIndex > data.Length) return false;
            }
            length = (int)lengthBuilder;
            return true;
        }

        private bool CertificateValidForIssuer(X509Certificate2 certificate, Uri issuerUri, ValidationOptions validationOptions) {
            bool MatchesDomain(string authorizedDomainName) {
                // In order to validate the domain name, the host portion of the issuer name as a URI is compared to
                // the Subject Alternative Name, either being an exact match ignoring case, or, if the Subject
                // Alternative Name is a proper wildcard domain, being an exact match for all but the bottom most
                // domain name.
                var host = issuerUri.Host;
                if (authorizedDomainName.StartsWith("*.", StringComparison.Ordinal)) {
                    var hostSeparatorIndex = host.IndexOf('.');
                    if (hostSeparatorIndex == -1) return false;
                    return string.Equals(
                        host.Substring(hostSeparatorIndex + 1),
                        authorizedDomainName.Substring(2), 
                        StringComparison.InvariantCultureIgnoreCase
                    );
                }
                return host.Equals(authorizedDomainName, StringComparison.InvariantCultureIgnoreCase);
            }

            // If URI validation is enabled, then the issuer name is valid if the Subject Alternative Name
            // is a parent URI of the issuer name.
            bool MatchesUri(Uri authorizedUri) => authorizedUri.IsBaseOf(issuerUri);

            bool MatchesIpAddress(IPAddress authorizedIpAddress) =>
                // If IP Address validation is enabled, then it is validated similar to domain name validation,
                // validating a URI containing an IP address instead of a domain name.
                IPAddress.TryParse(issuerUri.Host, out var ipAddress) && ipAddress.Equals(authorizedIpAddress)
            ;

            // The different types of Subject Alternative Names are context specific ASN1 tags.  The ones of interest
            // are all simple types.  The DNS tag has an enum value of 2 and a type of (restricted) ASCII string, 
            // the URI tag has a value of 6 and also has a type of (restricted) ASCII string, and IP address tag
            // is a 4 or 16 byte array in the format expected by the IPAddress constructor.  Any other tag can be
            // skipped, and, if at any point the declared length does not fit within the raw data, or within the
            // limits imposed by this software, then the raw data cannot be properly parsed, and no further attempt
            // is made to parse the remaining data.
            const byte DnsType = 0x82;
            const byte UriType = 0x86;
            const byte IpType = 0x87;
            var domains = new List<string>();
            var uris = new List<Uri>();
            var ipAddresses = new List<IPAddress>();
            if (certificate.Extensions["Subject Alternative Name"] is { RawData.Length: > 0 } san && san.RawData[0] == 0x30) {
                for (var currentIndex = 2; currentIndex < san.RawData.Length;) {
                    var type = san.RawData[currentIndex++];
                    if (!TryReadLength(san.RawData, ref currentIndex, out var length)) break;
                    switch (type) {
                        case DnsType:
                            domains.Add(Encoding.ASCII.GetString(san.RawData, currentIndex, length));
                            break;
                        case UriType:
                            if (validationOptions.AllowUriValidation && Uri.TryCreate(Encoding.ASCII.GetString(san.RawData, currentIndex, length), UriKind.Absolute, out var uri)) uris.Add(uri);
                            break;
                        case IpType:
                            if (validationOptions.AllowIpValidation && length is 4 or 16) {
                                var ipAddr = new byte[length];
                                Array.Copy(san.RawData, currentIndex, ipAddr, 0, length);
                                ipAddresses.Add(new(ipAddr));
                            }
                            break;
                        default:
                            currentIndex += length;
                            break;
                    }
                    currentIndex += length;
                }
            }
            if (domains.Count is 0) {
                // If domains is empty, either there is no SAN, the SAN could not be parsed, or the SAN does not
                // contain any DNS.  In this case we will allow the OS to provide us the last DNS in the SAN or
                // the subject common name as DNS.
                domains.Add(certificate.GetNameInfo(X509NameType.DnsName, false));
            }
            return domains.Any(MatchesDomain) || uris.Any(MatchesUri) || ipAddresses.Any(MatchesIpAddress);
        }
    }
}
