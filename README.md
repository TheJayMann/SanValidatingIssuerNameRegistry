# SanValidatingIssuerNameRegistry

SanValidatingIssuerNameRegistry is an `IssuerNameRegistry` implementation for Windows Identity Foundation which validates the signing certificate against the issuer name using the subject alternative name of the certificate.

![GitHub](https://img.shields.io/github/license/TheJayMann/SanValidatingIssuerNameRegistry?style=plastic)
[![Nuget](https://img.shields.io/nuget/v/SanValidatingIssuerNameRegistry?style=plastic)](https://www.nuget.org/packages/SanValidatingIssuerNameRegistry/)
[![GitHub issues](https://img.shields.io/github/issues/TheJayMann/SanValidatingIssuerNameRegistry?style=plastic)](https://github.com/TheJayMann/SanValidatingIssuerNameRegistry/issues)

## Getting Started

### Installation

SanValidatingIssuerNameRegistry can be installed on an ASP.NET project utilizing Windows Identity Foundation by installing the nuget package.  Alternatively, it can be installed on an already deployed ASP.NET application using Windows Identity Framework by copying the appropriate assembly file to the `bin` folder.

### Configuration

The simplest way to configure SanValidatingIssuerNameRegistry is by adding it as the the `issuerNameRegistry` in the web.config file.

```xml
<system.identityModel>
  <identityConfiguration>
    <issuerNameRegistry type="SanValidatingIssuerNameRegistry.SanValidatingIssuerNameRegistry, SanValidatingIssuerNameRegistry">
      <add issuerUri="http://sts.corp.example/adfs/services/trust" allowUriValidation="false" allowIpValidation="false" />
    </issuerNameRegistry>
  </identityConfiguration>
</system.identityModel>
```

In addition to validating the issuer name against a DNS subject alternative name, `allowUriValidation` can be set to true to allow validating against a URI subject alternative name, and `allowIpValidation` to true to allow validating against an IP address subject alternative name. These values are false by default due to potential security concerns, and should only be enabled if necessary.

### Certificate Validation

SanValidatingIssuerNameRegistry will only validate that subject alternative name of the certificate matches the issuer name as a URI.  It does not validate the certificate itself.  Given the simplicity of creating a fraudulent certificate with a matching subject alternative name, it is highly recommended to validate the certificate itself.  This can be done using the `certificateValidation` element, setting the `certificateValidationMode` attribute to either `ChainTrust`, `PeerTrust`, or `ChainOrPeerTrust`.  If none of these validation modes will work with the given signing certificate, a custom `X509CertificateValidator` should be used.
