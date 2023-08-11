%%%
title = "Automated Certificate Management Environment (ACME) Renewal Information (ARI) Extension"
abbrev = "ACME ARI"
ipr = "trust200902"
area = "Security Area (sec)"
workgroup = "ACME Working Group"
keyword = ["Internet-Draft"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-ietf-acme-ari-latest"
stream = "IETF"
status = "standard"

[[author]]
  name = "Aaron Gable"
  initials = "A."
  surname = "Gable"
  organization = "Internet Security Research Group"
    [author.address]
    email = "aaron@letsencrypt.org"
%%%

.# Abstract

This document specifies how an ACME server may provide suggestions to ACME clients as to when they should attempt to renew their certificates. This allows servers to mitigate load spikes, and ensures clients do not make false assumptions about appropriate certificate renewal periods.

.# Current Implementations

Draft note: this section will be removed by the editor before final publication.

Let's Encrypt's [Boulder](https://github.com/letsencrypt/boulder) software fully implements the server side of an earlier version of this draft, and that implementation is deployed in both the [Production](https://acme-v02.api.letsencrypt.org/directory) and [Staging](https://acme-staging-v02.api.letsencrypt.org/directory) environments. Google Trust Services has [done the same](https://security.googleblog.com/2023/05/google-trust-services-acme-api_0503894189.html). Client implementations include [Lego](https://github.com/go-acme/lego), [eggsampler](https://github.com/eggsampler/acme), [ACMEz](https://github.com/mholt/acmez), and [win-acme](https://github.com/win-acme/win-acme).

{mainmatter}

# Introduction

Most ACME [@!RFC8555] clients today choose when to attempt to renew a certificate in one of three ways. They may be configured to renew at a specific interval (e.g. via `cron`); they may parse the issued certificate to determine its expiration date and renew a specific amount of time before then; or they may parse the issued certificate and renew when some percentage of its validity period has passed. The first two techniques create significant barriers against the issuing Certification Authority (CA) changing certificate lifetimes. All three techniques lead to load clustering for the issuing CA.

Allowing issuing CAs to suggest a period in which clients should renew their certificates enables for dynamic time-based load balancing. This allows a CA to better respond to exceptional circumstances. For example, a CA could suggest that clients renew prior to a mass-revocation event to mitigate the impact of the revocation, or a CA could suggest that clients renew earlier than they normally would to reduce the size of an upcoming mass-renewal spike.

This document specifies a mechanism by which ACME servers may provide suggested renewal windows to ACME clients.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [@!RFC2119;@!RFC8174] when, and only when, they appear in all capitals, as shown here.

# Extensions to the Directory Object

An ACME server which wishes to provide renewal information **MUST** include a new field, `renewalInfo`, in its directory object.

Field         | URL in Value
--------------|-------------
renewalInfo   | Renewal info

~~~ json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "newNonce": "https://example.com/acme/new-nonce",
  "newAccount": "https://example.com/acme/new-account",
  "newOrder": "https://example.com/acme/new-order",
  "newAuthz": "https://example.com/acme/new-authz",
  "revokeCert": "https://example.com/acme/revoke-cert",
  "keyChange": "https://example.com/acme/key-change",
  "renewalInfo": "https://example.com/acme/renewal-info",
  "meta": {
    "termsOfService": "https://example.com/acme/terms/2021-10-05",
    "website": "https://www.example.com/",
    "caaIdentities": ["example.com"],
    "externalAccountRequired": false
  }
}
~~~

# Getting Renewal Information

## The "renewalInfo" Resource

The "`renewalInfo`" resource is a new resource type introduced to ACME protocol. This new resource both allows clients to query the server for suggestions on when they should renew certificates, and allows clients to inform the server when they have completed renewal (or otherwise replaced the certificate to their satisfaction).

To request the suggested renewal information for a certificate, the client sends a GET request to a path under the server's `renewalInfo` URL.

The path component is a unique identifier for the certificate in question. The unique identifer is constructed by concatenating the base64url-encoding [@!RFC4648, section 5] of the bytes of the `keyIdentifier` field of certificate's Authority Key Identifier (AKI) [@!RFC5280, section 4.2.1.1] extension, a literal period, and the base64url-encoding of the bytes of the certificate's Serial Number value. All trailing "`=`" MUST be stripped from both parts of the unique identifier.

Thus the full request url is constructed as follows, where the "`||`" operator indicates string concatenation and the renewalInfo url is taken from the Directory object:

~~~ text
url = renewalInfo || '/' || base64url(AKI) || '.' || base64url(Serial)
~~~

For example, to request renewal information for the end-entity certificate given in Appendix A, the client would make the request as follows:

1. The `keyIdentifier` field of the certificate's AKI extension has the bytes `38:CF:30:D1:51:A5:C7:54:AA:A5:49:35:A4:50:B1:94:E3:31:99:A5` as its ASN.1 Octet String value. The base64url encoding of those bytes is `OM8w0VGlx1SqpUk1pFCxlOMxmaU=`.
2. The certificate's Serial Number field has the bytes `3E:A3:45:68:65:44:1F:1C` as its ASN.1 Integer value. The base64url encoding of those bytes is `PqNFaGVEHxw=`.
3. Stripping the trailing padding characters and concatenating with the separator, the unique identifier is therefore `OM8w0VGlx1SqpUk1pFCxlOMxmaU.PqNFaGVEHxw`, and the client makes the request (split onto multiple lines for readability):

~~~ text
GET https://example.com/acme/renewal-info/
      OM8w0VGlx1SqpUk1pFCxlOMxmaU.PqNFaGVEHxw
~~~

## RenewalInfo Objects

The structure of an ACME `renewalInfo` resource is as follows:

`suggestedWindow` (object, required): A JSON object with two keys, "`start`" and "`end`", whose values are timestamps, encoded in the format specified in [@!RFC3339], which bound the window of time in which the CA recommends renewing the certificate.

`explanationURL` (string, optional): A URL pointing to a page which may explain why the suggested renewal window is what it is. For example, it may be a page explaining the CA's dynamic load-balancing strategy, or a page documenting which certificates are affected by a mass revocation event. Conforming clients **SHOULD** provide this URL to their operator, if present.

~~~ json
HTTP/1.1 200 OK
Content-Type: application/json
Retry-After: 21600

{
  "suggestedWindow": {
    "start": "2021-01-03T00:00:00Z",
    "end": "2021-01-07T00:00:00Z"
  },
  "explanationURL": "https://example.com/docs/ari"
}
~~~

The server **SHOULD** include a `Retry-After` header indicating the polling interval that the ACME server recommends. Conforming clients **SHOULD** query the `renewalInfo` URL again after the `Retry-After` period has passed, as the server may provide a different `suggestedWindow`.

Conforming clients **MUST** attempt renewal at a time of their choosing based on the suggested renewal window. The following algorithm is **RECOMMENDED** for choosing a renewal time:

  1. Select a uniform random time within the suggested window.
  2. If the selected time is in the past, attempt renewal immediately.
  3. Otherwise, if the client can schedule itself to attempt renewal at exactly the selected time, do so.
  4. Otherwise, if the selected time is before the next time that the client would wake up normally, attempt renewal immediately.
  5. Otherwise, sleep until the next normal wake time, re-check ARI, and return to Step 1.

In all cases, renewal attempts are subject to the client's existing error backoff and retry intervals.

In particular, cron-based clients may find they need to increase their run frequency to check ARI more frequently. Those clients will need to store information about failures so that increasing their run frequency doesn't lead to retrying failures without proper backoff. Typical information stored should include: number of failures for a given order (defined by the set of names on the order), and time of the most recent failure.

If the client receives no response or a malformed response (e.g. an `end` timestamp which is equal to or precedes the `start` timestamp), it **SHOULD** make its own determination of when to renew the certificate, and **MAY** retry the `renewalInfo` request with appropriate exponential backoff behavior.

# Extensions to the Order Object

## Extending ACME Order Objects with Certificate Lineage Information

In order to convey information regarding which certificate requests represent
renewals of previous certificates, a new field is added to the Order object:

`replaces` (string, optional): A string uniquely identifying a previously-issued certificate which this order is intended to replace. This unique identifier is constructed in the same way as the path component for GET requests described above.

Clients **SHOULD** include this field in New Order requests if there is a clear predecessor certificate, as is the case for most certificate renewals.

~~~ text
POST /acme/new-order HTTP/1.1
Host: example.com
Content-Type: application/jose+json

{
  "protected": base64url({
    "alg": "ES256",
    "kid": "https://example.com/acme/acct/evOfKhNU60wg",
    "nonce": "5XJ1L3lEkMG7tR6pA00clA",
    "url": "https://example.com/acme/new-order"
  }),
  "payload": base64url({
    "identifiers": [
      { "type": "dns", "value": "example.com" }
    ],
    "replaces": "OM8w0VGlx1SqpUk1pFCxlOMxmaU.PqNFaGVEHxw"
  }),
  "signature": "H6ZXtGjTZyUnPeKn...wEA4TklBdh3e454g"
}
~~~

Servers **SHOULD** check that the identified certificate and the current New Order request correspond to the same ACME Account and share a preponderance of identifiers, and that the identified certificate has not already been marked as replaced by a different finalized Order. Servers **MAY** ignore the `replaces` field in New Order requests which do not pass such checks.

It is suggested that Servers should use this information to grant New Order requests which arrive during the suggested renewal window of their identified predecessor certificate higher priority or allow them to bypass rate limits, if the Server's policy uses such.

## Extending ACME Order Objects with ARI Payloads

An ACME server wishing to provide renewal information **SHOULD** additionally extend ACME Order Objects with an initial payload of suggested renewal information to preclude ACME clients from having to immediately make a subsequent call to the Server's `renewalInfo` URL for this information.

The server **SHOULD** extend the ACME Order Object [@!RFC8555, section 7.1.3] with a new field `renewalInfo` containing the same paylod as provided by the `renewalInfo` resource, with the addition of a `retryAfter` field to contain the information provided in the `Retry-After` header.  The server **SHOULD NOT** include this field until a certificate has been issued and the `certificate` field is populated in the Order object.


   renewalInfo (optional, object):

        `suggestedWindow` (object, required): A JSON object as defined in the aforementioned `renewalInfo` resource

        `explanationURL` (string, optional): A URL as defined in the aforementioned `renewalInfo` resource

        `retryAfter` (string, optional): A string in the format of a `Retry-After` header, as defined in the aforementioned `renewalInfo` resource.


~~~ json
"renewalInfo": {
      "suggestedWindow": {
        "start": "2021-01-03T00:00:00Z",
        "end": "2021-01-07T00:00:00Z"
      },
      "explanationURL": "https://example.com/docs/example-mass-reissuance-event",
      "Retry-After: 21600"
    }
}
~~~

Conforming clients **SHOULD** check order objects for the presence of a `renewalInfo` field upon Certificate issuance.  If the field is present, the client **SHOULD** act as if the payload were provided as an initial ARI request.

# Interoperability Considerations

This document describes the addition of "Automated Renewal Information" to ACME [@!RFC8555], "an extensible framework for automating the issuance and domain validation procedure". Specifically, the document details the addition of a `renewalInfo` resource to the ACME `directory` object [@!RFC8555, section 7.1.1], and the `renewalInfo` and `replaces` fields to the ACME Order Object [@!RFC8555, section 7.1.3].

The optional extensions described in this document do not alter the functionality of [@!RFC8555]. [@!RFC8555] also notes in several contexts that unsupported or unknown fields should be ignored by both clients and servers.

# Security Considerations

The extensions to the ACME protocol described in this document build upon the Security Considerations and threat model defined in [@!RFC8555], Section Section 10.1.

This document specifies that `renewalInfo` resources **MUST** be exposed and accessed via unauthenticated GET requests, a departure from RFC8555’s requirement that clients must send POST-as-GET requests to fetch resources from the server. This is because the information contained in `renewalInfo` resources is not considered confidential, and because allowing `renewalInfo` to be easily cached is advantageous to shed load from clients which do not respect the Retry-After header.

# IANA Considerations

## ACME Resource Type

IANA will add the following entry to the "ACME Resource Types" registry within the "Automated Certificate Management Environment (ACME) Protocol" registry group at <https://www.iana.org/assignments/acme>:

Field Name  | Resource Type       | Reference
------------|---------------------|-----------
renewalInfo | Renewal Info object | This document

## ACME Renewal Info Object Fields

IANA will add the following new registry to the "Automated Certificate Management Environment (ACME) Protocol" registry group at <https://www.iana.org/assignments/acme>:

Registry Name: ACME Renewal Info Object Fields

Registration Procedure: Specification Required

Template:

* Field name: The string to be used as a field name in the JSON object
* Field type: The type of value to be provided, e.g., string, boolean, array of string
* Reference: Where this field is defined

Initial contents:

Field Name      | Field type | Reference
----------------|------------|-----------
suggestedWindow | object     | This document
explanationURL  | string     | This document

## ACME Order Object Fields

IANA will add the following entry to the "ACME Order Object Fields" registry within the "Automated Certificate Management Environment (ACME) Protocol" registry group at <https://www.iana.org/assignments/acme>:

Field Name  | Field Type | Configurable | Reference
------------|------------|--------------|-----------
renewalInfo | object     | true         | This document
replaces    | string     | true         | This document

{backmatter}

{numbered="false"}
# Appendix A. Example Certificate

~~~ text
-----BEGIN CERTIFICATE-----
MIIDMDCCAhigAwIBAgIIPqNFaGVEHxwwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVbWluaWNhIHJvb3QgY2EgM2ExMzU2MB4XDTIyMDMxNzE3NTEwOVoXDTI0MDQx
NjE3NTEwOVowFjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCgm9K/c+il2Pf0f8qhgxn9SKqXq88cOm9ov9AVRbPA
OWAAewqX2yUAwI4LZBGEgzGzTATkiXfoJ3cN3k39cH6tBbb3iSPuEn7OZpIk9D+e
3Q9/hX+N/jlWkaTB/FNA+7aE5IVWhmdczYilXa10V9r+RcvACJt0gsipBZVJ4jfJ
HnWJJGRZzzxqG/xkQmpXxZO7nOPFc8SxYKWdfcgp+rjR2ogYhSz7BfKoVakGPbpX
vZOuT9z4kkHra/WjwlkQhtHoTXdAxH3qC2UjMzO57Tx+otj0CxAv9O7CTJXISywB
vEVcmTSZkHS3eZtvvIwPx7I30ITRkYk/tLl1MbyB3SiZAgMBAAGjeDB2MA4GA1Ud
DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0T
AQH/BAIwADAfBgNVHSMEGDAWgBQ4zzDRUaXHVKqlSTWkULGU4zGZpTAWBgNVHREE
DzANggtleGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAx0aYvmCk7JYGNEXe
+hrOfKawkHYzWvA92cI/Oi6h+oSdHZ2UKzwFNf37cVKZ37FCrrv5pFP/xhhHvrNV
EnOx4IaF7OrnaTu5miZiUWuvRQP7ZGmGNFYbLTEF6/dj+WqyYdVaWzxRqHFu1ptC
TXysJCeyiGnR+KOOjOOQ9ZlO5JUK3OE4hagPLfaIpDDy6RXQt3ss0iNLuB1+IOtp
1URpvffLZQ8xPsEgOZyPWOcabTwJrtqBwily+lwPFn2mChUx846LwQfxtsXU/lJg
HX2RteNJx7YYNeX3Uf960mgo5an6vE8QNAsIoNHYrGyEmXDhTRe9mCHyiW2S7fZq
o9q12g==
-----END CERTIFICATE-----
~~~

{numbered="false"}
# Acknowledgments

TODO acknowledge.
