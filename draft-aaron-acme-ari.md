%%%
title = "Automated Certificate Management Environment (ACME) Renewal Information (ARI) Extension"
abbrev = "ACME ARI"
ipr = "trust200902"
area = "Security Area (sec)"
workgroup = "ACME Working Group"
keyword = ["Internet-Draft"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-aaron-acme-ari-latest"
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

This document specifies how an ACME server may provide hints to ACME clients as to when they should attempt to renew their certificates. This allows servers to mitigate load spikes, and ensures clients do not make false assumptions about appropriate certificate renewal periods.

.# Current Implementations

Draft note: this section will be removed by the editor before final publication.

Let's Encrypt's Staging environment (available at [@lestaging], source at [@boulder]) implements this draft specification.

<reference anchor='lestaging' target='https://acme-staging-v02.api.letsencrypt.org/directory'>
    <front>
        <title>Let's Encrypt Staging Environment</title>
        <author>
            <organization>Internet Security Research Group</organization>
        </author>
        <date year='2021'/>
    </front>
</reference>

<reference anchor='boulder' target='https://github.com/letsencrypt/boulder'>
    <front>
        <title>Boulder</title>
        <author>
            <organization>Internet Security Research Group</organization>
        </author>
        <date year='2021'/>
    </front>
</reference>

{mainmatter}

# Introduction

Most ACME [@!RFC8555] clients today choose when to attempt to renew a certificate in one of three ways. They may be configured to renew at a specific interval (e.g. via `cron`); they may parse the issued certificate to determine its expiration date and renew a specific amount of time before then; or they may parse the issued certificate and renew when some percentage of its validity period has passed. The first two techniques create significant barriers against the issuing CA changing certificate lifetimes. All three techniques lead to load clustering for the issuing CA.

Being able to indicate to the client a period in which the issuing CA suggests renewal would allow both dynamic changes to the certificate validity period and proactive smearing of load. This document specifies a mechanism by which ACME servers may provide suggested renewal windows to ACME clients.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [@!RFC2119;@!RFC8174] when, and only when, they appear in all capitals, as shown here.

# Extensions to the ACME Protocol: The "directory" Resource

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

# Extensions to the ACME Protocol: The "renewalInfo" Resource

We define a new resource type, the "`renewalInfo`" resource, as part of the ACME protocol. To request the suggested renewal information for a certificate, the client sends a GET request to a path under the server's `renewalInfo` URL.

The full request URL is computed by concatenating the `renewalInfo` URL from the server's directory with the following case-insensitive hex-encoded (see [@!RFC4648], Section [@!RFC4648, section 8]) elements, separated by forward slashes:

* the SHA-1 hash of the issuer's public key (often included in the certificate as the Authority Key Identifier, see [@!RFC5280], Section [@!RFC5280, section 4.2.1.1]),
* the SHA-1 hash of the issuer's Distinguished Name, see [@!RFC5280], Section [@!RFC5280, section 4.1.2.4], and
* the certificate serial number.

These are the same components that make up the `CertID` sequence of an `OCSPRequest` [@!RFC6960], Section [@RFC6960, section 4.1.1], with the caveat that the hash algorithm is restricted to SHA-1, in line with [@!RFC5019].

~~~ text
GET https://example.com/acme/renewal-info
        /254581685026383D3B2D2CBECD6AD9B63DB36663
        /06FE0BABD8E6746EFCC4730285F7A9487ED1344F
        /BCDF4596B6BDC523
~~~

The structure of an ACME `renewalInfo` resource is as follows:

`suggestedWindow` (object, required): A JSON object with two keys, "`start`" and "`end`", whose values are timestamps, encoded in the format specified in [@!RFC3339], which bound the window of time in which the CA recommends renewing the certificate.

~~~ json
HTTP/1.1 200 OK
Content-Type: application/json
Retry-After: "21600"

{
  "suggestedWindow": {
    "start": "2021-01-03T00:00:00Z",
    "end": "2021-01-07T00:00:00Z"
  }
}
~~~

The server **SHOULD** include a `Retry-After` header indicating the polling interval that the ACME server recommends. Conforming clients **SHOULD** query the `renewalInfo` URL again after the `Retry-After` period has passed, as the server may provide a different `suggestedWindow`.

Conforming clients **MUST** select a uniform random time within the suggested window to attempt to renew the certificate. If the selected time is in the past, the client **SHOULD** attempt renewal immediately. If the selected time is in the future, but before the next time that the client would wake up normally, the client **MAY** attempt renewal immediately. In all cases, renewal attempts are subject to the client's existing error backoff and retry intervals.

In particular, cron-based clients may find they need to increase their run frequency to check ARI more frequently. Those clients will need to store information about failures so that increasing their run frequency doesn't lead to retrying failures without proper backoff. Typical information stored should include: number of failures for a given order (defined by the set of names on the order), and time of the most recent failure.

# Security Considerations

The extensions to the ACME protocol described in this document build upon the Security Considerations and threat model defined in [@!RFC8555], Section [@!RFC8555, section 10.1].

This document specifies that `renewalInfo` resources **MUST** be exposed and accessed via unauthenticated GET requests, a departure from RFC8555’s requirement that clients must send POST-as-GET requests to fetch resources from the server. This is because the information contained in `renewalInfo` resources is not considered confidential, and because allowing `renewalInfo` to be easily cached is advantageous to shed load from clients which do not respect the Retry-After header.

# IANA Considerations

Draft note: The following changes to IANA registries have not yet been made.

## New Registries

Within the "Automated Certificate Management Environment (ACME) Protocol" registry, IANA has created the new "ACME Renewal Info Object Fields" registry (Section 6.4).

## ACME Resource Type

Within the "Automated Certificate Management Environment (ACME) Protocol" registry, the following entry has been added to the "ACME Resource Types" registry.

Field Name  | Resource Type       | Reference
------------|---------------------|-----------
renewalInfo | Renewal Info object | This draft

## ACME Renewal Info Object Fields

The "ACME Renewal Info Object Fields" registry lists field names that are defined for use in ACME renewal info objects.

Template:

* Field name: The string to be used as a field name in the JSON object
* Field type: The type of value to be provided, e.g., string, boolean, array of string
* Reference: Where this field is defined

Initial contents:

Field Name      | Field type | Reference
----------------|------------|-----------
suggestedWindow | object     | This draft

{backmatter}

{numbered="false"}
# Acknowledgments

TODO acknowledge.
