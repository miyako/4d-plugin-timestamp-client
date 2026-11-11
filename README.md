![version](https://img.shields.io/badge/version-20%2B-E23089)
![platform](https://img.shields.io/static/v1?label=platform&message=mac-intel%20|%20mac-arm%20|%20win-64&color=blue)
[![license](https://img.shields.io/github/license/miyako/4d-plugin-timestamp-client)](LICENSE)
![downloads](https://img.shields.io/github/downloads/miyako/4d-plugin-timestamp-client/total)

# 4d-plugin-timestamp-client

Timestamp client based on OpenSSL [``ts``](https://github.com/openssl/openssl/blob/master/apps/ts.c).

The plugin builds and checks [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) trusted timestamps with the OpenSSL `TS_*` API (statically linked OpenSSL 1.1.1). It does no networking: you hash your data into a timestamp query (`Blob`), send that query to a Time Stamping Authority (TSA) yourself, for example with `HTTP Request`, then pass the TSA's reply (`Blob`) back to the plugin to verify it against the query and a CA certificate. Verification returns an `Object`.

| Command | Returns | Purpose |
|---|---|---|
| [Create timestamp query](#create-timestamp-query) | `Blob` | Hash data and build a timestamp query (DER or text) |
| [Verify timestamp request](#verify-timestamp-request) | `Object` | Verify a TSA response against the query and trusted CA certificates |

**Platforms:** macOS (Apple silicon and Intel, 11.5 or later), Windows 64-bit. 4D v20 or later.

Releases: [GitHub releases](https://github.com/miyako/4d-plugin-timestamp-client/releases).

---

## Requirements & platform notes

- **Failure is silent, not a 4D error.** Neither command raises a 4D error or sets `OK`. [Create timestamp query](#create-timestamp-query) returns an empty `Blob` when it fails; [Verify timestamp request](#verify-timestamp-request) returns an object whose `success` is `False`. Neither tells you why.
- **All parameters are mandatory.** Both commands read every parameter; pass an empty object (`New object`) when you have no options.
- **No network access.** Posting the query to the TSA is up to you (see the example below, which uses `HTTP Request` with `Content-Type: application/timestamp-query`).
- **No system trust store.** Verification only trusts the certificates you pass in `cafile` or `capath`. Without either, verification always fails.
- **macOS paths must be system paths** (colon-separated, as returned by `Get 4D folder` or `File.platformPath`). The plugin converts them to POSIX paths; a POSIX path (`/Users/...`) passed on macOS is misread. On Windows the path is passed to OpenSSL as is.
- **Thread-safe.** Both commands are declared thread-safe in the manifest and can run in preemptive processes.

### Constants

The plugin adds two constant themes.

| Constant | Value | Use |
|---|---|---|
| `Timestamp Request Text` | 0 | `format`: human-readable text dump of the query |
| `Timestamp Request ASN1` | 1 | `format`: DER-encoded query, the form a TSA accepts |
| `Timestamp Hash Algorithm SHA512` | 0 | `hash` |
| `Timestamp Hash Algorithm SHA384` | 1 | `hash` |
| `Timestamp Hash Algorithm SHA256` | 2 | `hash` |
| `Timestamp Hash Algorithm SHA224` | 3 | `hash` |
| `Timestamp Hash Algorithm SHA1` | 4 | `hash` |

---

## Create timestamp query

### Syntax

```
Create timestamp query ( data ; options ) -> Blob
```

| Parameter | Type | Description |
|---|---|---|
| `data` | Blob | The data to timestamp. Only its hash goes into the query; the data itself never leaves 4D |
| `options` | Object | Query options (table below). Pass an object, even an empty one |
| Result | Blob | The timestamp query, DER-encoded or as text; empty on failure |

`options` properties:

| Property | Type | Description |
|---|---|---|
| `format` | Integer | `Timestamp Request ASN1` (1) for a DER query to send to a TSA, `Timestamp Request Text` (0) for a readable dump. **Read even when absent: an options object without `format` produces text.** Any value other than 1 produces text |
| `hash` | Integer | Hash algorithm, one of the `Timestamp Hash Algorithm` constants. Default, and fallback for unknown values: SHA-512 |
| `cert` | Boolean | Ask the TSA to include its signing certificate in the response (`certReq`). Default `True` |
| `no_nonce` | Boolean | `True` (default) sends no nonce. `False` adds a random 64-bit nonce, which the response must echo for verification to succeed |
| `policy` | Text | TSA policy OID in dotted form (e.g. `"1.2.3.4.1"`). Omit it to let the TSA use its default policy |

### Description

The command hashes `data` with the chosen algorithm, builds a version 1 `TimeStampReq` with that message imprint, and returns it. Use `Timestamp Request ASN1` for the query you send to the TSA, and keep that `Blob`: [Verify timestamp request](#verify-timestamp-request) needs the exact same query to check the response.

The text format is the output of OpenSSL's `TS_REQ_print_bio`, returned as bytes in a `Blob`; convert it with `BLOB to text` to read it.

The result is empty when:

- `data` is empty (OpenSSL cannot create a memory buffer for an empty BLOB);
- `policy` is not a valid OID;
- OpenSSL fails for any other reason (allocation, encoding).

Since this revision, a negative, non-numeric or very large `format` or `hash` falls back to text and SHA-512. Earlier builds cast such values without a check (undefined behaviour).

### Example

From the plugin's own test method (`TEST_freetsa.4dm`):

```4d
  //data to hash
$path:=Get 4D folder:C485(Current resources folder:K5:16)+"4D.pdf"
DOCUMENT TO BLOB:C525($path;$PDF)

If (True:C214)
	  //this is the default when params is empty
	$params:=New object:C1471(\
		"cert";True:C214;\
		"no_nonce";True:C214;\
		"format";Timestamp Request ASN1;\
		"hash";Timestamp Hash Algorithm SHA512)
End if 

C_BLOB:C604($TSQ;$TSR)

$TSQ:=Create timestamp query ($PDF;$params)
```

The comment in the test method says these are the defaults "when params is empty". That holds for `cert`, `no_nonce` and `hash`, but **not for `format`**: an empty object gives a text query. Always set `format` explicitly.

A SHA-256 query with a nonce, and a readable dump of a query:

```4d
var $data; $tsq; $dump : Blob
TEXT TO BLOB("hello"; $data; UTF8 text without length)

$tsq:=Create timestamp query($data; New object(\
"format"; Timestamp Request ASN1; \
"hash"; Timestamp Hash Algorithm SHA256; \
"no_nonce"; False))

$dump:=Create timestamp query($data; New object("format"; Timestamp Request Text))
ALERT(BLOB to text($dump; UTF8 text without length))
```

Each call with `no_nonce` = `False` draws a new random nonce, so a dump made in a separate call does not match the DER query exactly.

---

## Verify timestamp request

### Syntax

```
Verify timestamp request ( response ; query ; options ) -> Object
```

| Parameter | Type | Description |
|---|---|---|
| `response` | Blob | The TSA's reply (`TimeStampResp`, DER), e.g. the HTTP body returned for an `application/timestamp-query` POST |
| `query` | Blob | The DER query the response answers, as returned by [Create timestamp query](#create-timestamp-query) with `Timestamp Request ASN1` |
| `options` | Object | Trusted certificates (table below) |
| Result | Object | Verification result (table below) |

`options` properties:

| Property | Type | Description |
|---|---|---|
| `cafile` | Text | Path of a file with the trusted CA certificate(s). Read as PEM first, then as DER |
| `capath` | Text | Path of a folder of trusted CA certificates in OpenSSL's hashed-directory layout (files named `<subject hash>.0`, as made by `openssl rehash`). PEM and DER are both looked up |
| `untrusted` | Text | Path of a PEM file with intermediate certificates, used to build the chain but not trusted as anchors. If the file cannot be read, verification fails |
| `castore` | Text | Accepted but **ignored** (not implemented with OpenSSL 1.1.1) |

Result properties:

| Property | Type | Description |
|---|---|---|
| `success` | Boolean | `True` only when the response passed every check |
| `tsr` | Text | Readable dump of the response (`TS_RESP_print_bio`). Present only when `response` could be parsed |
| `tsq` | Text | Readable dump of the query (`TS_REQ_print_bio`). Present only when both `response` and `query` could be parsed |

### Description

The command parses the response and the query, then runs OpenSSL's `TS_RESP_verify_response` with the checks the query implies, as `openssl ts -verify -queryfile` does:

- the response status is "granted" or "granted with modifications";
- the token's signature is valid and the signing certificate chains to a certificate from `cafile` or `capath`;
- the token version is 1;
- the message imprint (hash algorithm and value) equals the query's;
- the policy matches, if the query named one;
- the nonce matches, if the query had one;
- the TSA name in the token, if any, matches the signing certificate.

The response must contain the TSA's signing certificate (query made with `cert` = `True`, the default), unless you supply it through `untrusted`.

`success` is `False` when either BLOB is empty or cannot be parsed, when neither `cafile` nor `capath` is given, when a certificate file cannot be loaded, or when any check fails. The reason is not reported; compare the `tsr` and `tsq` dumps to investigate.

**On macOS**, `cafile`, `capath` and `untrusted` are converted from system (colon-separated) paths to POSIX. **On Windows**, they are passed to OpenSSL unchanged.

Since this revision the command no longer leaks two OpenSSL memory buffers on every call.

### Example

From the plugin's own test method (`TEST_freetsa.4dm`), continuing the example above:

```4d
ARRAY TEXT:C222($hn;1)
ARRAY TEXT:C222($hv;1)

$hn{1}:="Content-Type"
$hv{1}:="application/timestamp-query"

$status:=HTTP Request:C1158(HTTP POST method:K71:2;"https://freetsa.org/tsr";$TSQ;$TSR;$hn;$hv)

ASSERT:C1129($status=200)

$capath:=Get 4D folder:C485(Current resources folder:K5:16)+"freetsa.org"+Folder separator:K24:12

$cafile:=$capath+"cacert.cer.der"

$params:=New object:C1471("cafile";$cafile)

$verify:=Verify timestamp request ($TSR;$TSQ;$params)

ASSERT:C1129($verify.success)

$cafile:=$capath+"cacert.cer.pem"

$params:=New object:C1471("cafile";$cafile)

$verify:=Verify timestamp request ($TSR;$TSQ;$params)

ASSERT:C1129($verify.success)
```

Showing the dumps when verification fails:

```4d
$verify:=Verify timestamp request($TSR; $TSQ; New object("cafile"; $cafile))
If (Not($verify.success))
	ALERT(String($verify.tsr)+Char(Carriage return)+String($verify.tsq))
End if 
```

---

## Error handling & troubleshooting

- **Empty query BLOB.** [Create timestamp query](#create-timestamp-query) returns an empty `Blob` for empty `data`, an invalid `policy` OID, or an OpenSSL failure. Check `BLOB size` before sending it.
- **Query is text, not DER.** An options object without `format` produces the text dump, which a TSA rejects. Set `"format"; Timestamp Request ASN1`.
- **`success` is always `False`.** Pass `cafile` or `capath`; the system trust store is not used. On macOS, pass a system path (`Get 4D folder`, `File.platformPath`), not a POSIX path.
- **Signature check fails although the CA is right.** The response may lack the TSA certificate (query made with `cert` = `False`), or the chain needs an intermediate certificate: pass it in `untrusted` (PEM).
- **Imprint or nonce mismatch.** Verify against the exact query `Blob` you sent. A query rebuilt from the same data has the same imprint but a different nonce when `no_nonce` is `False`.
- **No `tsq` in the result.** The response could not be parsed, so the query was never read. Check that `response` is the raw HTTP body and that the HTTP status was 200.
- **`castore` has no effect.** It is accepted for compatibility with the `openssl ts` options but ignored.

---

## Quick reference

```4d
var $data; $tsq; $tsr : Blob
var $verify : Object

DOCUMENT TO BLOB($path; $data)
$tsq:=Create timestamp query($data; New object("format"; Timestamp Request ASN1; "hash"; Timestamp Hash Algorithm SHA256))

ARRAY TEXT($hn; 1)
ARRAY TEXT($hv; 1)
$hn{1}:="Content-Type"
$hv{1}:="application/timestamp-query"
$status:=HTTP Request(HTTP POST method; $tsaURL; $tsq; $tsr; $hn; $hv)

$verify:=Verify timestamp request($tsr; $tsq; New object("cafile"; $cafile))
// $verify.success, $verify.tsr, $verify.tsq
```
