# Handshake Fuzz Seeds

Binary corpus for `fuzz_handshake`. Byte `0` of a seed picks the stage (`% 10`), and the rest is the message of that stage. The message of stages 0 to 5 comes from a handshake between the keys of the target, so a seed passes the certificate and the `rid` checks. The message of stages 6 to 9 comes from the CMS samples that `make interop` writes and from the content of a CMS opening.

| File                  | Stage | Message                                    |
| --------------------- | ----- | ------------------------------------------ |
| `hpke_opening.bin`    | 0     | The `ContentInfo` of an HPKE hello         |
| `cms_opening.bin`     | 1     | The `AuthEnvelopedData` of a CMS opening   |
| `hpke_reply.bin`      | 2     | The `SignedData` of an HPKE reply          |
| `cms_reply.bin`       | 3     | The `SignedData` of a CMS server Finished  |
| `hpke_closing.bin`    | 4     | The `AuthEnvelopedData` of an HPKE closing |
| `cms_closing.bin`     | 5     | The `AuthEnvelopedData` of a CMS closing   |
| `client_hello.bin`    | 6     | The DER of a `ClientHello`                 |
| `server_content.bin`  | 7     | The DER of a `ServerHandshake`             |
| `session_receipt.bin` | 8     | The DER of a `SessionReceipt`              |
| `opening_content.bin` | 9     | The DER of the content of a CMS opening    |

A reply or a closing seed binds another handshake, so its signature or its tag fails in every run. Stage 9 seals its message to the key of the server in each run, so AFL mutates the content behind that seal.
