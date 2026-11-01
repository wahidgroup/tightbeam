# Envelope Fuzz Seeds

Binary corpus for `fuzz_envelope_der`. Each file is the DER of one `TransportEnvelope` over the V0 frame of `TestFrame`.

| File                    | Envelope                                     |
| ----------------------- | -------------------------------------------- |
| `envelope_request.bin`  | A `Request` that carries the frame           |
| `envelope_response.bin` | A `Response` that carries the frame          |
| `envelope_refusal.bin`  | A `Response` of `Unauthenticated`, frameless |
