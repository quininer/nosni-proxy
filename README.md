# No SNI

All browsers send SNI, but not all websites require SNI.
Removing SNI from these requests is a good way to protect privacy.

Note that this is not a perfect solution because the Server certificate will still leak information.
The real solution needs to wait for [ESNI](https://tools.ietf.org/html/draft-ietf-tls-esni-02).

## Usage

```
env NOSNI_P12_PATH="YOUR-CERT-AND-KEY.p12" nosni-proxy
```

and set your HTTP proxy address to `127.0.0.1:1087`.

## license

[CC0 1.0 Universal License](https://creativecommons.org/publicdomain/zero/1.0/)
