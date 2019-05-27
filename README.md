# No SNI

All browsers send SNI, but not all websites require SNI.
Removing SNI from these requests is a good way to protect privacy.

## Usage

```
$ vim .config/nosni-proxy/config.toml
$ nosni-proxy
```

and set your HTTP proxy address to `127.0.0.1:1087`.

## license

[CC0 1.0 Universal License](https://creativecommons.org/publicdomain/zero/1.0/)
