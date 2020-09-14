# usbll2sr

Simple USBLL PCAP to Sigrok session file converter.

## Features

- Generates USB signaling from binary USBLL packets.
- Respect the packet timing as much as possible.
- Supports USB 2.0 Low-Speed and Full-Speed signaling.

## Usage

```sh
pipenv install
pipenv run ./usbll2sr.py ...
```

## Planned

- Actually test against Low-Speed devices.
- Automatically detect signal type (can this be done?).
- Implement High-Speed signaling (need a way to test it since sigrok does not support HS yet).
