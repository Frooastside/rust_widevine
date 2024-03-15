# rust_widevine

## CDM

create a directory called `security` and put your `device_private_key` and `device_client_id_blob` in it.

### Tests

#### Crunchyroll

put your etp-rt cookie in a file called `.env` like this:

```env
etp-rt=98daf35f-821e-4350-9c1f-6725014657d3
```

#### Bitmovin

this test does not require any configuration.

## License Stuff

This project is licensed under GPLv3-or-later because of `src/license_protocol.proto` from [@rlaphoenix/pywidevine 1.6.0](https://github.com/rlaphoenix/pywidevine). It's license is in `THIRDPARTY.md`. The file `src/lib.rs` is licensed under MIT. `src/error.rs` is from [@crunchy-labs/crunchyroll-rs 0.6.2](https://github.com/crunchy-labs/crunchyroll-rs) and is also licensed under MIT. The license is in `THIRDPARTY.md`.
