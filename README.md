# rust_widevine

## Disclaimer
1. This project requires a valid Google-provisioned Private Key and Client Identification blob which are not provided by this project.
2. Public test provisions are available and provided by Google to use for testing projects such as this one.
3. License Servers have the ability to block requests from any provision, and are likely already blocking test provisions on production endpoints.
4. This project does not condone piracy or any action against the terms of the DRM systems.
5. All efforts in this project have been the result of Reverse-Engineering, Publicly available research, and Trial & Error.

### Tests

To use your CDM, create a directory called `security` and put your `device_private_key` and `device_client_id_blob` in it.

Output of the tests will be in the `security` directory.

#### Crunchyroll

put your etp-rt cookie in a file called `.env` like this:

```env
etp_rt=98daf35f-821e-4350-9c1f-6725014657d3
```

#### Bitmovin

this test does not require any configuration.

## License Stuff

This project is licensed under GPLv3-or-later because of `src/license_protocol.proto` from [@rlaphoenix/pywidevine 1.6.0](https://github.com/rlaphoenix/pywidevine). It's license is in `THIRDPARTY.md`. The file `src/lib.rs` is licensed under MIT. `src/error.rs` is from [@crunchy-labs/crunchyroll-rs 0.6.2](https://github.com/crunchy-labs/crunchyroll-rs) and is also licensed under MIT. The license is in `THIRDPARTY.md`.
