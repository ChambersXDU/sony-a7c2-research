# ILCE-7CM2 Ver. 2.01 validation

Validated on 2026-10-11 (Asia/Shanghai), on macOS with Python 3.9.6,
pycryptodomex 3.24.0 and PyYAML 6.0.3. The development baseline is
[DavidBuchanan314/a7iv](https://github.com/DavidBuchanan314/fwtool.py/tree/a7iv),
commit `3955d7890fc38daf942bb52827599bfe35de4a14`. Both this unmodified
baseline and the patch were run against the complete official download.

This page records the initial support patch, commit
`0bf0915dce843e398b23d11e2f3d2e97086093e0`. The subsequent
[WBI2 contribution](wbi2.md) adds section and memory-image outputs and extends
the tests; the baseline comparison and file counts below describe that initial
patch.

[PR #52](https://github.com/ma1co/fwtool.py/pull/52) was still open and unmerged
when checked; its head matched that baseline. David Buchanan's existing
CXD90057 implementation already decrypts this update. This patch adds verified
device metadata, regression coverage and checks for truncated input; it does
not introduce the decryption algorithm.

## Firmware provenance

- [Sony USA Ver. 2.01 page](https://www.sony.com/electronics/support/software/00301105).
- [Sony China Ver. 2.01 page](https://service.sony.com.cn/download/firm/00003056.html).
- The USA page returned HTTP 403 to curl. The China page and its normal
  `clientlib-downloadRoom.js` flow were inspected, including the download terms.
  Its public `outDownload?method=findOne` endpoint, using the product path
  `/etc/commerce/products/casch/pim/download/firmware/00003056`, supplied
  `https://support.d-imaging.sony.co.jp/download/NEX/uua3b90658/BODYDATA.DAT?fm=cn`.
- That Sony URL redirected to
  `https://di.update.sony.net/NEX/uua3b90658/BODYDATA.DAT` (HTTP 200).
  No third-party mirror was used.
- File: `BODYDATA.DAT`; version: 2.01; size: **1,139,929,560 bytes**.
- SHA-256: `eb4943e6099754d64deaef5047942e9bfe258f232d0b7bc39fa23b3cd10e1e31`.
  This digest was calculated locally, not published as a Sony signature.

## Reproduction

Obtain the update through Sony's download flow and applicable terms. Store the
firmware and outputs outside the checkout. The initial unpacked tree used about
3.84 GiB, in addition to the 1.06 GiB input. With WBI2 section extraction and
the sparse image, outputs use under 4.5 GiB; reserve at least 6 GiB for one
extraction. The opt-in test also needs 6 GiB free in the system temporary
directory and removes its own output afterward.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python fwtool.py --help
.venv/bin/python fwtool.py unpack -f /tmp/sony-fw/BODYDATA.DAT -o /tmp/sony-fw/unpacked
.venv/bin/python -m unittest discover -s tests -v
SONY_A7C2_FW=/tmp/sony-fw/BODYDATA.DAT .venv/bin/python -m unittest tests.test_a7c2_e2e -v
```

Only pycryptodomex and PyYAML are needed for source execution and tests;
PyInstaller is an existing build dependency in `requirements.txt`.
Without an existing `SONY_A7C2_FW` file, the real-firmware test reports a skip,
not a successful firmware validation. A supplied file with the wrong size or
digest fails the test. The test does not download anything or execute pack.

## Observed results

The DAT header was recognized, DAT CRC32 passed, encrypted block checksums
passed during the complete stream, and the FDAT header CRC32 passed. No
checksum or integrity exception occurred. `config.yaml` contains:

```yaml
dat:
  crypterName: CXD90057_k8
  isLens: false
fdat:
  model: 0x20030014
  region: 0
  version: '2.01'
  isAccessory: false
```

| Output | Bytes | SHA-256 |
| --- | ---: | --- |
| firmware.fdat | 1,135,475,712 | `03eee07301010ff644fae1073f7c7f6dd2d60278f18aa3e6053938d5f1426d1f` |
| firmware.tar | 1,134,221,824 | `c29eaafab7f5f46dc364ebee244d75b1f93e017af651df5f4f92ec239df953b7` |
| updater.img | 1,253,376 | `788db9cdfb38edc171686b07635efea397279c303cef49308d8303601d0dcf0e` |

The firmware tar, nested loader tar, ext2 partitions `nflasha7`/`nflasha15`,
FAT partitions `nflasha3`/`nflasha8`, nested ext2 `initrd.img`, SquashFS
`udtrbody.bin`, and SquashFS
`updater.img` were extracted. `updater.img_unpacked/bodylib/libupdaterbody.so`
exists. Recursive extraction produced 1,365 regular files below the two
output trees (1,850,534,679 bytes, including preserved partition images).
SHA-256 manifests of all 1,369 regular output files, including the top-level
files and config, matched between the unmodified baseline and patched CLI.

## Patch and verification scope

`devices.yml` supplies metadata to `pack -d` and the device list. It is not
consulted by unpack. The new entry uses the model ID read from this firmware
and `key: k8`, because the registered crypter is `CXD90057_k8`; there is no
bare `CXD90057` crypter. Packing/reencryption remains unsupported by the CBC
crypter and was not performed.

Synthetic tests reproduce three pre-existing input-handling defects:
truncated DAT headers/chunks raised `AttributeError`; incomplete encrypted
blocks raised low-level XOR/AES errors and aborted decrypter selection;
FDAT payloads could be shorter than their declared ranges without rejection.
The fixes validate those lengths, preserve checksum failures, and leave valid
input and existing device entries unchanged. Fixtures construct small binary
headers, block framing and AES data independently of fwtool's pack routines.

The suite covers device schema/duplicate keys, verified ILCE-7CM2 metadata,
CXD90057 k0/k8, CBC continuation and replay, checksum/end-flag failures,
truncation, legacy CXD4132/CXD90014/CXD90045 decryption, ext2 detection and
CLI tar/gzip recursion. Real-firmware tests independently check the input
digest, parsed metadata, output sizes/digests and representative nested output.
The added test workflow runs synthetic coverage on Python 3.9 and 3.13.
Locally, the default run passed 16 tests and skipped the optional firmware
test. With `SONY_A7C2_FW` set, all 17 tests passed, including an additional
complete extraction and output digest checks (29.32 seconds for the suite).
The inherited binary-build workflow uses old runner/action versions and is
not modernized by this patch.

## Limits and unverified behavior

- `nflasha5` (267,171,648 bytes) begins with **WBI2**. It is preserved intact
  but was not parsed by the baseline or the initial ILCE-7CM2 support patch.
  A subsequent, separate [WBI2 contribution](wbi2.md) now extracts this
  uncompressed 64-bit variant. Other WBI2 flags remain unsupported.
- The unpacker writes regular files/directories, omitting symbolic links and
  special files. It is not a faithful filesystem restoration tool.
- CRC/block checks verify the checks implemented by fwtool. Camera-side
  authenticity checks and the 256-byte encryption trailer are not validated.
- Compatibility with other ILCE-7CM2 versions/regions and genuine firmware
  for other models remains untested here. Other-model regression uses
  synthetic data, not camera firmware.
- No hardware connection, firmware update, pack operation or execution of
  extracted programs was performed. Firmware binaries remain outside Git.
