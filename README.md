# Endolum Nuclei templates

Nuclei detection templates written by Endolum, mostly as a byproduct of our own
vulnerability research. Every template here is non invasive: it reads a version
string or a banner and compares it against the fixed builds. None of them send a
payload or touch an exploit path, which is what makes them safe to run against
production systems and against hosts you do not own.

Published under the same terms as the upstream project templates so anyone can
use them. Where a CVE fits the scope of `projectdiscovery/nuclei-templates`, we
propose it there as well.

## Layout

```
cves/            one YAML file per CVE, named after the CVE id
manifest.json    generated index: content version plus a sha256 per template
scripts/         manifest generator
```

## How our scanners consume this

The Endolum Sentinel scanners do not bake these templates into their image. They
read `manifest.json` at the start of a scan, compare `version` against the copy
they already hold on disk, and download the bundle again only when it differs.
A new detection is therefore live on the next scan without any rebuild and
without any customer touching their sensor.

`version` is a hash of the template contents, so it moves when a template moves
and never otherwise. A fetch that fails leaves the previous bundle in place; a
scan never fails because this repo was unreachable.

## Adding a template

1. Write the YAML into `cves/`, named after the CVE id, with `author: endolum`.
2. Keep `info.severity` in critical, high, medium or low. The scanners filter on
   exactly those four, so an `info` template would load, match, and then have its
   findings dropped before anything reaches a report.
3. Validate the schema: `nuclei -validate -t cves/`.
4. Test the matcher logic against a local mock server that serves a vulnerable
   build, the exact fixed build, a boundary build and an unrelated response.
   A version comparison that is off by one octet passes schema validation.
5. Regenerate the index: `python3 scripts/build_manifest.py`.

For detectors produced by Vuln Radar, run the local distribution gate before
finishing the research run:

```bash
python3 scripts/check_vuln_radar_coverage.py
```

The command fails when a verified detector with a supported scanner severity is
missing from `cves/`. Unverified `info` fingerprints are reported and skipped
because Sentinel discards that severity and they do not prove vulnerability.

CI runs steps 3 and 5 in check mode on every push, and fails if the manifest is
stale or a template is unparseable, carries a duplicate id, or uses a severity
the scanners would discard.
