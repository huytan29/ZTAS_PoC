# Client tools

The source scripts in this directory are implementation templates only.  The
server deployment command produces the end-user artifacts in
`runtime/client-onboarding/`.  The intended public artifacts are exactly:

* `CAI-ZTAS-Windows.cmd`
* `CAI-ZTAS-macOS.command`
* `CAI-ZTAS-Ubuntu.sh`

The generated files must be self-contained: each embeds the active private CA,
the `ztas.ptit` endpoint configuration and the Locator client logic.  Do not
give `provision-client-*`, configuration files, or CA files to end users.
