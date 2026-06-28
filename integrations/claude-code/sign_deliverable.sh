#!/bin/sh
# Sign the file named by $AP_DELIVERABLE and write <file>.receipt next to it.
#
# SECURITY: $AP_DELIVERABLE must be a TRUSTED path set by your orchestrator — never raw model
# output. We quote defensively, but a hook runs unattended on Stop, so do not let an agent choose
# this value. Treat it like a filename you'd pass to `rm`.
set -eu
: "${AP_DELIVERABLE:?set AP_DELIVERABLE to the file to sign}"
exec vouchsafe sign "$AP_DELIVERABLE" --out "${AP_DELIVERABLE}.receipt"
