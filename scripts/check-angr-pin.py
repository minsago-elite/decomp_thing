#!/usr/bin/env python3
"""Check the authored production/default qualification pin before installing tools."""
import hashlib
import json
from pathlib import Path
import re

docker = Path("Dockerfile").read_bytes()
requirements = Path("requirements/angr-qualification.txt").read_bytes()
compatibility = Path("requirements/angr-compatibility.txt").read_bytes()
production = re.findall(rb"^ARG[ \t]+ANGR_VERSION=([0-9]+(?:\.[0-9]+)+)[ \t]*$", docker, re.M)
qualification = re.findall(rb"^angr==([0-9]+(?:\.[0-9]+)+)[ \t]*$", requirements, re.M)
if len(production) != 1 or production != qualification:
    raise SystemExit("Angr qualification requires one matching Docker and requirements pin")
bitstring = re.findall(rb"^bitstring==([0-9]+(?:\.[0-9]+)+)[ \t]*$", compatibility, re.M)
if len(bitstring) != 1:
    raise SystemExit("Angr qualification requires one shared bitstring compatibility pin")
pycparser = re.findall(rb"^pycparser==([0-9]+(?:\.[0-9]+)+)[ \t]*$", compatibility, re.M)
if len(pycparser) != 1:
    raise SystemExit("Angr qualification requires one shared pycparser compatibility pin")
print(json.dumps({
    "angrVersion": production[0].decode("ascii"),
    "bitstringVersion": bitstring[0].decode("ascii"),
    "pycparserVersion": pycparser[0].decode("ascii"),
    "dockerfileSha256": hashlib.sha256(docker).hexdigest(),
    "requirementsSha256": hashlib.sha256(requirements).hexdigest(),
    "compatibilitySha256": hashlib.sha256(compatibility).hexdigest(),
}))
