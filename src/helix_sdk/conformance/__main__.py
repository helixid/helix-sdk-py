# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""``python -m helix_sdk.conformance [vectors_dir]``: the seven story F-2 categories."""

import sys

from .runner import main

sys.exit(main(sys.argv[1:]))
