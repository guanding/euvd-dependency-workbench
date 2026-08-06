"""Test environment bootstrap.

Web tests construct ``matcher.EuvdClient``, whose ``__init__`` calls
``DATA_DIR.mkdir(...)`` and connects to ``CACHE_DB`` (a path derived from
``DATA_DIR`` at module-import time). The module default ``DATA_DIR`` is the
in-container path ``/app/data``; outside the container that path is read-only
or absent, so every test that builds a client fails before any assertion runs.

Force a writable temp directory *before* ``app.matcher`` is imported (pytest
loads conftest before test modules) so the whole suite runs hermetically on any
host, container or not.
"""

import os
import tempfile

os.environ.setdefault("DATA_DIR", str(tempfile.gettempdir()) + "/euvd-web-test")
# OUTPUT_DIR defaults to an independent /app/outsides-the-data-tree path
# (/app/outputs), so it needs its own override.
os.environ.setdefault("OUTPUT_DIR", str(tempfile.gettempdir()) + "/euvd-web-test/outputs")
