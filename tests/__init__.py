"""Silence application logging while the suite runs.

The service logs every branch on purpose - that is what makes a rejected
webhook diagnosable in production. Inside a test runner it is noise: several
hundred INFO lines bury the one line that says which assertion failed.

This suppresses output only. The logging calls still execute, so a broken
format string would still raise.
"""

import logging

logging.disable(logging.CRITICAL)
