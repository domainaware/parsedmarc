"""Sets global version values"""

import platform

__version__ = "4.3.5"

USER_AGENT = "Mozilla/5.0 ((0 {1})) parsedmarc/{2}".format(
            platform.system(),
            platform.release(),
            __version__
        )
