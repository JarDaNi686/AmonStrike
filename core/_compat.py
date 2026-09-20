"""
AmonStrike — Compatibility helper.

Some libraries perform a hard `import urllib3.packages.six.moves`. That only
succeeds after `urllib3.packages.six` has been imported once, because six
registers its lazy `moves` module via a meta-path importer at import time.

Importing this helper early simply imports `urllib3.packages.six` first, so
the lazy `moves` submodule is registered by urllib3 itself and later hard
imports resolve normally. No modules are replaced or patched.

Usage (import early, before requests-using modules):
    import core._compat  # noqa
"""


def _prime_urllib3_six():
    try:
        # Importing the package registers six's meta-path importer, which is
        # what makes `urllib3.packages.six.moves` resolvable afterwards.
        import urllib3.packages.six  # noqa: F401
        import urllib3.packages.six.moves  # noqa: F401
    except Exception:
        pass


_prime_urllib3_six()
