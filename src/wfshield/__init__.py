"""wfshield — zero-dependency GitHub Actions workflow security auditor.

wfshield reads your .github/workflows/*.yml files and flags the CI
supply-chain patterns behind the real attacks: unpinned third-party
actions, write-all tokens, pull_request_target + fork checkout, shell
interpolation of untrusted GitHub context, secrets expanded at script
level, self-hosted runners on fork events, remote pipe-to-shell
installers, and cache poisoning. Exit codes 0/1/2 gate it in CI.
"""

__version__ = "1.0.0"
__all__ = ["cli", "rules", "scanner", "wfyaml"]
