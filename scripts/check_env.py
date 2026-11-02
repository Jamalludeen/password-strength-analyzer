# Quick environment probe script for local troubleshooting.
import sys
import platform

# Keep this script dependency-free so it runs in minimal Python setups.
print('Python:', sys.version.split()[0])
print('Platform:', platform.platform())
