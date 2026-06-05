# Quick environment probe script for local troubleshooting.
import sys
import platform

print('Python:', sys.version.split()[0])
print('Platform:', platform.platform())
