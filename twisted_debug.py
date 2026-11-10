from twisted.scripts.twistd import run
import os
try:
    os.unlink('twistd.pid')
except OSError:
    pass
run()