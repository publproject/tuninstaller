# ===============================================================================
#  Detail      : This is part from tuninstaller and used for serve webserver
#  License     : https://github.com/publproject/tuninstaller/blob/main/LICENSE
# ===============================================================================

from http.server import HTTPServer, SimpleHTTPRequestHandler
import os, sys

os.chdir("/etc/publproject/tuninstaller/webserver") # >> Set directory to /etc/publproject/tuninstaller/webserve
HTTP_Server_Config = HTTPServer(('0.0.0.0', 85), SimpleHTTPRequestHandler)
print("serving at port 0.0.0.0:85")
HTTP_Server_Config.serve_forever()
