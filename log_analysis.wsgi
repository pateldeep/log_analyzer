import sys
sys.stdout = sys.stderr
sys.path.insert(0, '/home/cstoolweb/cstool-portal/wsgi-scripts/log_analyzer')
from log_analysis_server import app as application
