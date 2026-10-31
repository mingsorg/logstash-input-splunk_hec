"""Packaged equivalent of the current indexer's native-CLI bootstrap; not run by inspection."""
import os
from configure import configure
from splunk_bootstrap import start, supervise

home, app = configure('indexer', '/opt/splunk')
supervise(start(home, os.environ['SPLUNK_PASSWORD']), home)
