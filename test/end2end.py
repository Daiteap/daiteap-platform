import daiteaptest
import requests
import time

session, url = daiteaptest.initConfig()
if url is None:
    print("URL is not configured")
    exit(-1)
error = False
success, cluster_ids = daiteaptest.createFromTemplates(session, url)
if success == False:
    print("Error in createFromTemplates(), deleting resources anyway...")
    daiteaptest.deleteResources(session, url, cluster_ids)
    exit(-1)

if daiteaptest.getEndStatus(session, url, cluster_ids) == False:
    error = True
    exit(-1)

time.sleep(1)
if daiteaptest.deleteResources(session, url, cluster_ids) == False:
    error = True
    exit(-1)

if error:
    exit(-1)

exit(0)