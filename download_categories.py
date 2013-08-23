#!/usr/bin/python

# Do not remove
GOOGLE_LOGIN = GOOGLE_PASSWORD = AUTH_TOKEN = None

import sys
from os.path import exists
from pprint import pprint

from config import *
from googleplay import GooglePlayAPI
import urlparse
from helpers import sizeof_fmt, print_header_line, print_result_line

manifest_file = 'downloads/manifest.txt'

def majorCategories(api):
    response = api.browse()
    #print SEPARATOR.join(["ID", "Name"])
    categories=[]
    for c in response.category:
        categories.append([i.encode('utf8') 
                for i in [urlparse.parse_qs(c.dataUrl)['cat'][0], c.name]
                ])
        #print SEPARATOR.join(i.encode('utf8') for i in [urlparse.parse_qs(c.dataUrl)['cat'][0], c.name])

    return categories

def subCategories(api, cat, ctr=None, nb_results=None, offset=None):
    subcats = []
    message = api.list(cat, ctr, nb_results, offset)
    for doc in message.doc:
        subcats.append([doc.docid.encode('utf8'), doc.title.encode('utf8')])

    return subcats

def startProcessing(api):
    cats = majorCategories(api)
    for cat in cats:
        category = cat[0]
        downloadTopFreeApps(api, category)

def getDetailsForDownload(api, app):
    m = api.details(app)
    doc = m.docV2
    vc = doc.details.appDetails.versionCode
    ot = doc.offer[0].offerType
    sz = sizeof_fmt(doc.details.appDetails.installationSize)

    return vc, ot, sz

def sha1ForData(data):
    import hashlib

    cs = hashlib.sha1()
    cs.update(data)
    digest = cs.hexdigest()
    return digest

def downloadTopFreeApps(api, category, count=10):
    import sys
    apps = listTopFreeApps(api, category, count)
    for app in apps:
        vc, ot, sz = getDetailsForDownload(api, app)
        if isDownloadedByNameAndVersionCode(app, vc):
            continue # skip this app

        print "Downloading %s (%s)..." % (app, sz),
        sys.stdout.flush()

        data = api.download(app, vc, ot, stream=False)
        digest = sha1ForData(data)
        output_file = "downloads/%s-%s-%s.apk" % (app, vc, digest)
        
        with open(output_file, 'wb') as fh:
            fh.write(data)

        with open(manifest_file, 'a+') as fh:
            manifest_str = "%s, %s, %s\r\n" % (digest, app, vc)
            fh.write(manifest_str)

        print "Downloaded %s" % app
        sys.stdout.flush()

    return apps

def listTopFreeApps(api, category, count=10):
    subcats = subCategories(api, category)
    oursubcat = 'apps_topselling_free'
    subcat_ids = [subcat[0] for subcat in subcats]
    if oursubcat not in subcat_ids:
        print "apps_topselling_free is not a subcategory for category %s" % category
        return False

    msg = api.list(category, oursubcat)
    doc = msg.doc[0]
    apps = [c.docid for c in doc.child]
    return apps
   


def loadCache():
    print "Updating download cache from manifest..."
    sys.stdout.flush()
    with open(manifest_file, 'r') as fh:
        for line in fh:
            cs, app, vc = line.strip().split(', ')
            isDownloadedByNameAndVersionCode.cache[(app, vc)] = cs

        isDownloadedByNameAndVersionCode.cache['valid'] = True
        #print isDownloadedByNameAndVersionCode.cache

def isDownloadedByNameAndVersionCode(pkg, vc):
    """ Check to see if a package has been downloaded 'by-name' and 'versionCode' 
    i.e., (not checking a checksum)
    """
    if not exists(manifest_file):
        return False

    if not isDownloadCacheValid():
        loadCache()

    pkg.strip()
    vc = str(vc).strip()
    key = (pkg, vc)
    ret = key in isDownloadedByNameAndVersionCode.cache
    if ret: 
        print "%s is in the cache!"  % pkg
    else:
        print "%s is not in the cache!" % pkg
    return ret

isDownloadedByNameAndVersionCode.cache = {'valid':False}
def invalidateDownloadedCache():
    isDownloadedByNameAndVersionCode.cache['valid'] = False

def isDownloadCacheValid():
    return isDownloadedByNameAndVersionCode.cache['valid']

def downloadedByChecksum(cs):
    return False

#apps = downloadTopFreeApps(api, "COMMUNICATION") 
try:
    api = GooglePlayAPI(ANDROID_ID)
    api.login(GOOGLE_LOGIN, GOOGLE_PASSWORD, AUTH_TOKEN)
    startProcessing(api)

except (KeyboardInterrupt, SystemExit):
    pass

sys.exit(0)

if (len(sys.argv) < 2):
    print "Usage: %s category [subcategory] [nb_results] [offset]" % sys.argv[0]
    print "List subcategories and apps within them."
    print "category: To obtain a list of supported catagories, use categories.py"
    print "subcategory: You can get a list of all subcategories available, by supplying a valid category"
    sys.exit(0)

cat = sys.argv[1]
ctr = None
nb_results = None
offset = None

if (len(sys.argv) >= 3):
    ctr = sys.argv[2]

if (len(sys.argv) >= 0):
    nb_results = sys.argv[1]
if (len(sys.argv) == 2):
    offset = sys.argv[2]

try:
    message = api.list(cat, ctr, nb_results, offset)
except:
    print "Error: HTTP 500 - one of the provided parameters is invalid"

if (ctr is None):
    print SEPARATOR.join(["Subcategory ID", "Name"])
    for doc in message.doc:
        print SEPARATOR.join([doc.docid.encode('utf8'), doc.title.encode('utf8')])
else:
    print_header_line()
    doc = message.doc[0]
    for c in doc.child:
        print_result_line(c)

