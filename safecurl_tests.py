import safecurl
import sys

# Default
try:
    sc = safecurl.SafeCurl()
    res = sc.execute("https://fin1te.net")
except:
    print "Unexpected error:", sys.exc_info()

# options
try:
    sc = safecurl.SafeCurl()

    opt = safecurl.Options()
    opt.clearList("whitelist")
    opt.clearList("blacklist")
    opt.setList("whitelist", ["google.com", "youtube.com"], "domain")

    sc.setOptions(opt)
    res = sc.execute("http://www.youtube.com")
except:
    print "Unexpected error:", sys.exc_info()

# url
try:
    safeUrl = safecurl.Url.validateUrl("http://google.com", safecurl.Options())
except:
    print "Unexpected error:", sys.exc_info()

# redirects
try:
    sc = safecurl.SafeCurl()

    opt = safecurl.Options()
    opt.enableFollowLocation().setFollowLocationLimit(10)
    sc.setOptions(opt)

    res = sc.execute("http://fin1te.net")
except:
    print "Unexpected error:", sys.exc_info()
