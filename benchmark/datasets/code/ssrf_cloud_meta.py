import urllib.request

def fetch_instance_metadata():
    # Direct probe of cloud metadata IP
    target_url = "http://169.254.169.254/latest/meta-data/"
    return urllib.request.urlopen(target_url).read()
