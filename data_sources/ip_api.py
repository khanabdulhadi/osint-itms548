import requests, logging
ENDPOINT='http://ip-api.com/json/{q}'

def lookup(q:str):
    try:
        r=requests.get(ENDPOINT.format(q=q),timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logging.warning('ip-api error: %s',e); return {}
