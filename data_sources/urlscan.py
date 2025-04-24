
import requests, logging, time, random
URL='https://urlscan.io/api/v1/search/?q={q}'

def _fetch(q):
    r=requests.get(URL.format(q=q),timeout=20,headers={'User-Agent':'osint-dashboard'})
    r.raise_for_status()
    return r.json().get('results',[])

def search(q:str):
    for i in range(3):
        try:
            return _fetch(q)
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            wait=3*(i+1)+random.random()
            logging.warning('urlscan timeout, retry in %.1fs', wait)
            time.sleep(wait)
        except Exception as e:
            logging.warning('urlscan error: %s', e); return []
    return []
