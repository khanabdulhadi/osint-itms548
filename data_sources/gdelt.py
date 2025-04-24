
import requests, logging, time, random
from typing import List, Dict
URL='https://api.gdeltproject.org/api/v2/doc/doc?query={q}&mode=artlist&format=json'

def _fetch(q):
    r=requests.get(URL.format(q=q),timeout=10,headers={'User-Agent':'osint-dashboard'})
    if r.status_code==429:
        raise RuntimeError('rate_limit')
    r.raise_for_status()
    return r.json().get('articles',[])

def search_articles(q:str)->List[Dict]:
    for i in range(3):
        try:
            return _fetch(q)[:100]
        except RuntimeError:
            wait=2*(i+1)+random.random()
            logging.warning('GDELT 429, retry in %.1fs', wait)
            time.sleep(wait)
        except Exception as e:
            logging.warning('GDELT error: %s', e); return []
    return []
