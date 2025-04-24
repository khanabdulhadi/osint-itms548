import requests, logging
API='https://www.wikidata.org/w/api.php'

def entity_search(term:str):
    params={'action':'wbsearchentities','search':term,'language':'en','limit':10,'format':'json'}
    try:
        r=requests.get(API,params=params,timeout=10)
        r.raise_for_status()
        return r.json().get('search',[])
    except Exception as e:
        logging.warning('Wikidata error: %s',e); return []
