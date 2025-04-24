
"""Hackertarget hostsearch -> crt.sh fallback"""
import requests, logging
from typing import List, Set

HT='https://api.hackertarget.com/hostsearch/?q={d}'
CRT='https://crt.sh/?q=%25{d}&output=json'

def _ht(d):
    r=requests.get(HT.format(d=d), timeout=10)
    r.raise_for_status()
    subs={line.split(',')[0].lower() for line in r.text.splitlines() if line}
    return [s for s in subs if s.endswith(d)]

def _crt(d):
    r=requests.get(CRT.format(d=d), timeout=15, headers={'User-Agent':'osint-dashboard'})
    r.raise_for_status()
    subs=set()
    for e in r.json():
        for part in e.get('name_value','').split('\n'):
            subs.add(part.lstrip('*.').lower())
    return [s for s in subs if s.endswith(d)]

def get_subdomains(domain:str)->List[str]:
    domain=domain.lower().strip()
    try:
        s=_ht(domain)
        if s: return sorted(s)
    except Exception as e:
        logging.warning('Hackertarget error: %s',e)
    try:
        return sorted(_crt(domain))
    except Exception as e:
        logging.warning('crt.sh error: %s',e); return []
