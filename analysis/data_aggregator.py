
import json, pandas as pd, pathlib, datetime

def _flatten_ip(d): return pd.DataFrame([d])

def _domain_df(subs, root): return pd.DataFrame({'subdomain':subs,'root':root})

def _gdelt_df(arts):
    keep=('title','domain','url','seendate','language')
    return pd.DataFrame([{k:a.get(k) for k in keep} for a in arts])

def _wikidata_df(ents):
    return pd.DataFrame({'id':[e['id'] for e in ents],
                         'label':[e['label'] for e in ents],
                         'description':[e.get('description','') for e in ents],
                         'url':[e['concepturi'] for e in ents]})

def _urlscan_df(scans):
    rows=[{'domain':s.get('page',{}).get('domain',''),
           'ip':s.get('page',{}).get('ip',''),
           'ptr':s.get('page',{}).get('ptr',''),
           'asn':s.get('page',{}).get('asn',''),
           'asnname':s.get('page',{}).get('asnname',''),
           'url':s.get('page',{}).get('url','')} for s in scans]
    return pd.DataFrame(rows)

def save_csv(report, out_dir=None):
    if out_dir is None:
        out_dir=pathlib.Path('reports')/f"run_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    out_dir.mkdir(parents=True, exist_ok=True)
    if (ip:=report.get('ip')): _flatten_ip(ip).to_csv(out_dir/'ip.csv', index=False)
    if (scans := report.get('urlscan')): _urlscan_df(scans).to_csv(out_dir/'urlscan.csv', index=False)
    if (subs:=report.get('domain',{}).get('subdomains')):
        root=subs[0].split('.',1)[-1] if subs else ''
        _domain_df(subs, root).to_csv(out_dir/'domain.csv', index=False)
    kw=report.get('keyword',{})
    if kw:
        if kw.get('gdelt'): _gdelt_df(kw['gdelt']).to_csv(out_dir/'gdelt.csv', index=False)
        if kw.get('wikidata'): _wikidata_df(kw['wikidata']).to_csv(out_dir/'wikidata.csv', index=False)

    return out_dir
