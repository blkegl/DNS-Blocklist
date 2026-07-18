#!/usr/bin/env python3
# Domain Aggregator
# Supports plain domain lists and hosts files.
import os,re,requests
INPUT_FILE="url.txt";OUTPUT_FILE="domains.txt";TIMEOUT=30;USER_AGENT="Mozilla/5.0"
DOMAIN_REGEX=re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",re.I)
SKIP={"localhost","localhost.localdomain","broadcasthost","local"}
HOSTS={"0.0.0.0","127.0.0.1","::1","::","255.255.255.255"}
def fmt(n):
 u=["B","KB","MB","GB"]
 for x in u:
  if n<1024 or x=="GB": return f"{int(n)} B" if x=="B" else f"{n:.2f} {x}"
  n/=1024
def valid(d):
 if not d:return None
 d=d.strip(".").lower()
 if d in SKIP:return None
 try:
  if any(ord(c)>127 for c in d): d=d.encode("idna").decode("ascii")
 except: return None
 return d if DOMAIN_REGEX.fullmatch(d) else None
def extract(line):
 line=line.split("#",1)[0].strip().lower()
 if not line:return None
 p=line.split()
 if not p:return None
 return (p[1] if p[0] in HOSTS and len(p)>1 else p[0]).strip(".")
def filt(domains):
 s=domains;out=[]
 for d in s:
  k=True;pos=d.find(".")
  while pos!=-1:
   if d[pos+1:] in s: k=False;break
   pos=d.find(".",pos+1)
  if k: out.append(d)
 return sorted(out)
def main():
 urls=[]
 with open(INPUT_FILE,encoding="utf-8") as f:
  urls=list(dict.fromkeys(l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")))
 sess=requests.Session();sess.headers.update({"User-Agent":USER_AGENT})
 g=set();metrics=[];raw=0;ok=0
 for i,u in enumerate(urls,1):
  print(f"[{i}/{len(urls)}] Fetching: {u}")
  try:
   with sess.get(u,stream=True,timeout=TIMEOUT) as r:
    r.raise_for_status();sz=int(r.headers.get("Content-Length","0") or 0);fb=0;uniq=set();cnt=0
    for b in r.iter_lines():
      if not sz: fb+=len(b)+1
      d=valid(extract(b.decode("utf-8","ignore")))
      if d: cnt+=1;uniq.add(d);g.add(d)
    metrics.append((u,sz or fb,len(uniq)));raw+=cnt;ok+=1
  except Exception as e: print("ERROR",e)
 metrics.sort(key=lambda x:x[2],reverse=True)
 clean=filt(g)
 with open(OUTPUT_FILE,"w") as f:
  f.write("\n".join(clean)+"\n")
 print("="*50);print(" INDIVIDUAL SOURCE METRICS REPORT");print("="*50)
 for u,s,c in metrics:
  print(f"Source: {u}\n  └─ File Size: {fmt(s)}\n  └─ Unique Valid Domains: {c:,}\n")
 print("="*50)
 print(f"[INFO] Downloaded sources: {ok}")
 print(f"[INFO] Raw domains processed: {raw:,}")
 print(f"[INFO] Global unique valid domains: {len(g):,}")
 print(f"[INFO] Global duplicates/invalid removed: {raw-len(g):,}")
 print(f"[INFO] After subdomain removal: {len(clean):,}")
 print(f"[INFO] Subdomains removed: {len(g)-len(clean):,}")
if __name__=="__main__": main()
