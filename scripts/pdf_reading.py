"""Bounded OCR on the cloud updater, never on the visitor PC. mofu © 2026."""
import datetime as dt, pathlib, shutil, subprocess, tempfile
from source_summary import extract, normalized

def run(cache,state,checked_at,max_documents=1):
 entries=state.setdefault('entries',{})
 now=dt.datetime.fromisoformat(checked_at).timestamp();jobs=[];reports=[]
 available=bool(shutil.which('pdftoppm') and shutil.which('tesseract'))
 for source,doc in cache.items():
  if not doc.get('pdfBytes') or doc.get('pdfProtected'):continue
  old=entries.get(source,{})
  if old.get('hash')==doc.get('hash') and now<float(old.get('retryAfter',0)):
   reports.append(old);continue
  jobs.append((old.get('checkedAt',''),source,doc))
 for _,source,doc in sorted(jobs,key=lambda x:(x[0],x[1]))[:max_documents]:
  result={'source':source,'hash':doc['hash'],'checkedAt':checked_at,'state':'pending','passages':[],'retryAfter':now+86400}
  if not available:result['state']='ocr_tools_not_available'
  elif not 1<=doc.get('pdfPages',0)<=4:result['state']='page_limit_requires_review'
  else:
   try:
    with tempfile.TemporaryDirectory(prefix='mofu-official-pdf-') as temporary:
     folder=pathlib.Path(temporary);pdf=folder/'source.pdf';pdf.write_bytes(doc['pdfBytes'])
     subprocess.run(['pdftoppm','-r','120','-scale-to','1600','-png',str(pdf),str(folder/'page')],check=True,timeout=20,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
     images=sorted(folder.glob('page-*.png'))
     if len(images)!=doc['pdfPages']:raise ValueError('Incomplete rasterization')
     texts=[]
     for image in images:
      output=subprocess.run(['tesseract',str(image),'stdout','-l','jpn+eng','--psm','3'],check=True,timeout=12,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
      texts.append(output.stdout.decode('utf-8'))
     body='\n'.join(texts)
     if not 100<=len(normalized(body))<=40_000:raise ValueError('Unreadable OCR')
     passages=extract(body,source,checked_at,doc['hash'])['passages']
     result.update(state='ocr_requires_human_review',passages=passages)
   except Exception:result['state']='ocr_read_failed'
  entries[source]=result;reports.append(result)
 for _,source,doc in jobs[max_documents:]:
  reports.append(entries.get(source) or {'source':source,'state':'deferred','passages':[]})
 return {'toolsAvailable':available,'attempted':min(max_documents,len(jobs)),
         'requiresReview':sum(x['state']=='ocr_requires_human_review' for x in reports)},reports
