import hashlib,json,os,pathlib,stat
paths=list(pathlib.Path(os.environ['RUNNER_TEMP']).glob('dw-php-setup-*/receipt.json'))
assert len(paths)==1,'Missing or ambiguous original setup receipt'
path=paths[0]
metadata=path.lstat()
assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid==os.getuid() and metadata.st_size<=65536
raw=path.read_bytes();report=json.loads(raw)
allowed=('schema','outcome','stage','host','image','apt','ca_sha256','setup_php_commit','source_hashes','installer','archive','installed','configured','tools','failure_type','cause_type','http_status','errno','verify_code','verify_message','returncode','reason')
result={key:report[key] for key in allowed if key in report}
result['receipt_sha256']=hashlib.sha256(raw).hexdigest()
result['source']='25314d6efb576004570e15954915fff2a9a11c60'
text=json.dumps(result,sort_keys=True)
assert len(text.encode())<=65536
print(text)
with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as summary:
    summary.write('Original bound setup receipt\n\n'+text+'\n')
