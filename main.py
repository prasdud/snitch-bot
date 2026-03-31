'''
read packages.json (packageName: versionNumber)
hit https://api.osv.dev/v1/querybatch with content of packages.json 
if vulns returned -> slack alert
if nothing -> silence
'''
