'''
read packages.json (packageName: versionNumber)
hit https://api.osv.dev/v1/querybatch with content of packages.json get vuln ids
fetch each id -> get full details
derive severity
find safe version (first version before affected range)
slack: package, severity, affected versions, recommended action
'''
