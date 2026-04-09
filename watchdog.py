'''
watchdog
watches over repositories PR
especially the packages.json and lockfiles and runs the same loop
main.py runs as cron, this only triggers on commits on PR

add it to a repo
init lock files
store that in cache
For a PR, on every new commit, run a action
if checksum(old_lockfile) != checksum(new_lockfile):
    run the loop
    report vulns as a comment
    update cache
else
    pass

'''

