import os
import subprocess
import sys

def check_and_elevate():
    if os.geteuid() != 0:
        print("Elevating privileges...")
        subprocess.call(['sudo', 'python3'] + sys.argv)
        sys.exit()

def drop_privileges(uid_name='nobody'):
    if os.getuid() != 0:
        # Already running as non-root
        return
    try:
        import pwd
        pw_record = pwd.getpwnam(uid_name)
        uid = pw_record.pw_uid
        gid = pw_record.pw_gid
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        os.umask(0o077)
    except Exception as e:
        print(f"Failed to drop privileges: {e}")
        sys.exit(1)
