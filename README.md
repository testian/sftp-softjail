# sftp-softjail
A patch to OpenSSH 6.8p1 to jail clients into directories without chroot

## WARNING
1. This patch is vulnerable to symlink race attacks. Do only use it in combination with "-P symlink" and only on jail directories that do not contain any symbolic links
- or alternatively using "-R" (read-only) in which case you it is theoretically safe to place symbolic links inside the jail directory.
This patch emulates a chroot-style jail without making use of the chroot()-syscall. To achieve this it implements a userspace-version of realpath() which is then used by alternative versions of syscalls like open() before actually opening the file.
There is, however, no way to disable the kernel-mode symbolic link resolution entirely (O_NOFOLLOW only works for the last component of the path).
This can be exploited by replacing a file or directory that is part of the internally resolved path with a symbolic link right after the internal version of realpath() has been called and right before it is accessed with the alternative version of the syscall (e.g. open()). There are also attacks possible during the resolution of realpath() but they would probably only expose the contents of symbolic links outside the jail in the worst case.
2. This patch is EXPERIMENTAL. In the current state this patch is unreviewed and untested. The patch has been written by a person who writes C once a decade.

## Usage
My personal setup is as follows
In ~/.ssh/authorized_keys I have an entry like

command="/home/user/sftp-server",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-rsa ...

where /home/user/sftp-server is a wrapper around the sftp-server binary, e.g.

#!/bin/bash
/home/user/openssh/sftp-server -P symlink -j /home/user/jail

You may evaluate SSH_ORIGINAL_COMMAND to decide if the user should get a sftp-session or a (restricted) shell.
