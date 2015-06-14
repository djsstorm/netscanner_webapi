#!/usr/bin/env python
# -*- coding: utf-8 -*-

from libnmap.process import NmapProcess


def mycallback(nmaptask):
    nmaptask = nmap_proc.current_task
    if nmaptask:
        print("Task {0} ({1}): ETC: {2} DONE: {3}%".format(nmaptask.name,
                                                           nmaptask.status,
                                                           nmaptask.etc,
                                                           nmaptask.progress))

nmap_proc = NmapProcess(targets="10.0.0.15",
                        options="-sV",
                        event_callback=mycallback)
nmap_proc.run()
print(nmap_proc.stdout)
print(nmap_proc.stderr)
