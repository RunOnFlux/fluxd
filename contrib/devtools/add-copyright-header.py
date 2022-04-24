#!/usr/bin/env python
'''
Run this script inside of src/ and it will look for all the files
that do not have a Copyright message for "The Flux Developers" and
if there is one for The Zel or Bitcoin it will put Flux after that.
If no known copyright header is found it will be flagged for manual
intervention.

It will do this for all the files in the folder and its children.

Author: @gubatron
Modified: @w2vy from fix-copyright-headers.py
'''
import os
import time

year = time.gmtime()[0]
last_year = year - 1
command = "perl -pi -e 's/%s The Bitcoin/%s The Bitcoin/' %s"
listFilesCommand = "find . | grep %s"

extensions = [".cpp",".h"]

FluxDevs = "The Flux Developers"
ZelDevs = "The Zel developers"
ZelCDevs = "The Zelcash Core developers"
BitDevs = "The Bitcoin developers"
BitcDevs = "The Bitcoin Core developers"

def getLastGitModifiedDate(filePath):
  gitGetLastCommitDateCommand = "git log " + filePath +" | grep Date | head -n 1"
  p = os.popen(gitGetLastCommitDateCommand)
  result = ""
  for l in p:
    result = l
    break
  result = result.replace("\n","")
  return result

n=1
c=0
for extension in extensions:
  foundFiles = os.popen(listFilesCommand % extension)
  for filePath in foundFiles:
    filePath = filePath[1:-1]
    if filePath.endswith(extension):
      filePath = os.getcwd() + filePath
      f = open(filePath, 'r')
      datafile = f.readlines()
      f.close()
      flux = -1
      other = -1
      l = 0
      for line in datafile:
        if FluxDevs in line:
          flux = l
        if BitDevs in line or BitcDevs in line or ZelDevs in line or ZelCDevs in line:
          other = l
        l = l + 1
      if flux == -1:
        print(FluxDevs," not found in ", filePath)
        if other == -1:
          print("No known Copyright found in ", filePath)
        else:
          #print("Last Copyright: ", datafile[other])
          #print("Next line     : ", datafile[other+1])
          #print(" ")
          datafile.insert(other+1, "// Copyright (C) 2018-2022 The Flux Developers\n")
          f = open(filePath, 'w')
          f.writelines(datafile)
          f.close()
          #print(datafile[other])
          #print(datafile[other+1])
          #print(datafile[other+2])
          c = c + 1
      n = n + 1
print("There were ", n, " files examined and ", c, " files modified")


