#!/usr/bin/env python3

# Copyright (c) 2019, Richard Hughes All rights reserved.
# Released under the BSD license. Please see LICENSE.md for more information.

import sys
import os
import argparse
import glob
import xml.dom.minidom
import re

# Define command line arguments
parms=argparse.ArgumentParser()
parms.add_argument("-f", "--file", type=str, required=False, default="*.nessus", help="Specify input file(s)")
parms.add_argument("-c", "--case_sensitive", required=False, action="store_true", help="Case sensitive search")
parms.add_argument("-d", "--debug", required=False, action="store_true", help="Debug output")
parms.add_argument("-o", "--output", type=str, required=False, default="xml_min", choices=['xml','xml_min','ipv4',"mac","mac+ipv4","ports","script"], help="Specify output format")
parms.add_argument("-p", "--path", type=str, required=False, default=".", help="Specify location of file(s)")
parms.add_argument("-r", "--regex", type=str, required=True, help="Search expression")

args = vars(parms.parse_args())

# Globals
errorsexist = False

# Main processing
def main(args):
  # If output format is XML then add root element
  if args['output'] == "xml":
    print("<NessusClientData_v2>")

  # Generate list of files and pass for processing
  for file in glob.glob(args['path'] + "/" + args['file']):
    # Process file if it is not empty
    if os.path.getsize(file) > 0:
      procFile(file)

  # If output format is XML then close root element
  if args['output'] == "xml":
    print("</NessusClientData_v2>")

  if(not args['debug'] and errorsexist): print("\nWARNING: Run with -d to see files that could not be processed", file=sys.stderr)


# Process file
def procFile(file):

  global errorsexist

  # Parse XML file
  try:
    doc=xml.dom.minidom.parse(file)
    # Verify this is an Nmap output file
    if doc.getElementsByTagName("NessusClientData_v2"):
      # Compile regular expression
      if not args['case_sensitive']:
        regexp = re.compile(args['regex'], re.IGNORECASE)
      else:
        regexp = re.compile(args['regex'])
      procDocument(doc,regexp)
    else:
      if args['debug']: print("WARNING: " + file + " is not a valid Nmap output file", file=sys.stderr)
      errorsexist=True
  except:
    if args['debug']: print("WARNING: Unable to parse " + file, file=sys.stderr)
    errorsexist=True


# Process document
def procDocument(doc,regexp):
  # Extract hosts
  hosts=doc.getElementsByTagName("ReportHost")
  for host in hosts:

    # Check for regular expression match
    if regexp.search(host.toxml()):

      # Get host tags
      tags=host.getElementsByTagName("tag")
      addr_ipv4=""
      addr_mac=""
      hostname=""
      for tag in tags:
        tagname=tag.getAttribute("name")
        tagvalue=tag.firstChild.data
        if tagname == "host-ip": addr_ipv4 = tagvalue
        if tagname == "host-fqdn": hostname = tagvalue

      # Output minimal XML
      if args['output'] == "xml_min":
        hostxml=host.toxml()
        for m in regexp.finditer(hostxml):
          idxStart = m.start(0)
          idxStart = hostxml.rfind("<", 0, idxStart)
          idxEnd = m.end(0)
          print("")
          print("Host-FQDN: " + hostname)
          print("Host-Addr: " + addr_ipv4)
          print("")
          print(hostxml[idxStart:idxEnd])

      # Output XML
      elif args['output'] == "xml":
        print(host.toxml())

      # Output addresses
      if args['output'] == "ipv4" and addr_ipv4 != "": print(addr_ipv4)
      if args['output'] == "mac" and addr_mac != "": print(addr_mac)
      if args['output'] == "mac+ipv4" and addr_ipv4 != "": print(addr_mac + "|" + addr_ipv4)

      # Output port list
      if args['output'] == "ports":
        ssl_list = []
        out_list = []
        items=host.getElementsByTagName("ReportItem")

        # Discover which ports have SSL/TLS
        for item in items:
          portid=item.getAttribute("port")
          plugin=item.getAttribute("pluginName")
          if plugin == "SSL / TLS Versions Supported":
            if portid not in ssl_list:
              ssl_list.append(portid)

        # Get port details from ReportItem elements
        for item in items:
          portid=item.getAttribute("port")
          name=item.getAttribute("svc_name")
          if name == "www": name = "http"
          tunnel=""
          if portid in ssl_list:
            tunnel="ssl"
          if name == "http" and tunnel == "ssl":
            name = "https"

          # Regex must be found in portid or service name
          if(regexp.search(portid) or regexp.search(name)):
            if portid not in out_list:
              print(addr_ipv4+"|"+portid+"|"+name+"|"+tunnel+"|open")
              out_list.append(portid)

      # Output script output
      if args['output'] == "script":
        items=host.getElementsByTagName("ReportItem")
        for item in items:
          portid=item.getAttribute("port")
          scripts=item.getElementsByTagName("plugin_output")
          for script in scripts:
            if regexp.search(script.toxml()):
              print("")
              print("Host-FQDN: " + hostname + ":" + portid)
              print("Host-Addr: " + addr_ipv4 + ":" + portid)
              print(script.firstChild.data)


if __name__ == '__main__':
  # Execute main method
  main(args)
