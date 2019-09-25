#!/usr/bin/python

#
# Satellite API documentation is available at
# https://satsvr.xxx.xxx/apidoc/v2.html
#

import json
import sys
import time

try:
    import requests
except ImportError:
    print "Please install the python-requests module."
    sys.exit(-1)

from argparse import ArgumentParser

import getpass

########################################

def get_json(uname, pword, ssl, location):
    """
    Performs a GET using the passed URL location
    """

    r = requests.get(location, auth=(uname, pword), verify=ssl)

    return r.json()

########################################

def post_json(uname, pword, ssl, location, json_data):
    """
    Performs a POST and passes the data to the URL location
    """

    result = requests.post(
        location,
        data=json_data,
        auth=(uname, pword),
        verify=ssl,
        headers=POST_HEADERS)

    return result.json()

########################################

def pre_write(filed):
  filed.write("<!DOCTYPE html>\n")
  filed.write("<html>\n")

  filed.write("<head>\n")

  filed.write("<style>\n")

  filed.write("table {\n")
  filed.write("    font-family: arial, sans-serif;\n")
  filed.write("    border-collapse: collapse;\n")
  filed.write("    width: 100%;\n")
  filed.write("}\n")

  filed.write("td, th {\n")
  filed.write("    border: 1px solid #dddddd;\n")
  filed.write("    text-align: left;\n")
  filed.write("    padding: 8px;\n")
  filed.write("}\n")

  filed.write("tr:nth-child(even) {\n")
  filed.write("    background-color: #dddddd;\n")
  filed.write("}\n")

  filed.write("</style>\n")

  filed.write("</head>\n")

  filed.write("<body>\n")

  filed.write("<table>\n")

  filed.write("  <tr>\n")
  filed.write("    <th>Organization</th>\n")
  filed.write("    <th>Hostname</th>\n")
  filed.write("    <th>OS</th>\n")
  filed.write("    <th>Environment</th>\n")
  filed.write("    <th>Content View</th>\n")
  filed.write("    <th>Errata ID</th>\n")
  filed.write("    <th>Applicable</th>\n")
  filed.write("    <th>Installable</th>\n")
  filed.write("    <th>Installed</th>\n")
  filed.write("  </tr>\n")

########################################

def post_write(filed):
  filed.write("</table>\n")

  filed.write("</body>\n")

  filed.write("</html>\n")

########################################

def main():
    """
    Main routine that
      - Finds all organizations
      - For each organization
        - Find each host in the organization
        - For each host
          - Obtain list of applicable and installable errata from Satellite
            - Write list of applicable and installable errata
          - Read list of installed errata from a supplied file
            - Write list of installed errata
    """

    # Parse command line arguments

    parser = ArgumentParser()
    parser.add_argument("-s", "--satsvr", dest="satsvr", type=str, default="sat-520a.rhpds.opentlc.com", help="Satellite server to query")
    parser.add_argument("-u", "--user", dest="USERNAME", type=str, help="User name")
    parser.add_argument("-p", "--password", dest="PASSWORD", type=str, help="Password")
    parser.add_argument("--ssl", dest="SSL_VERIFY", default="False", type=str, help="Observe SSL errors - True or (default) False")
    parser.add_argument("-l", "--logdir", dest="LOGDIR", type=str, help="Log directory")
    parser.add_argument("-e", "--erratarepdir", dest="ERRATA_REPORTS_DIR", type=str, help="Directory containing host errata reports")
    args = parser.parse_args()

    # Prompt for username if needed

    if not args.USERNAME:
      username = raw_input("Username:  ")
    else:
      username = args.USERNAME

    # Prompt for password if needed

    if not args.PASSWORD:
      password = getpass.getpass()
    else:
      password = args.PASSWORD

    # Define SSL variable

    if args.SSL_VERIFY == "False":
      ssl_ver = False
    else:
      ssl_ver = True

    # Define the output file (if not specified, use stdout)

    if args.LOGDIR:
      logdir = args.LOGDIR
      filename = logdir + "/" + time.strftime("%m-%d-%Y") + "-patchreport.html"
      fileo = open(filename, 'w')
    else:
      fileo = sys.stdout

    # Define the directory containing all of the errata reports for each host

    if args.ERRATA_REPORTS_DIR:
      errata_reports_dir = args.ERRATA_REPORTS_DIR
    else:
      errata_reports_dir = "errata_reports"

    # Compose the URL to the Satellite 6 server

    URL = "https://" + args.satsvr + "/"

    # URL for the API to the Satellite 6 server

    #SAT_API = "%s/katello/api/v2/" % URL
    SAT_API = "%s/api/" % URL

    # Katello-specific API

    KATELLO_API = "%s/katello/api/" % URL
    POST_HEADERS = {'content-type': 'application/json'}

    # Write out the initial part of the HTML file

    pre_write(fileo)

    # Get the list of Organizations
    # API:  /katello/api/organizations

    orgs = get_json(username, password, ssl_ver, KATELLO_API + "organizations/")

    # Loop over all Organizations:Start

    for i_org in orgs['results']:

      # Get a list of hosts in the organization
      # API:  /api/hosts - this lists all hosts
      # API:  /api/organizations/:organization_id/hosts

      orghosts = get_json(username, password, ssl_ver, SAT_API + "organizations/" + str(i_org['id']) + "/hosts")
#      print(json.dumps(orghosts, indent=4))

      # Loop over all Hosts in an Organization:Start

      for i_orghost in orghosts['results']:
#        print(json.dumps(i_orghost, indent=4))
#        print("hostname = " + i_orghost['name'])
#        print("id = " + str(i_orghost['id']) )

        # Skip the host if it is not subscribed in Satellite

        host_subs = get_json(username, password, ssl_ver, SAT_API + "hosts/" + str(i_orghost['id']) + "/subscriptions")
        if not 'results' in host_subs:
          continue

        # Skip the host if it is not registered in Satellite

        if not ( i_orghost['subscription_facet_attributes']['registered_through'] ):
          continue

        errata = get_json(username, password, ssl_ver, KATELLO_API + "errata/?host_id=" + str(i_orghost['id']) + "&full_result=true")
        if len(errata['results']) > 0:
#          print("Have applicable or installable errata for host " + i_orghost['name'])
#          print(json.dumps(errata['results'], indent=4))

          # Loop over all Errata:Start

          for i_errata in errata['results']:
#            print(i_errata['type'])

            if (i_errata['hosts_applicable_count'] == 1):
              errata_applicable = "Yes"
            else:
              errata_applicable = "No"

            if (i_errata['hosts_available_count'] == 1):
              errata_installable = "Yes"
            else:
              errata_installable = "No"

            errata_installed = "No"

            fileo.write("  <tr>\n")
            fileo.write("    <td>{}</td>\n".format(i_org['name']) )
            fileo.write("    <td>{}</td>\n".format(i_orghost['name']) )
            fileo.write("    <td>{}</td>\n".format(i_orghost['operatingsystem_name']) )
            fileo.write("    <td>{}</td>\n".format(i_orghost['content_facet_attributes']['lifecycle_environment_name']) )
            fileo.write("    <td>{}</td>\n".format(i_orghost['content_facet_attributes']['content_view_name']) )
            fileo.write("    <td>{}</td>\n".format(i_errata['errata_id']) )
            fileo.write("    <td>{}</td>\n".format(errata_applicable) )
            fileo.write("    <td>{}</td>\n".format(errata_installable) )
            fileo.write("    <td>{}</td>\n".format(errata_installed) )
            fileo.write("  </tr>\n")

          # Loop over all Errata:End

        else:
#          print("No applicable or installable errata for host " + i_orghost['name'])

          errata_applicable = "NONE AVAILABLE"
          errata_installable = "NONE AVAILABLE"
          errata_installed = "-"

          fileo.write("  <tr>\n")
          fileo.write("    <td>{}</td>\n".format(i_org['name']) )
          fileo.write("    <td>{}</td>\n".format(i_orghost['name']) )
          fileo.write("    <td>{}</td>\n".format(i_orghost['operatingsystem_name']) )
          fileo.write("    <td>{}</td>\n".format(i_orghost['content_facet_attributes']['lifecycle_environment_name']) )
          fileo.write("    <td>{}</td>\n".format(i_orghost['content_facet_attributes']['content_view_name']) )
          fileo.write("    <td>{}</td>\n".format("-") )
          fileo.write("    <td>{}</td>\n".format(errata_applicable) )
          fileo.write("    <td>{}</td>\n".format(errata_installable) )
          fileo.write("    <td>{}</td>\n".format(errata_installed) )
          fileo.write("  </tr>\n")

        # Read list of installed errata
        #
        # This file will have been generated by running the Ansible playbook
        # that collects the list of installed errata.  Each line is of the form
        #
        # errata_name errata_type package
        #
        # Since an errata can update multiple packages, a dictionary is created
        # to generate a unique list of errata
        #
        # Note also that the errata file has some information at the beginning
        # and end that aren't actual errata.  For that reason, only lines
        # beginning with "RH" are considered.

        fname_installed_errata = errata_reports_dir + "/" + i_orghost['name']
        fd_installed_errata = None
        installed_errata = {}

        try:
          fd_installed_errata = open(fname_installed_errata, 'r')
        except IOError:
#          print("Cannot open file: " + fname_installed_errata)
          pass
        else:
          for i_installed in fd_installed_errata:
            if i_installed[:2] == "RH":
              errata_components = i_installed.split()
              installed_errata.update({ errata_components[0] : errata_components[1] })
          fd_installed_errata.close()

        # Write out the list of installed errata

        if installed_errata:
#          print("Writing out the list of installed errata for host " + i_orghost['name'])

          errata_applicable = "-"
          errata_installable = "-"
          errata_installed = "Yes"
          for (errata_name, errata_type) in installed_errata.items():
#            print(errata_name + " : " + errata_type)
            fileo.write("  <tr>\n")
            fileo.write("    <td>{}</td>\n".format(i_org['name']) )
            fileo.write("    <td>{}</td>\n".format(i_orghost['name']) )
            fileo.write("    <td>{}</td>\n".format(i_orghost['operatingsystem_name']) )
            fileo.write("    <td>{}</td>\n".format(i_orghost['content_facet_attributes']['lifecycle_environment_name']) )
            fileo.write("    <td>{}</td>\n".format(i_orghost['content_facet_attributes']['content_view_name']) )
            fileo.write("    <td>{}</td>\n".format(errata_name) )
            fileo.write("    <td>{}</td>\n".format(errata_applicable) )
            fileo.write("    <td>{}</td>\n".format(errata_installable) )
            fileo.write("    <td>{}</td>\n".format(errata_installed) )
            fileo.write("  </tr>\n")
        else:
#          print("No installed errata or installed errata not available for host " + i_orghost['name'])

          errata_applicable = "-"
          errata_installable = "-"
          errata_installed = "NOT AVAILABLE"
          fileo.write("  <tr>\n")
          fileo.write("    <td>{}</td>\n".format(i_org['name']) )
          fileo.write("    <td>{}</td>\n".format(i_orghost['name']) )
          fileo.write("    <td>{}</td>\n".format(i_orghost['operatingsystem_name']) )
          fileo.write("    <td>{}</td>\n".format(i_orghost['content_facet_attributes']['lifecycle_environment_name']) )
          fileo.write("    <td>{}</td>\n".format(i_orghost['content_facet_attributes']['content_view_name']) )
          fileo.write("    <td>{}</td>\n".format(i_errata['errata_id']) )
          fileo.write("    <td>{}</td>\n".format(errata_applicable) )
          fileo.write("    <td>{}</td>\n".format(errata_installable) )
          fileo.write("    <td>{}</td>\n".format(errata_installed) )
          fileo.write("  </tr>\n")

      # Loop over all Hosts in an Organization:End

    # Loop over all Organizations:End

    # Write out the final part of the HTML file

    post_write(fileo)

    # Close the file

    fileo.close()

    # Get a list of errata

#    errata = get_json(username, password, ssl_ver, KATELLO_API + "errata/")
#    print errata

########################################

if __name__ == "__main__":
    main()
