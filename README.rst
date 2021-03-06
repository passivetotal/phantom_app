RiskIQ's PassiveTotal Phantom App
=================================

Introduction
------------

*Phantom application for PassiveTotal*

RiskIQ's PassiveTotal Phantom application brings the data from Internet-scanning directly inside of the Phantom platform. Using a combination of actions or playbooks, Phantom users can chain together a number of different datasets in order to automate analysis or aspects of incident response. At the time of release, this application supports the following datasets:

- Passive DNS
- WHOIS
- Host Pairs
- Trackers
- Metadata
- OSINT
- Intelligence
- SSL Certificates

Supported Actions
-----------------

Phantom attempts to reduce the total number of actions shown to a user. In order to maximize the amount of data from RiskIQ's PassiveTotal, we chose to create subtasks within each action. Each of the top-level actions can be found within the "investigate" section and will prompt you for a query value and subtask selection.

- get ip info
 - metadata_ip : Metadata for the IP address
 - passive_dns : Passive DNS records
 - ssl_certificate_history : SSL certificate history
- get domain info
 - metadata_domain : Metadata for the domain
 - passive_dns : Passive DNS records
 - find_subdomains : Get subdomains for the domain
 - host_pairs : Get parent and child hosts
 - analytical_trackers : Get listing of analytics trackers
- whois domain : Show the WHOIS contents
- whois ip : Show the WHOIS contents
- hunt ip
 - check_blacklist : Check the RiskIQ blacklist
 - check_osint : Check the PassiveTotal OSINT repository
- hunt domain
 - check_blacklist : Check the RiskIQ blacklist
 - check_osint : Check the PassiveTotal OSINT repository
- ip reputation
 - check_blacklist : Check the RiskIQ blacklist
 - check_osint : Check the PassiveTotal OSINT repository
- domain reputation
 - check_blacklist : Check the RiskIQ blacklist
 - check_osint : Check the PassiveTotal OSINT repository

Manual Installation (command line)
----------------------------------

*You must be part of the Phantom (https://www.phantom.us/) community and have a virtual appliance in order to run this app.*

It is recommended to use the application that ships with the Phantom appliance. However, if you would like to install directly from this source, you can do so using the following steps.

1. Download the latest Phantom virtual appliance, SSH to the command line and clone this repository.

2. Install the requirements for the app::

    $ pip install -r requirements.txt

3. From within the "passivetotal" folder, compile the app::

    $ ../compile_app.py -id

4. Restart the HTTPD server::

    $ sudo service httpd restart
    
Manual Installation (app upload)
--------------------------------

1. Download the latest Phantom virtual appliance, SSH to the command line and clone this repository.

2. Install the requirements for the app::

    $ pip install -r requirements.txt

3. Visit Administration within the Phantom portal and click "+ App"

4. Select the "passivetotal.tgz" file

5. Visit "Assets" within the Phantom portal and click "+ Asset"

6. Create a new asset for PassiveTotal

7. Obtain your username (email) and API key from PassiveTotal settings (https://www.passivetotal.org/account_settings)


Support
-------

This application come with no support and is only provided as a convenience. Our preferred method for accessing this application is using the Phantom hub. Any questions, issues or problems should be directed to Github issues for the fastest triage.


Bug Reporting
-------------

Please use the issues feature of Github to report any problems with the transforms and we will work to triage any of the issues.
