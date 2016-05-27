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

Manual Installation
-------------------

*You must be part of the Phantom_ community and have a virtual appliance in order to run this app.*

.. _Phantom: https://www.phantom.us/

It is recommended to use the application that ships with the Phantom appliance. However, if you would like to install directly from this source, you can do so using the following steps.

1. Download the latest Phantom virtual appliance, SSH to the command line and clone this repository.

2. Install the requirements for the app::

    $ pip install -r requirements.txt

3. From within the "passivetotal" folder, compile the app::

    $ ../compile_app.py -id

4. Restart the HTTPD server::

    $ sudo service httpd restart

Support
-------

This application come with no support and is only provided as a convenience. Our preferred method for accessing this application is using the Phantom hub. Any questions, issues or problems should be directed to Github issues for the fastest triage.


Bug Reporting
-------------

Please use the issues feature of Github to report any problems with the transforms and we will work to triage any of the issues.
