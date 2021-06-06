===================
Splunk Installation
===================

Install Splunk for use with Docker
----------------------------------

Download latest Splunk image::

  docker pull splunk/splunk:latest

Run Splunk with Docker
----------------------

Listen on all network interfaces::

  docker run -d -p 8000:8000 -p 8088:8088 -e "SPLUNK_START_ARGS=--accept-license" -e "SPLUNK_PASSWORD=password1234" -e "SPLUNK_HEC_TOKEN=hec-token-1234" --name splunk splunk/splunk:latest

Listen on localhost for use with reverse proxy with base URL ``/splunk``::

  docker run -d -p 127.0.0.1:8000:8000 -p 127.0.0.1:8088:8088 -e "SPLUNK_START_ARGS=--accept-license" -e "SPLUNK_PASSWORD=password1234" -e "SPLUNK_HEC_TOKEN=hec-token-1234" -e "SPLUNK_ROOT_ENDPOINT=/splunk" --name splunk splunk/splunk:latest

Set up reverse proxy, e.g. Apache2::

  ProxyPass /splunk http://127.0.0.1:8000/splunk
  ProxyPassReverse /splunk http://127.0.0.1:8000/splunk

Splunk Configuration
--------------------

Access web UI at http://127.0.0.1:8000 and log in with ``admin:password1234``.

Create App and Index
~~~~~~~~~~~~~~~~~~~~

- Settings > Data > Indexes: New Index

  - Index name: "email"

- HEC token ``hec-token-1234`` should be already set up. 

  - Check under Settings > Data > Data inputs: HTTP Event Collector

- Apps > Manage Apps: Create app

  - Name: "parsedmarc"
  - Folder name: "parsedmarc"

Create Dashboards
~~~~~~~~~~~~~~~~~

1. Navigate to the app you want to add the dashboards to, or create a new app called DMARC
2. Click Dashboards
3. Click Create New Dashboard
4. Use a descriptive title, such as "Aggregate DMARC Data"
5. Click Create Dashboard
6. Click on the Source button
7. Paste the content of ''dmarc_aggregate_dashboard.xml`` into the source editor
8. If the index storing the DMARC data is not named email, replace index="email" accordingly
9. Click Save
10. Click Dashboards
11. Click Create New Dashboard
12. Use a descriptive title, such as "Forensic DMARC Data"
13. Click Create Dashboard
14. Click on the Source button
15. Paste the content of ''dmarc_forensic_dashboard.xml`` into the source editor
16. If the index storing the DMARC data is not named email, replace index="email" accordingly
17. Click Save

==============
Example Config 
==============

parsedmarc.ini::

  [splunk_hec]
  url = https://127.0.0.1:8088/
  token = hec-token-1234
  index = email
  skip_certificate_verification = True

Note that ``skip_certificate_verification = True`` disables security checks.

Run parsedmarc::

  python3 -m parsedmarc.cli -c parsedmarc.ini
  
