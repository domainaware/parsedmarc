=================
Splunk dashboards
=================

Setup guide
-----------

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
