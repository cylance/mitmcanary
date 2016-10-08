# mitmcanary
Tool/service to detect Man in the Middle attacks with Canary Requests

Temporary setup docs:
In order to run the service, you must first go into the "service" directory and run "python setup_test_persistence.py" which trains a variety of testing canary requests. If you want to modify the canary requests, modify this file. This will create a persist.json, which stores the configuration for the service.

Then run python main.py (still in the service directory) to start the service.

In another terminal, return to the root directory of the git repo, and run python main.py to start the UI. The UI does not need to be running for the service to work, and alerts are stored, so restarting the UI will bring the alerts back.

Talks
======
This tool was presented at VirusBulletin 2016 in Denver. The slides for that talk are available here:
https://www.virusbulletin.com/uploads/pdf/conference_slides/2016/Wallace-vb-2016-detecting-mitm-canary.pdf

Demos
=====
MITMCanary vs MITMf:
https://www.youtube.com/watch?v=fDbQMk5OMZw

MITMCanary vs Responder:
https://www.youtube.com/watch?v=d8oWPesBFUY

MITMCanary vs Zarp + MITMProxy:
https://www.youtube.com/watch?v=vEPU3FICqEw
