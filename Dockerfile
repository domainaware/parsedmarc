FROM python:3.9-slim

WORKDIR /app
COPY parsedmarc/ parsedmarc/
COPY README.rst requirements.txt setup.py ./

RUN pip install -r requirements.txt
RUN python setup.py install

ENTRYPOINT ["parsedmarc"]
