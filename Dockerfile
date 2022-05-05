FROM python:3.9-slim

WORKDIR /app
COPY parsedmarc/ parsedmarc/
COPY README.rst setup.py ./

RUN python setup.py install

ENTRYPOINT ["parsedmarc"]
