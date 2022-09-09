FROM python:3.9-slim

WORKDIR /app
COPY parsedmarc/ parsedmarc/
COPY README.md pyproject.toml requirements.txt ./

RUN pip install -r requirements.txt
RUN hatch build
RUN pip install dist/*.whl

ENTRYPOINT ["parsedmarc"]
