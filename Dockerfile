FROM python:3.9-slim

WORKDIR /app
COPY parsedmarc/ parsedmarc/
COPY README.md pyproject.toml ./

RUN pip install -U pip
RUN pip install hatch
RUN hatch build
RUN pip install dist/*.whl

ENTRYPOINT ["parsedmarc"]
