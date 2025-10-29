ARG BASE_IMAGE=python:3.13-slim
ARG USERNAME=parsedmarc
ARG USER_UID=1000
ARG USER_GID=$USER_UID

## build

FROM $BASE_IMAGE AS build

WORKDIR /app

RUN pip install hatch

COPY parsedmarc/ parsedmarc/
COPY README.md pyproject.toml ./

RUN hatch build

## image

FROM $BASE_IMAGE
ARG USERNAME
ARG USER_UID
ARG USER_GID

COPY --from=build /app/dist/*.whl /tmp/dist/
RUN set -ex; \
    groupadd --gid ${USER_GID} ${USERNAME}; \
    useradd --uid ${USER_UID} --gid ${USER_GID} -m ${USERNAME}; \
    pip install /tmp/dist/*.whl; \
    rm -rf /tmp/dist

USER $USERNAME

ENTRYPOINT ["parsedmarc"]
