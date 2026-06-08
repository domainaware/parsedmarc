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
    # Install the wheel with the [postgresql] extra so the prebuilt image
    # ships the PostgreSQL output backend (psycopg). Resolve the globbed wheel
    # path into a variable first: `*.whl[postgresql]` would otherwise be parsed
    # as a shell bracket glob rather than a pip extras spec. psycopg[binary]
    # has prebuilt manylinux wheels for both amd64 and arm64, so this adds no
    # source-build step on either platform.
    whl="$(ls /tmp/dist/*.whl)"; \
    pip install "${whl}[postgresql]"; \
    rm -rf /tmp/dist

USER $USERNAME

ENTRYPOINT ["parsedmarc"]
