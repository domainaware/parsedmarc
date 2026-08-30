# syntax=docker/dockerfile:1
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

# The wheel is bind-mounted from the `build` stage rather than COPYed in. A COPY
# commits it to its own layer, and the `rm -rf /tmp/dist` that used to end this
# RUN could only write a whiteout on top: a layer that is already committed
# cannot be removed by a later one, so the wheel shipped in every pull. A bind
# mount is never committed to a layer, so there is nothing left to remove.
RUN --mount=type=bind,from=build,source=/app/dist,target=/tmp/dist \
    set -ex; \
    groupadd --gid ${USER_GID} ${USERNAME}; \
    useradd --uid ${USER_UID} --gid ${USER_GID} -m ${USERNAME}; \
    # Install the wheel with the [all] and [postgresql] extras so the prebuilt
    # image ships every output and mailbox integration, including the
    # PostgreSQL backend (psycopg). The image deliberately bundles everything:
    # container users see no change across the packaging split that made
    # `pip install parsedmarc` the parsing core plus the base CLI.
    # Resolve the globbed wheel path into a variable first:
    # `*.whl[all,postgresql]` would otherwise be parsed as a shell bracket
    # glob rather than a pip extras spec. psycopg[binary] has prebuilt
    # manylinux wheels for both amd64 and arm64, so this adds no source-build
    # step on either platform.
    whl="$(ls /tmp/dist/*.whl)"; \
    pip install "${whl}[all,postgresql]"

USER $USERNAME

ENTRYPOINT ["parsedmarc"]
