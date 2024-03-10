FROM python:3.12-slim-bookworm
# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=America/Vancouver

# Install system dependencies
RUN set -exu \
    && apt update \
    && apt upgrade --yes \
    && apt install --yes --no-install-recommends \
               bzip2 \
               ca-certificates \
               wget \
               curl \
               jq \
               git \
               python3-venv \
               graphviz \
               sqlite3 \
    ## libraries
    && apt-get clean \
    && apt-get autoremove --yes \
    && rm -rf /var/lib/apt/lists/*

# Set build arguments
ARG APP_DIR=/application
ARG APP_GROUP=birdwatcher
ARG APP_ENV=/opt/venv
ARG HF_HOME=/application/models

# Set environment variables
ENV APP_AUTO_UPDATE_APP=false \
    APP_DIR="$APP_DIR" \
    APP_ENV="$APP_ENV" \
    APP_GROUP="$APP_GROUP" \ 
    HF_HOME="$HF_HOME"

# Create application directory
RUN set -exu \
    && mkdir -p $APP_DIR \
    && groupadd -r $APP_GROUP \
    && useradd -r -g $APP_GROUP -d $APP_DIR $APP_GROUP \
    && chown root:$APP_GROUP $APP_DIR \
    && chmod 750 $APP_DIR

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN set -exu \
    && pip install --upgrade pip \
    && pip install --upgrade setuptools wheel \
    && pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm -rf /tmp/requirements.txt

# Startups
WORKDIR "$APP_DIR"
