# Depending on your system you  may need to prefix the commands below with sudo.
#
# To build:  docker build --force-rm=true -t <projectName>:1.0.0 .
#   Example:  docker build --force-rm=true -t scimgateway:1.0.0 .
#
# To tag as latest:   docker tag <projectName>:1.0.0 <projectName>:latest
#   Example:   docker tag scimgateway:1.0.0 scimgateway:latest
#
# To run:   docker run -d -e NODE_ENV=<environment> -e PORT=<port> -h localhost -p <external port>:<internal port> --name <projectName> <projectName>:latest
#   Example:   docker run -d -e NODE_ENV=development -e PORT=3000  -h localhost -p 8880:8880 --name scimgateway scimgateway:latest


# use the official Bun image, see all versions at https://hub.docker.com/r/oven/bun/tags
FROM oven/bun:slim AS base

# Declare who maintains this Dockerfile
LABEL maintainer="Charles Watson <cwatsonx@costco.com>"

# Add a Process ID 1 Safety Net.  Specific to debian.
ADD https://github.com/Yelp/dumb-init/releases/download/v1.2.0/dumb-init_1.2.0_amd64 /usr/local/bin/dumb-init
RUN chmod +x /usr/local/bin/dumb-init

# Define your working directory for the bun app.
WORKDIR /home/scimgateway
ENV NODE_HOME=/home/scimgateway

# Add your project info
ADD ./package.json ./bun.lockb $NODE_HOME

# Install dependencies (exclude test stuff for dependencies)
RUN . ~/.bashrc && cd $NODE_HOME && bun install --production --frozen-lockfile

# Copy your project's code to your working directory
COPY . $NODE_HOME

# Start it up
CMD ["dumb-init", "bun", "index.ts"]
