FROM ubuntu:latest
# This builds a docker image that has all dependencies as well as fpm installed.
# Running it without additional commands clones the github repo and builds the master branch
# using the version number in cealr/VERSION

# build with docker:
# docker build -t cealr_dev_base .
# Run with:
# docker run cealr_dev_base > myartifacts.tar.gz

RUN apt update && apt install -y \
  xz-utils \
  build-essential \
  rpm \
  curl \
  cmake \
  libcurl4-openssl-dev \
  libssl-dev \
  nlohmann-json-dev \
  zlib1g-dev \
  libgpgme-dev \
  ruby ruby-dev rubygems \
  git
#  && rm -rf /var/lib/apt/lists/*

RUN gem install --no-ri --no-rdoc fpm

# Start from a Bash prompt
CMD git clone https://github.com/cryptowerk/cealr.git && cd cealr && ./build-release.sh && ./pack.sh \
  && cd build/release && tar -zc -f cealr-artifacts.tar.gz *.deb *.rpm cealr && mkdir -p /mnt/archive \
  && mv cealr-artifacts.tar.gz /mnt/archive && chmod a+r /mnt/archive/cealr-artifacts.tar.gz

RUN echo 'Run with:'
RUN echo 'docker run -v`pwd`:/mnt/archive cealr_dev_base'
