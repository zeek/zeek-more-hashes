FROM zeek/zeek-dev
RUN apt-get update && apt-get -y --no-install-recommends install \
    cmake \
    build-essential \
    libpcap-dev \
    libssl-dev

RUN git config --global --add safe.directory '*'

# Load packages by default
RUN echo '@load packages' >> /usr/local/zeek/share/zeek/site/local.zeek

WORKDIR /src/zeek-more-hashes
COPY . .
RUN rm -rf ./build
RUN ./configure && make
RUN cd tests && btest -d -j
RUN echo "Y" | zkg install .
RUN zeek -NN Zeek::MoreHashes
RUN zeek -r tests/Traces/get.trace LogAscii::use_json=T zeek-more-hashes/mmh3
RUN grep 1887416688 files.log
