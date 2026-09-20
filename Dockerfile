FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHON_VERSION=3.11

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential cmake ninja-build git \
    python3 python3-pip python3-venv \
    libssl-dev openssl \
    && rm -rf /var/lib/apt/lists/*

# Build liboqs
WORKDIR /tmp
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && mkdir build && cd build && \
    cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    ninja && ninja install && \
    ldconfig

# Install liboqs-python
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && pip3 install .

# Set up lab
WORKDIR /lab
COPY requirements.txt .
RUN pip3 install -r requirements.txt

COPY . .

ENV EVIDENCE_DIR=/lab/evidence
ENV REPORTS_DIR=/lab/reports

# Default: run all labs
CMD ["make", "all"]