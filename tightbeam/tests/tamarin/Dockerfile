# Tamarin 1.12.0 and Maude 3.5.1, the version that Tamarin's own CI installs.
# Each download is pinned by SHA-256. The proofs run with no network.
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates curl unzip graphviz libgmp10 libtinfo6 zlib1g libffi8 libnuma1 \
	&& rm -rf /var/lib/apt/lists/*

RUN set -e; \
	cd /tmp; \
	curl -fsSL -o tamarin.tar.gz https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz; \
	echo "201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6  tamarin.tar.gz" | sha256sum -c -; \
	mkdir tamarin; \
	tar -xzf tamarin.tar.gz -C tamarin; \
	install -m 755 "$(find tamarin -type f -name tamarin-prover | head -n 1)" /usr/local/bin/tamarin-prover; \
	curl -fsSL -o maude.zip https://github.com/maude-lang/Maude/releases/download/Maude3.5.1/Maude-3.5.1-linux-x86_64.zip; \
	echo "72ed1ca87e3b3d0dfc6ee1436baf154bf04c45ff97d521bec040c5e8dfc8f92c  maude.zip" | sha256sum -c -; \
	unzip -oj maude.zip -d /usr/local/bin; \
	chmod 755 /usr/local/bin/maude; \
	rm -rf /tmp/*

# A missing library or a Maude that Tamarin refuses fails the build here.
RUN ! ldd /usr/local/bin/tamarin-prover | grep 'not found'
RUN tamarin-prover --version
