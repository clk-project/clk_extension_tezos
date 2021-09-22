FROM python:3.7

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests --yes libsodium-dev libsecp256k1-dev libgmp-dev

ARG uid=1000
ARG username=user
ENV HOME=/home/$username
RUN addgroup --gid $uid --system $username \
	&& adduser --uid $uid --system $username --ingroup $username \
	&& addgroup --system $username audio \
 	&& addgroup --system $username video \
 	&& addgroup --system $username disk \
 	&& addgroup --system $username lp \
 	&& addgroup --system $username dialout \
 	&& addgroup --system $username users \
 	&& chown -R $username:$username $HOME
ENV PATH=$HOME/.local/bin:$PATH

USER $username
WORKDIR $HOME

RUN python3 -m pip install pytezos
COPY key.py /home/user/.local/lib/python3.7/site-packages/pytezos/crypto/key.py
