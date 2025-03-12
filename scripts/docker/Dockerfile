FROM docker:dind

# Install Python and other deps
RUN apk add --update --no-cache python3 python3-dev py-pip bash xterm gcc musl-dev && ln -sf python3 /usr/bin/python
RUN pip3 install --no-cache --upgrade --break-system-packages pip setuptools

# Install Kathara and Lab Checker
RUN pip3 install --no-cache --upgrade --break-system-packages git+https://github.com/saghul/pyuv@master#egg=pyuv
RUN pip3 install --no-cache --upgrade --break-system-packages kathara kathara-lab-checker
