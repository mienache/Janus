FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update
RUN apt install --yes sudo pkg-config
RUN apt install gcc-7 -y
RUN apt install python3 -y
RUN apt install -y python3-pip python-dev build-essential
RUN pip3 install regex
RUN apt install cmake -y


RUN adduser --ingroup sudo janus
RUN echo 'janus ALL=(ALL) NOPASSWD:ALL'>/etc/sudoers
USER janus

# Add paths to janus_project/bin and janus_project/janus
RUN echo 'export PATH=/janus_project/bin:$PATH'>>/home/janus/.bashrc
RUN echo 'export PATH=/janus_project/janus/:$PATH'>>/home/janus/.bashrc

WORKDIR "/janus_project"
