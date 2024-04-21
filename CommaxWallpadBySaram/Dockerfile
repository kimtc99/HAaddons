FROM python:3.10-slim-buster
  
ENV LANG C.UTF-8
ENV TZ=Asia/Seoul

# Install requirements for add-on
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir paho-mqtt==1.6.1
#RUN pip install --no-cache-dir telnetlib

# Copy data for add-on
COPY apps /apps

WORKDIR /share

CMD ["python", "/apps/main.py" ]


