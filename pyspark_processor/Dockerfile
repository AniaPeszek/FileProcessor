# pull official base image
FROM python:3.10-slim-buster AS py3
FROM openjdk:8-slim-buster
COPY --from=py3 / /
# set work directory
WORKDIR /usr/src/pyspark_processor

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install system dependencies
RUN apt-get update && apt-get install -y file

# install dependencies
RUN pip install --upgrade pip
COPY ./requirements.txt .
RUN pip install -r requirements.txt

# copy project
COPY . .
#RUN mkdir /tmp
#MOUNT --type=tmpfs --tmpfs-size=500MB --destination=/tmp /tmp

EXPOSE 5001
# run server
CMD ["python", "pyspark_processor.py"]
