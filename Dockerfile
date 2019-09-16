FROM python:alpine3.9

RUN apk add --no-cache curl

RUN mkdir -p /opt/blackduck/

COPY bdba-pdf.py /opt/blackduck/bdba-pdf.py

CMD ["python3"]
