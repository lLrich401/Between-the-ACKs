FROM python:3.12-slim

WORKDIR /app
COPY server.py .

ENV BTA_PORT=9001
ENV BTA_UDP_BASE=20001
ARG BTA_FLAG=LR{b3tw33n_th3_ACKs_1s_wh3r3_th3_pr0t0c0l_l1v3s}
ENV BTA_FLAG=${BTA_FLAG}

EXPOSE 9001/tcp 9002/tcp 20001-20002/udp

CMD ["python", "-u", "server.py"]
