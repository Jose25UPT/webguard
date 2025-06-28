FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl git perl libssl-dev libffi-dev \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf2.0-0 \
    shared-mime-info libxml2-dev libxslt-dev \
    && apt-get clean

RUN pip install --no-cache-dir wapiti3

RUN git clone https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./app /app/app

RUN apt-get update && apt-get install -y wkhtmltopdf
RUN pip install pdfkit jinja2


EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

