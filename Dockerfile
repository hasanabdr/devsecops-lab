FROM python:3.11-slim

WORKDIR /app

COPY app/requirements.txt .
RUN pip install --no-requirements requirements.txt

COPY app/ .

EXPOSE 8080

CMD ["python", "app.py"]
