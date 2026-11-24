FROM python:3.12-slim
WORKDIR /app
COPY . /app
EXPOSE 8080
CMD ["sh", "-c", "python run.py demo --no-dashboard && python run.py dashboard --host 0.0.0.0 --port 8080"]
