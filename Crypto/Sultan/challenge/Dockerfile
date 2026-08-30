FROM python:3.11-slim

# Create non-root user
RUN useradd -m -u 1000 ctfuser

WORKDIR /home/ctfuser/app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PORT=5000

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R ctfuser:ctfuser /home/ctfuser/app

USER ctfuser

EXPOSE 5000

# Use 1 worker with 16 threads per container to safely share in-memory session store
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "16", "--worker-class", "gthread", "--access-logfile", "-", "app:app"]
