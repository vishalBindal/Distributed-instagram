from tasks import run_kmeans
from celery import group

res = group(run_kmeans.s()).apply_async()
res.get()

