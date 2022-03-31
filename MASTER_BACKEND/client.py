import threading
from tasks import run_kmeans
from config import KMEANS_INTERVAL

t = threading.Thread(target=run_kmeans)
t.start()
t.join()
