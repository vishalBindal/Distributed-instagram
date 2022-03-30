from celery import Celery
from sklearn.cluster import KMeans
import numpy as np
from master_app import get_master_rds
from config import NUM_CLUSTERS, KMEANS_INTERVAL
import time

app = Celery('tasks', backend='redis://localhost', broker='pyamqp://guest@localhost:5672//')

@app.task
def run_kmeans():
    while True:
        mr = get_master_rds()
        ids = 0
        loc_to_id = {}
        user_to_id = {}
        locs = []

        user_to_loc = mr.rds.hgetall(mr.USER2LOC)

        for username in user_to_loc:
            location = user_to_loc[username]
            loc_to_id[location] = ids
            user_to_id[username] = ids
            locs.append(location)
            ids += 1

        locs = np.array(locs)
        kmeans = KMeans(n_clusters=NUM_CLUSTERS, random_state=0).fit(locs)

        usernames = list(mr.rds.smembers(mr.USERNAMES)) 
        to_predict = []

        for username in usernames:
            to_predict.append(locs[user_to_id[username]])

        user_clusters = kmeans.predict(to_predict)
        clus_to_users = {}

        for i in range(len(usernames)):
            mr.rds.hset(mr.USER2LOC, usernames[i], user_clusters[i])
            clus_to_users[user_clusters[i]].append(usernames[i])

        for i in range(NUM_CLUSTERS):
            while mr.rds.scard(mr.CLUS2USERS_PREFIX + str(i)) > 0:
                mr.rds.spop(mr.CLUS2USERS_PREFIX + str(i))
            
            for value in clus_to_users[i].values():
                mr.rds.add(mr.CLUS2USERS_PREFIX + str(i), value)

        time.sleep(KMEANS_INTERVAL)

        
        

        

        

