from elasticsearch import Elasticsearch
from pymongo import MongoClient
import config
import redis
ESconnection = None
mongoconnection = None
redisconnection = None

try:
    ESconnection = Elasticsearch(config.ELASTICSEARCH_URL)
    mongoconnection = MongoClient(config.MONGO_CONECTION)
    redisip = redis.StrictRedis(host='localhost', port=6379, db=0)
    redisdomain = redis.StrictRedis(host='localhost', port=6379, db=2)
except Exception as err:
    print (err)