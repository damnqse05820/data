import config
import requests
import connection
import json

mongo = connection.mongoconnection
redip = connection.redisip
redomain = connection.redisdomain
mongodb = mongo.DomainIP
ip_collection = mongodb['ipList']
domain_collection = mongodb['domainList']
session = requests.Session()

def getipdomain(obj,mode):
    session.headers = {'User-Agent': config.USER_AGENT,"x-apikey": config.VIRUSTOTAL_API_KEY,}
    if mode == 0:
        url = "https://www.virustotal.com/api/v3/domains/"+obj['domain']
        
    else:
        url = "https://www.virustotal.com/api/v3/ip_addresses/"+obj['ip']
    r = session.get(url)
    if r.status_code == 200:
        data = r.json()
    else:
        return None
    result = {}
    if mode == 0:
        result['domain'] = obj['domain']
    else:
        result['ip'] = obj['ip']
    if data['data']['attributes']['last_analysis_stats']['malicious']>0:
        result['status'] = 'malicious'
    else:
        result['status'] = 'clean'
    result['info'] = data['data']['attributes']['last_analysis_stats']
    return result

def add_redis(result, mode):
    if '_id' in result:
        del result['_id']
    if mode == 0:
        redomain.set(result['domain'], json.dumps(result))
    else:
        redip.set(result['ip'],json.dumps(result))

def  search_redis(obj,mode):
    if mode == 0:
        result = redomain.get(obj['domain'])
    else:
        result = redip.get(obj['ip'])
    if result == None:
        return False, None
    return True, json.loads(result.decode())

def add_db(result,mode):
    if mode == 0:
        _id = domain_collection.insert_one(result).inserted_id
    else:
        _id = ip_collection.insert_one(result).inserted_id

def search_db(obj,mode):
    if mode == 0:
       result = domain_collection.find_one(obj['domain'], {'_id': False})
    else:
        result = ip_collection.find_one(obj['ip'], {'_id': False})
    return result

def checkIpDomain(obj,mode):
    flag, result = search_redis(obj,mode)
    if not flag:
        result = search_db(obj,mode)
        if result == None:
            result = getipdomain(obj,mode)
            if result == None:
                return "Not Found"
            add_db(result,mode)
        add_redis(result, mode)
    return result

# obj = {'domain':'facebook.com'}
# print(getipdomain(obj,0))
