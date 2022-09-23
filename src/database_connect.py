import json

class mongo_middleware:

    def __init__(self, mongo_uri):
        from pymongo import MongoClient
        self.mongo_connection = MongoClient(mongo_uri)['fp']


    
    def save_client_hello(self,json_data):
        collection_fp = self.mongo_connection["fp"]

        # Check if it's already exists in database
        req = collection_fp.find_one(
            {'sha_384': json_data['sha_384']},
            {'user_agent': json_data['user-agent']})

        if not req:
            collection_fp.insert_one(json_data)


    def get_fp(self, key='sha_384'):
        collection_fp = self.mongo_connection["fp"]


        req = collection_fp.find().sort("_id", -1).limit(10)
        res = json.loads(json.dumps(list(req), default=str))

        if key is None:
            return json.dumps(res)

        user_agents = []
        for elem in res:
            user_agents.append(elem[key])
        return json.dumps(user_agents)