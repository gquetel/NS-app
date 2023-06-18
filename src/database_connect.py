class mongo_middleware:

    def __init__(self, mongo_uri):
        from pymongo import MongoClient
        self.mongo_connection = MongoClient(mongo_uri)['fp']

    def save_client_hello(self, json_data):
        collection_fp = self.mongo_connection["fp"]

        # Check if it's already exists in database
        req = collection_fp.find_one(
            {'sha_384': json_data['sha_384']})

        if(json_data['user-agent'] not in req.user_agent):
            pass

        if not req:
            collection_fp.insert_one(json_data)

    def get_fp(self):
        collection_fp = self.mongo_connection["fp"]
        req = collection_fp.find().sort("_id", -1).limit(10)
        return list(req)

    def get_ua(self):
        collection_fp = self.mongo_connection["fp"]
        req = collection_fp.find({}, {"user-agent": 1}
                                 ).sort("_id", -1).limit(10)
        return list(req)
