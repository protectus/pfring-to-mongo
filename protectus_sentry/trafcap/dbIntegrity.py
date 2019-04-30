#!/usr/bin/python
#
# Copywrite (c) 2015 PROTECTUS,LLC.  All Rights Reserved.
#
import pymongo

client = pymongo.MongoClient()
db = client.kw

# Iterate through bytes, making sure everything matches up.  Might take a while.

bad = 0
cursor = db.tcp_sessionBytes.find()
tcp_sessionInfo = db.tcp_sessionInfo
for i,doc in enumerate(cursor):
    match = tcp_sessionInfo.find_one({
        "ip1": doc["ip1"],
        "ip2": doc["ip2"],
        "p1": doc["p1"],
        "p2": doc["p2"],
        "tbm": {"$lte": doc["se"] + 61},
        "tb": {"$lte": doc["se"] + 1},
        "tem": {"$gte": doc["sb"] - 61},
        "te": {"$gte": doc["sb"] - 1}
    })

    if match is None:
        bad += 1
        print(doc)

    if i % 10000 == 0:
        print("Checked",i)
        
print("Done.  Found", bad, "potential bad documents")
