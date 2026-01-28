from motor.motor_asyncio import AsyncIOMotorClient
from typing import Any

mongourl : str = "mongodb://localhost:27017/"
client : AsyncIOMotorClient[Any] = AsyncIOMotorClient(mongourl)
db :Any = client["refreshtoken"]
collection : Any= db['students'] 