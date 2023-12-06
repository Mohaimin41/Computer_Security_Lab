import importlib

aes = importlib.import_module("1905041_aes")
cbc = importlib.import_module("1905041_cbc")

worker = cbc.CBC()

worker.run()