import pickle
messages = []
with open("messages.pickle", "wb") as f:
    pickle.dump(messages, f)
