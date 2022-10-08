from threading import Thread
import time


class ApiHelper(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.QUEUE = []
    
    def run(self):
        while True:
            try:
                if self.QUEUE:
                    func = self.QUEUE[0]
                    del self.QUEUE[0]

                    func[0].run(func[1], **func[2])
            except Exception as e:
                print(e)
                try:
                    del self.QUEUE[0]
                except Exception as e:
                    pass

            time.sleep(0.1)