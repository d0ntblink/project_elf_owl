import threading
import time
import logging

class ThreadHandler:
    def __init__(self, functions):
        self.functions = functions
        self.results = []
        self.thread_statuses = {}
        self.running = True

        # Configure logging
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)

    def run_threads(self):
        threads = []
        for func in self.functions:
            thread = threading.Thread(target=self.run_function, args=(func,))
            threads.append(thread)
            self.thread_statuses[func.__name__] = "Running"
            thread.start()

        for thread in threads:
            thread.join()

        return self.results

    def run_function(self, func):
        start_time = time.time()
        result = func()
        end_time = time.time()
        execution_time = end_time - start_time
        self.results.append((func.__name__, execution_time))

        # Update thread status
        self.thread_statuses[func.__name__] = "Completed"

        # Log the execution time
        self.logger.info(f"{func.__name__} executed in {execution_time} seconds")

    def get_thread_status(self, func_name):
        return self.thread_statuses.get(func_name, "Not Found")

    def check_thread_statuses(self):
        while self.running:
            for func in self.functions:
                status = self.get_thread_status(func.__name__)
                print(f"{func.__name__}: {status}")
            time.sleep(1)

    def stop_checking_statuses(self):
        self.running = False

if __name__ == "__main__":
    def func1():
        time.sleep(2)
        return "Function 1 done"

    def func2():
        time.sleep(3)
        return "Function 2 done"

    def func3():
        time.sleep(1)
        return "Function 3 done"

    def func4():
        time.sleep(4)
        return "Function 4 done"

    functions = [func1, func2, func3, func4]

    thread_handler = ThreadHandler(functions)
    status_thread = threading.Thread(target=thread_handler.check_thread_statuses)
    status_thread.start()

    results = thread_handler.run_threads()

    # Stop checking statuses after all threads are completed
    thread_handler.stop_checking_statuses()
    status_thread.join()
