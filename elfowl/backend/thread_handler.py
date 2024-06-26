from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time, logging


class ThreadManager:
    def __init__(self):
        """
        Initializes the ThreadManager class.
        """
        self.logger = logging.getLogger("ThreadManager")
        self.all_threadpools = {}
        self.lock = threading.Lock()

    def create_a_pool(self, pool_name):
        """
        Creates a new thread pool with the given name.

        Args:
            pool_name (str): The name of the thread pool.
        """
        with self.lock:
            self.all_threadpools[pool_name] = {}

    def add_to_threadpool(self, pool_name, func, *args):
        """
        Adds a task to the specified thread pool.

        Args:
            pool_name (str): The name of the thread pool.
            func (function): The function to be executed as a task.
            *args: The arguments to be passed to the function.
        """
        with self.lock:
            if pool_name not in self.all_threadpools:
                self.logger.error(f"ThreadPool {pool_name} does not exist.")
                return
            # Count how many tasks are already in the pool starting with the same function name
            task_name = func.__name__
            task_num = 0
            for task in self.all_threadpools[pool_name]:
                if task.startswith(task_name):
                    task_num += 1
            self.logger.debug(f"Adding task {task_name}_{task_num} to ThreadPool {pool_name}")
            # Task is stored with its initial status and the function with arguments
            self.all_threadpools[pool_name][f"{task_name}_{task_num}"] = {"status": "not_started", "func": func, "args": args, "result": None}


    def track_threads_in_threadpool(self, pool_name, timer):
        """
        Tracks the progress of tasks in the specified thread pool.

        Args:
            pool_name (str): The name of the thread pool.
            timer (int): The interval in seconds between progress updates.
        """
        all_done = False
        while not all_done:
            with self.lock:
                started, not_started, finished = 0, 0, 0
                for task_info in self.all_threadpools[pool_name].values():
                    status = task_info['status']
                    if status == 'not_started':
                        not_started += 1
                    elif status == 'started':
                        started += 1
                    elif status == 'finished':
                        finished += 1
                
                total = started + not_started + finished
                if total > 0:
                    self.logger.info(f"""
                        Percentage complete: {finished / total * 100:.2f}%
                        Started: {started},
                        Not started: {not_started},
                        Finished: {finished}
                    """)
                all_done = (finished == total)
            
            time.sleep(timer)  # Wait for a second before checking again

    def run_a_threadpool(self, pool_name, max_threads=0, track_threads=True, timer=1):
        """
        Runs the tasks in the specified thread pool.

        Args:
            pool_name (str): The name of the thread pool.
            max_threads (int): The number of threads to use. If 0, uses the number of tasks in the pool.
            track_threads (bool): Whether to track the progress of tasks.
            timer (int): The interval in seconds between progress updates.
        """
        if pool_name not in self.all_threadpools:
            self.logger.error(f"ThreadPool {pool_name} does not exist.")
            return
        
        if track_threads:
            # Start tracking in a separate thread
            tracking_thread = threading.Thread(target=self.track_threads_in_threadpool, args=(pool_name,timer))
            tracking_thread.start()
        
        if max_threads == 0:
            adjusted_max_threads = len(self.all_threadpools[pool_name])
        elif max_threads < 1:
            self.logger.error(f"Invalid number of threads: {max_threads}")
            return
        else:
            adjusted_max_threads = max_threads
        
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=adjusted_max_threads) as executor:
            futures = {executor.submit(task_info['func'], *task_info['args']): task_name for task_name, task_info in self.all_threadpools[pool_name].items() if task_info['status'] == 'not_started'}
            for future in as_completed(futures):
                task_name = futures[future]
                try:
                    result = future.result()  # Capture the return value
                    self.all_threadpools[pool_name][task_name]['result'] = result
                except Exception as e:
                    self.logger.error(f"Task {task_name} resulted in an error: {e}")
                finally:
                    self.mark_finished(pool_name, task_name)

        self.logger.info(f"ThreadPool {pool_name} completed in {time.time() - start_time:.2f} seconds")
        if track_threads:
            tracking_thread.join()  # Wait for the tracking thread to finish

    def mark_finished(self, pool_name, task_name):
        """
        Marks a task as finished in the specified thread pool.

        Args:
            pool_name (str): The name of the thread pool.
            task_name (str): The name of the task.
        """
        with self.lock:
            if pool_name in self.all_threadpools and task_name in self.all_threadpools[pool_name]:
                self.all_threadpools[pool_name][task_name]['status'] = 'finished'

    def is_threadpool_running(self, pool_name):
        """
        Checks if there are any tasks running in the specified thread pool.

        Args:
            pool_name (str): The name of the thread pool.

        Returns:
            bool: True if there are running tasks, False otherwise.
        """
        with self.lock:
            if pool_name in self.all_threadpools:
                for task_info in self.all_threadpools[pool_name].values():
                    if task_info['status'] in ['not_started', 'started']:
                        return True
        return False

    def get_threadpool_results(self, pool_name):
        """
        Retrieves the results of all tasks in the specified thread pool.

        Args:
            pool_name (str): The name of the thread pool.

        Returns:
            dict: A dictionary with task names as keys and their results as values.
        """
        with self.lock:
            if pool_name not in self.all_threadpools:
                self.logger.error(f"ThreadPool {pool_name} does not exist.")
                return None

            results = {}
            for task_name, task_info in self.all_threadpools[pool_name].items():
                if 'result' in task_info:
                    results[task_name] = task_info['result']
            return results
    
    def remove_threadpool(self, pool_name):
        """
        Removes the specified thread pool.

        Args:
            pool_name (str): The name of the thread pool.
        """
        with self.lock:
            if pool_name in self.all_threadpools:
                del self.all_threadpools[pool_name]
                self.logger.info(f"ThreadPool {pool_name} removed.")
            else:
                self.logger.error(f"ThreadPool {pool_name} does not exist.")


if __name__ == "__main__":
    pass