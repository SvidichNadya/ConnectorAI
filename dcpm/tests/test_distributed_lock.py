"""Proves the domain-creation lock is a REAL distributed lock: correctness holds across separate OS
processes sharing one SQLite file, not just across threads of one process (a Python threading.Lock
could never do this - it is invisible to a second process entirely)."""
import json
import multiprocessing
import os
import tempfile
import unittest

from dcpm.semantic.domains import resolve_domain
from dcpm.storage.db import Store


class _FixedGateway:
    """Always proposes the SAME new domain - the scenario where, without real cross-process
    coordination, every process would plausibly create its own duplicate row."""
    def complete_json(self, *, system, user, max_tokens):
        return json.dumps({"action": "new", "new_domain": {"key": "multiprocess_domain", "title": "MP Domain",
                                                            "description": "created under real concurrency"},
                           "confidence": 0.9, "evidence": ["shared sample text"]})


def _worker(db_path, idx, max_wait, queue):
    store = Store(db_path)
    dom, _ = resolve_domain(store, "tenant_mp", f"src_{idx}", llm=_FixedGateway(), ai_allowed=True,
                            sample_text="shared sample text about something", run_id=None,
                            lock_max_wait_seconds=max_wait)
    store.close()
    queue.put((dom["id"], os.getpid()))


@unittest.skipUnless(hasattr(multiprocessing, "get_context"), "multiprocessing required")
class DistributedLockTests(unittest.TestCase):
    def _run(self, n, max_wait):
        with tempfile.TemporaryDirectory() as d:
            db_path = os.path.join(d, "dcpm.sqlite3")
            Store(db_path).close()  # create the schema once, up front, before any worker opens it
            ctx = multiprocessing.get_context("spawn")
            queue = ctx.Queue()
            procs = [ctx.Process(target=_worker, args=(db_path, i, max_wait, queue)) for i in range(n)]
            for p in procs:
                p.start()   # started back-to-back with no synchronisation barrier: real OS scheduling
            results = [queue.get(timeout=30) for _ in range(n)]
            for p in procs:
                p.join(timeout=30)
                self.assertEqual(p.exitcode, 0)
            store = Store(db_path)
            rows = store.list_domains("tenant_mp")[0]
            store.close()
            return results, rows

    def test_real_distributed_lock_prevents_duplicate_across_processes(self):
        results, rows = self._run(n=12, max_wait=10.0)
        pids = {pid for _, pid in results}
        self.assertEqual(len(pids), 12, "test is invalid unless workers really ran in distinct processes")
        self.assertEqual(len({r[0] for r in results}), 1, "all six processes must resolve to the SAME domain id")
        self.assertEqual(len(rows), 1, "exactly one domain row must exist, not one per process")

    def test_unique_constraint_is_the_real_backstop_even_with_no_lock_wait(self):
        """max_wait=0: every process effectively skips queuing for the lock and races straight to
        create-or-get. Correctness must still hold, because it is the database's UNIQUE constraint
        that guarantees it, not the lock (the lock only avoids wasted work in the common case)."""
        results, rows = self._run(n=12, max_wait=0.0)
        self.assertEqual(len({r[0] for r in results}), 1)
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
