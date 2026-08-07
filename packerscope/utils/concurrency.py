"""Concurrency utilities for parallelised PE analysis.

Provides :class:`AnalysisPool` which fans out analysis work across a
:class:`~concurrent.futures.ThreadPoolExecutor`, reports progress through
`Rich <https://rich.readthedocs.io>`_ progress bars, and isolates errors on
a per-file basis so that a single corrupt sample never crashes the batch.

Typical usage::

    from packerscope.utils.concurrency import AnalysisPool

    pool = AnalysisPool(max_workers=8)
    results = pool.map_analyze(file_list, my_analyze_fn)
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

import structlog
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

__all__ = [
    "AnalysisPool",
]

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class AnalysisPool:
    """Thread-pool executor with Rich progress tracking.

    Args:
        max_workers: Maximum number of worker threads.  Defaults to ``4``.
    """

    def __init__(self, max_workers: int = 4) -> None:
        if max_workers < 1:
            raise ValueError(f"max_workers must be >= 1, got {max_workers}")
        self._max_workers = max_workers

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def map_analyze(
        self,
        file_paths: list[Path],
        analyze_fn: Callable[[Path], Any],
    ) -> list[Any]:
        """Apply *analyze_fn* to every file in *file_paths* concurrently.

        Each invocation receives a single :class:`~pathlib.Path` argument.
        Exceptions raised by *analyze_fn* are caught, logged, and replaced
        with ``None`` in the returned list so that the batch continues.

        Args:
            file_paths: Files to analyse.
            analyze_fn: A callable ``(Path) -> T`` that performs analysis
                on a single file.

        Returns:
            A list aligned with *file_paths* where each element is either
            the return value of *analyze_fn* or ``None`` on failure.
        """
        total = len(file_paths)
        if total == 0:
            return []

        results: list[Any] = [None] * total
        # Map each Future back to its index for ordered results.
        future_to_index: dict[Future[Any], int] = {}

        logger.info(
            "batch_analysis_started",
            total_files=total,
            workers=self._max_workers,
        )

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            transient=False,
        )

        with progress:
            task_id = progress.add_task("Analysing files…", total=total)

            with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
                for idx, path in enumerate(file_paths):
                    future = executor.submit(analyze_fn, path)
                    future_to_index[future] = idx

                for future in as_completed(future_to_index):
                    idx = future_to_index[future]
                    file_path = file_paths[idx]
                    try:
                        results[idx] = future.result()
                    except Exception as exc:  # noqa: BLE001
                        logger.error(
                            "file_analysis_failed",
                            file=str(file_path),
                            error=str(exc),
                            exc_info=True,
                        )
                        results[idx] = None
                    progress.advance(task_id)

        succeeded = sum(1 for r in results if r is not None)
        logger.info(
            "batch_analysis_completed",
            total=total,
            succeeded=succeeded,
            failed=total - succeeded,
        )

        return results
