"""Domain-aware and time-aware train/test splitting."""

from __future__ import annotations

from collections import defaultdict

import numpy as np
import pandas as pd
import tldextract


def registrable_domain(url: str) -> str:
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return (ext.domain or url).lower()


def domain_aware_split(
    df: pd.DataFrame,
    *,
    url_col: str = "url",
    label_col: str = "label",
    test_size: float = 0.2,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Put all URLs of a domain entirely in train or entirely in test."""
    df = df.copy()
    df["_domain"] = df[url_col].map(registrable_domain)

    domains = df["_domain"].unique().tolist()
    rng = np.random.RandomState(random_state)
    rng.shuffle(domains)

    # Stratify domains by majority label when possible
    domain_labels = {}
    for d, g in df.groupby("_domain"):
        domain_labels[d] = int(g[label_col].mode().iloc[0])

    by_label: dict[int, list[str]] = defaultdict(list)
    for d in domains:
        by_label[domain_labels[d]].append(d)

    test_domains: set[str] = set()
    for _label, dlist in by_label.items():
        n_test = max(1, int(round(len(dlist) * test_size))) if len(dlist) > 1 else 0
        test_domains.update(dlist[:n_test])

    test_mask = df["_domain"].isin(test_domains)
    train_df = df.loc[~test_mask].drop(columns=["_domain"])
    test_df = df.loc[test_mask].drop(columns=["_domain"])

    if test_df.empty and len(df) > 5:
        # Fallback: last 20% of shuffled domains
        n = max(1, int(len(domains) * test_size))
        test_domains = set(domains[:n])
        test_mask = df["_domain"].isin(test_domains)
        train_df = df.loc[~test_mask].drop(columns=["_domain"])
        test_df = df.loc[test_mask].drop(columns=["_domain"])

    return train_df.reset_index(drop=True), test_df.reset_index(drop=True)


def time_aware_split(
    df: pd.DataFrame,
    *,
    time_col: str = "timestamp",
    test_size: float = 0.2,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Older URLs → train, newer → test."""
    df = df.sort_values(time_col).reset_index(drop=True)
    cut = int(len(df) * (1 - test_size))
    return df.iloc[:cut].copy(), df.iloc[cut:].copy()
