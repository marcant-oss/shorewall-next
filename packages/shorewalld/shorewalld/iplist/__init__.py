"""shorewalld.iplist — cloud/bogon prefix-list management.

Fetches IP prefix lists from cloud providers and populates nft interval
sets.  Providers are registered via the ``shorewalld.iplist_providers``
entry-point group so third-party packages can add their own.
"""
