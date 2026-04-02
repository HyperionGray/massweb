""" PathBuster — gobuster-style directory and file enumeration.

Provides :class:`PathBuster`, a lean path-enumeration scanner built on top of
the existing :class:`~massweb.mass_requests.mass_request.MassRequest`
infrastructure.  It is designed for speed at scale: the same multiprocessing
pool that drives the core fuzzer handles path probing. """
