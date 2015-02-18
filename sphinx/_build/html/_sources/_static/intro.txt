Intro
=====

The Problem
-----------

In PunkSPIDER 3.0 (the release we're currently working on) we have to scan several hundred million hosts in a very short amount of time over a Hadoop distributed cluster. There's a few big challenges with this:

#. We have to do it super fast, so we can't simply do requests "one by one", we could take care of this with Hadoop job settings but this is highly inefficient - we need the native mapper and reducer to be multi-threaded

#. It's highly variable how long a URL takes to get a response - we could be downloading a tiny 1kb page or we could be hitting a 200GB monster (think high-quality video), we need an upper bound to the amount of time that a large set of requests will take

#. We're doing lots of requests here, we use about 100-150 high performance proxies when we scan, a proxy rotation system would be nice

#. We need all of this to be simple, we want to be able to do all of this with just a few lines of code


The Sollution
-------------

MassWeb is a library meant for lightning-fast web application fuzzing. It attempts to solve all of the major problems of massive Internet-level scans in one convenient library. We use it in PunkSPIDER to scan several hundred million URLs for vulnerabilities over the course of just a few days (3 for our last scan).  Use it wisely and please don't do anything nasty with this.

