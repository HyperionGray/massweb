Installation
============

.. include:: subs.rst

PIP (Recommended)
-----------------

To install MassWeb with pip_, simply type ``pip install massweb`` and you should get a working install on your system.


Manual
------
To install MassWeb from source:
#. Install MassWeb's dependencies.

    * `requests`_
    * `beautifulsoup4`_
    * `html5lib`_

#. Download MassWeb `massweb_archive`_.
#. Unpack the archive.
#. Install::

    cd massweb
    python setup.py install


Development
-----------

For development it is recommended that you use `virtualenv`. Below are the
steps to start building and testing.

#. Clone the git `massweb_repo`_.

#. Add virtualenv directory to your copy of the repository::

   $ cd massweb
   $ virtualenv env

#. Activate the virtualenv and run the ``refresh.sh`` script::

   $ source env/bin/activate
   $ ./test/refresh.sh

.. note:: If you are working on the documentation export ``REFRESH_SPHINX=true`` before running ``refresh.sh``.

#. Make changes.

#. Run ``refresh.sh`` again to build and install in a clean virtualenv.

#. Test changes.

