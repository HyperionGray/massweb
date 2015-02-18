Installation
============

PIP (Recommended)
-----------------

To install MassWeb with pip, simply type ``pip install massweb`` and you should get a working install on your system.


Manual
------
To install MassWeb from source:
#. Install MassWeb's dependencies.
    * `requests <http://docs.python-requests.org/en/latest/user/install/#install>`_
    * `beautifulsoup4 <http://www.crummy.com/software/BeautifulSoup/bs4/doc/index.html?highlight=tag#installing-beautiful-soup>`_
    * `html5lib <https://github.com/html5lib/html5lib-python>`_

#. Download MassWeb `here <http://fixme>`_.
#. Unpack the archive.
#. Install::

    cd massweb
    python setup.py install


Development
-----------

For development it is recommended that you use `virtualenv`. Below are the steps to start building and testing.

#. Clone the git `repo <fixme>`_.
#. Add virtualenv directory to your copy of the repo::

   $ cd massweb
   $ virtualenv env

#. Activate the virtualenv and run the ``refresh.sh`` script:
   * If you are working on the documentation export ``REFRESH_SPHINX=true`` before running ``refresh.sh``.
   ::

   $ source env/bin/activate
   $ ./test/refresh.sh

#. Make changes.
#. Run ``refresh.sh`` again to build and install in a clean virtualenv.
#. Test changes.

