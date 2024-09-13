# OpenStack Manila driver for Pure Storage FlashArray with FA-Files enabled

This is beta code for Prrof-of-Concept work only.
No support is implied or given by this driver being made available.
This code is a subset of https://review.opendev.org/c/openstack/manila/+/795180 which is the main submission
for this new driver, including the necessary documentation.

Note that this code is from the pre-dalmatian mater branch and therefore applying it to older versions of OpenStack
may have unexpected consequences. In particular, the `opts.py` file may try to import code that is not is earlier
releases of OpenStack.

The `opts.py` code is required to be added to your Manila deployment, as it contains required imports for this driver
