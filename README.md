# OpenStack Manila driver for Pure Storage FlashArray with FA-Files enabled

This is beta code for approved Proof-of-Concept work only.
No support is implied or given by this driver being made available.
This code is a subset of https://review.opendev.org/c/openstack/manila/+/795180 which is the main submission
for this new driver, including the necessary documentation.

Note that this code is from the pre-dalmatian mater branch and therefore applying it to older versions of OpenStack
may have unexpected consequences. In particular, the `opts.py` file may try to import code that is not in earlier
releases of OpenStack.

The `opts.py` code is required to be added to your Manila deployment, as it contains necessary imports for this driver

## WARNING

One feature of this driver does not work. That is the deletion of a share if it has any content. 
We beleive this is the only outstanding issue for this driver and requires an updated version of Purity//FA to allow
this to work. We are awaiting confirmation from Pure Storage Engineering when this feature will be added to Purity//FA.
