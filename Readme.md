Superkey management tool

It has SSO with google
each user can upload their public key

Servers / devices can be managed: they can be tagged with labels
each server can have mujltiple labels

Users can be added to groups - but this is synced from google groups. 

To manage access, one can add groups to labels (so which groups can access which labels)
one can also add users directly to labels

There is a view where a user can see to which servers they have access

There is an admin view where one can see this for each user (with a dropdown)
and there is an admin view where one can see for a server, who has access to it (both by group, and by user individually)

admin is everyone who is in the group superkey_admins


To deploy the settings to devices, it can export the key structure to a local folder, path configurable, default ~/hostnames/keys
There, it creates a subfolder for each server/device, and puts all public keys in this folder that should have access.

There is a dockerfile to build and deploy the application