 
# Cluster Glue

Cluster Glue is a set of libraries, tools and utilities used in the
the Heartbeat/Pacemaker cluster stack. In essence, Glue are the parts
of the cluster stack that don't fit in anywhere else, and aren't big
enough pieces or actively developed enough to qualify as their own
projects.

Cluster Glue has been managed as a separate Linux-HA sub-project since
its 1.0 release, which coincided with the Heartbeat 2.99
release. Previously, it was a part of the then-monolithic Heartbeat
project, and had no separate name.

## Components

### Local Resource Manager (LRM)

The Local Resource Manager is the interface between the Cluster
Resource Manager (Pacemaker) and the resource agents. It is itself not
cluster aware, nor does it apply any policies. It simply processes
commands received from the Cluster Resource Manager, passes them to
resource agents, and reports back success or failure. It particular,
the LRM may

* start a resource;
* stop a resource;
* monitor a resource;
* report a resource's status;
* list all resource instances it currently controls, and their status.

### STONITH

A mechanism for node fencing. In case a node is considered "dead" by
the cluster as a whole, STONITH ("Shoot The Other Node In The Head")
forcefully removes is from the cluster so it can no longer pose a risk
of interacting with other nodes in an uncoordinated fashion.

### hb_report (deprecated)

An advanced error reporting utility. hb_report-generated tarballs are
frequently requested by the developers to isolate and fix bugs, and
are commonly found as attachments to Bugzilla entries.

NOTE: hb_report has been integrated into
[crmsh](https://github.com/ClusterLabs/crmsh.git), and is now maintained as part of the
`crmsh` project.

### Cluster Plumbing Library

A low-level library for intra-cluster communications.

## Source Code Repository

Source code for Cluster Glue is being maintained in the
https://github.com/ClusterLabs/cluster-glue git repository.
